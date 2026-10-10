// Package dataplane programs the node's netfilter so that traffic to the
// bridge prefix reaches the right pod, with the routing decision made in
// userspace once per flow.
//
// The design follows kube-on-mac's mark-based service load balancer: the
// ruleset is static and tiny, and no nftables operation happens per flow.
//
//	table ip6 kube-bridge {
//	  map endpoints { type mark : ipv6_addr . inet_service }
//	  chain prerouting {  # nat, before kube-proxy's dstnat
//	    ip6 daddr <bridge> mark & 0xffff0000 == TAG dnat ip6 to mark map @endpoints
//	    ip6 daddr <bridge> queue num N bypass
//	  }
//	  chain postrouting { # nat srcnat
//	    mark & 0xffff0000 == TAG masquerade
//	  }
//	}
//
// The first packet of a flow has no mark, so it is queued to userspace. The
// handler maps the bridge address back to a ClusterIP, picks a ready
// endpoint, makes sure the map has an element for it, and verdicts NF_REPEAT
// with the mark set. The repeated packet matches the first rule and is
// DNAT'd by the kernel; conntrack carries every later packet of the flow.
// The masquerade makes replies from pods on other nodes return through this
// node, where conntrack reverses the translation.
package dataplane

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net/netip"
	"sync"
	"time"

	nfqueue "github.com/florianl/go-nfqueue"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
	corev1 "k8s.io/api/core/v1"

	"github.com/justinsb/kube-bridge/pkg/mapping"
	"github.com/justinsb/kube-bridge/pkg/resolver"
)

const (
	// TableName is the nftables table kube-bridge owns.
	TableName = "kube-bridge"

	markTag     uint32 = 0xb1d60000
	markTagMask uint32 = 0xffff0000
	maxIDs      uint32 = 0xffff
)

// Config configures the data plane.
type Config struct {
	QueueNum uint16
	Mapping  mapping.Mapping
	Resolver *resolver.Resolver
	// Verbose logs every flow decision.
	Verbose bool
}

// Dataplane owns the nftables table and the NFQUEUE handler.
type Dataplane struct {
	cfg   Config
	nft   *nftables.Conn
	table *nftables.Table
	eps   *nftables.Set

	mu   sync.Mutex
	ids  map[resolver.Endpoint]uint32
	next uint32
}

// New returns an uninstalled data plane.
func New(cfg Config) *Dataplane {
	return &Dataplane{cfg: cfg, nft: &nftables.Conn{}, ids: map[resolver.Endpoint]uint32{}, next: 1}
}

// Install creates the table, map and rules, replacing any previous instance.
func (d *Dataplane) Install() error {
	c := d.nft
	// Start from a clean table so a restart does not accumulate rules.
	c.DelTable(&nftables.Table{Family: nftables.TableFamilyIPv6, Name: TableName})
	_ = c.Flush() // ENOENT when there was no table: fine.

	d.table = c.AddTable(&nftables.Table{Family: nftables.TableFamilyIPv6, Name: TableName})
	d.eps = &nftables.Set{
		Table:    d.table,
		Name:     "endpoints",
		IsMap:    true,
		KeyType:  nftables.TypeMark,
		DataType: nftables.MustConcatSetType(nftables.TypeIP6Addr, nftables.TypeInetService),
	}
	if err := c.AddSet(d.eps, nil); err != nil {
		return fmt.Errorf("adding endpoints map: %w", err)
	}
	pre := c.AddChain(&nftables.Chain{
		Name:     "prerouting",
		Table:    d.table,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: nftables.ChainPriorityRef(-101), // just before kube-proxy's dstnat
	})
	post := c.AddChain(&nftables.Chain{
		Name:     "postrouting",
		Table:    d.table,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPostrouting,
		Priority: nftables.ChainPriorityNATSource,
	})

	bridge := d.cfg.Mapping.Bridge
	// Rule 1: marked by us -> dnat to endpoints[mark].
	c.AddRule(&nftables.Rule{
		Table: d.table, Chain: pre,
		Exprs: join(matchDaddr(bridge), matchOurMark(), []expr.Any{
			&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
			&expr.Lookup{SourceRegister: 1, DestRegister: 1, IsDestRegSet: true, SetName: d.eps.Name, SetID: d.eps.ID},
			&expr.NAT{Type: expr.NATTypeDestNAT, Family: unix.NFPROTO_IPV6, RegAddrMin: 1, RegProtoMin: 2},
		}),
	})
	// Rule 2: first packet of a flow -> userspace.
	c.AddRule(&nftables.Rule{
		Table: d.table, Chain: pre,
		Exprs: join(matchDaddr(bridge), []expr.Any{
			&expr.Queue{Num: d.cfg.QueueNum, Flag: expr.QueueFlagBypass},
		}),
	})
	// Rule 3: flows we marked are masqueraded so replies return through this node.
	c.AddRule(&nftables.Rule{
		Table: d.table, Chain: post,
		Exprs: join(matchOurMark(), []expr.Any{&expr.Masq{}}),
	})
	if err := c.Flush(); err != nil {
		return fmt.Errorf("installing nftables rules: %w", err)
	}
	return nil
}

// Uninstall removes the table.
func (d *Dataplane) Uninstall() error {
	d.nft.DelTable(&nftables.Table{Family: nftables.TableFamilyIPv6, Name: TableName})
	if err := d.nft.Flush(); err != nil {
		return fmt.Errorf("removing nftables table: %w", err)
	}
	return nil
}

// Run serves the NFQUEUE until ctx is done.
func (d *Dataplane) Run(ctx context.Context) error {
	nf, err := nfqueue.Open(&nfqueue.Config{
		NfQueue:      d.cfg.QueueNum,
		MaxPacketLen: 0xffff,
		MaxQueueLen:  0xff,
		Copymode:     nfqueue.NfQnlCopyPacket,
		WriteTimeout: 15 * time.Millisecond,
	})
	if err != nil {
		return fmt.Errorf("opening nfqueue %d: %w", d.cfg.QueueNum, err)
	}
	defer nf.Close()

	handle := func(a nfqueue.Attribute) int {
		if a.PacketID == nil {
			return 0
		}
		id := *a.PacketID
		if a.Mark != nil && *a.Mark&markTagMask == markTag {
			// Already marked by us: the DNAT rule did not match, so do not loop.
			log.Printf("dropping packet re-queued with mark %#x: endpoint map lookup failed", *a.Mark)
			if err := nf.SetVerdict(id, nfqueue.NfDrop); err != nil {
				log.Printf("setting drop verdict: %v", err)
			}
			return 0
		}
		var payload []byte
		if a.Payload != nil {
			payload = *a.Payload
		}
		mark, err := d.decide(payload)
		if err != nil {
			log.Printf("dropping flow: %v", err)
			if err := nf.SetVerdict(id, nfqueue.NfDrop); err != nil {
				log.Printf("setting drop verdict: %v", err)
			}
			return 0
		}
		if err := nf.SetVerdictWithMark(id, nfqueue.NfRepeat, int(mark)); err != nil {
			log.Printf("setting verdict with mark %#x: %v", mark, err)
		}
		return 0
	}
	onErr := func(e error) int {
		log.Printf("nfqueue: %v", e)
		return 0
	}
	if err := nf.RegisterWithErrorFunc(ctx, handle, onErr); err != nil {
		return fmt.Errorf("registering nfqueue handler: %w", err)
	}
	<-ctx.Done()
	return nil
}

type packet struct {
	src, dst netip.Addr
	proto    corev1.Protocol
	dstPort  uint16
}

func parse(p []byte) (packet, error) {
	if len(p) < 40 || p[0]>>4 != 6 {
		return packet{}, fmt.Errorf("not an IPv6 packet (%d bytes)", len(p))
	}
	pk := packet{
		src: netip.AddrFrom16([16]byte(p[8:24])),
		dst: netip.AddrFrom16([16]byte(p[24:40])),
	}
	switch p[6] {
	case unix.IPPROTO_TCP:
		pk.proto = corev1.ProtocolTCP
	case unix.IPPROTO_UDP:
		pk.proto = corev1.ProtocolUDP
	default:
		return packet{}, fmt.Errorf("%s -> %s: next header %d is not TCP or UDP", pk.src, pk.dst, p[6])
	}
	if len(p) < 44 {
		return packet{}, fmt.Errorf("%s -> %s: truncated transport header", pk.src, pk.dst)
	}
	pk.dstPort = binary.BigEndian.Uint16(p[42:44])
	return pk, nil
}

// decide maps the first packet of a flow to a mark whose map entry is the
// chosen endpoint.
func (d *Dataplane) decide(payload []byte) (uint32, error) {
	pk, err := parse(payload)
	if err != nil {
		return 0, err
	}
	clusterIP, ok := d.cfg.Mapping.ToCluster(pk.dst)
	if !ok {
		return 0, fmt.Errorf("%s is not in the bridge prefix %s", pk.dst, d.cfg.Mapping.Bridge)
	}
	svc, ok := d.cfg.Resolver.ServiceByClusterIP(clusterIP)
	if !ok {
		return 0, fmt.Errorf("%s -> [%s]:%d: no service has ClusterIP %s", pk.src, pk.dst, pk.dstPort, clusterIP)
	}
	eps, err := d.cfg.Resolver.Endpoints(svc, pk.dstPort, pk.proto)
	if err != nil {
		return 0, fmt.Errorf("%s -> [%s]:%d: %w", pk.src, pk.dst, pk.dstPort, err)
	}
	ep, ok := resolver.Pick(eps)
	if !ok {
		return 0, fmt.Errorf("%s -> [%s]:%d: service %s/%s has no ready endpoints", pk.src, pk.dst, pk.dstPort, svc.Namespace, svc.Name)
	}
	id, err := d.idFor(ep)
	if err != nil {
		return 0, err
	}
	mark := markTag | id
	if d.cfg.Verbose {
		log.Printf("flow %s -> [%s]:%d/%s = %s/%s -> [%s]:%d (mark %#x)", pk.src, pk.dst, pk.dstPort, pk.proto, svc.Namespace, svc.Name, ep.Addr, ep.Port, mark)
	}
	return mark, nil
}

// idFor returns the mark id for an endpoint, adding a map element on first use.
func (d *Dataplane) idFor(ep resolver.Endpoint) (uint32, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if id, ok := d.ids[ep]; ok {
		return id, nil
	}
	if d.next > maxIDs {
		return 0, fmt.Errorf("endpoint map is full (%d entries)", maxIDs)
	}
	id := d.next
	a := ep.Addr.As16()
	// Map value: address (16) + port (2, network order) + padding to a 4-byte boundary.
	val := append(a[:], byte(ep.Port>>8), byte(ep.Port), 0, 0)
	// The lookup register holds the whole mark, tag included, so that is the key.
	if err := d.nft.SetAddElements(d.eps, []nftables.SetElement{{Key: native32(markTag | id), Val: val}}); err != nil {
		return 0, fmt.Errorf("adding endpoint %s:%d to map: %w", ep.Addr, ep.Port, err)
	}
	if err := d.nft.Flush(); err != nil {
		return 0, fmt.Errorf("adding endpoint %s:%d to map: %w", ep.Addr, ep.Port, err)
	}
	d.next++
	d.ids[ep] = id
	return id, nil
}

func native32(v uint32) []byte {
	b := make([]byte, 4)
	binary.NativeEndian.PutUint32(b, v)
	return b
}

func matchDaddr(p netip.Prefix) []expr.Any {
	mask := make([]byte, 16)
	for i := 0; i < p.Bits(); i++ {
		mask[i/8] |= 1 << (7 - uint(i%8))
	}
	addr := p.Masked().Addr().As16()
	return []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 24, Len: 16},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 16, Mask: mask, Xor: make([]byte, 16)},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: addr[:]},
	}
}

func matchOurMark() []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: native32(markTagMask), Xor: make([]byte, 4)},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: native32(markTag)},
	}
}

func join(parts ...[]expr.Any) []expr.Any {
	var out []expr.Any
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}
