// Package ra sends IPv6 Router Advertisements that carry a Route Information
// Option (RFC 4191) for the bridge prefix, so hosts on the LAN route the
// prefix to this node without any router configuration. The advertisement
// has a router lifetime of zero: this node does not become anyone's default
// router, it only owns the one route.
package ra

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv6"
)

// Config configures the advertiser.
type Config struct {
	Interface     *net.Interface
	Source        netip.Addr // link-local address to send from
	Prefix        netip.Prefix
	Interval      time.Duration
	RouteLifetime time.Duration
}

// Advertiser sends periodic and solicited advertisements.
type Advertiser struct {
	cfg      Config
	conn     *icmp.PacketConn
	pc       *ipv6.PacketConn
	allNodes *net.IPAddr
}

// New opens the raw ICMPv6 socket (needs CAP_NET_RAW).
func New(cfg Config) (*Advertiser, error) {
	if !cfg.Source.Is6() || !cfg.Source.IsLinkLocalUnicast() {
		return nil, fmt.Errorf("source %s is not a link-local IPv6 address", cfg.Source)
	}
	conn, err := icmp.ListenPacket("ip6:ipv6-icmp", "::")
	if err != nil {
		return nil, fmt.Errorf("opening ICMPv6 socket: %w", err)
	}
	pc := conn.IPv6PacketConn()
	for _, err := range []error{
		pc.SetHopLimit(255),
		pc.SetMulticastHopLimit(255),
		pc.SetMulticastInterface(cfg.Interface),
		pc.SetControlMessage(ipv6.FlagInterface, true),
	} {
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("configuring ICMPv6 socket: %w", err)
		}
	}
	var f ipv6.ICMPFilter
	f.SetAll(true)
	f.Accept(ipv6.ICMPTypeRouterSolicitation)
	if err := pc.SetICMPFilter(&f); err != nil {
		conn.Close()
		return nil, fmt.Errorf("setting ICMPv6 filter: %w", err)
	}
	return &Advertiser{
		cfg:      cfg,
		conn:     conn,
		pc:       pc,
		allNodes: &net.IPAddr{IP: net.ParseIP("ff02::1"), Zone: cfg.Interface.Name},
	}, nil
}

// Run advertises until ctx is done, then withdraws the route.
func (a *Advertiser) Run(ctx context.Context) error {
	go a.answerSolicitations(ctx)
	t := time.NewTicker(a.cfg.Interval)
	defer t.Stop()
	for {
		if err := a.send(a.allNodes, a.cfg.RouteLifetime); err != nil {
			log.Printf("router advertisement: %v", err)
		}
		select {
		case <-ctx.Done():
			return a.withdraw()
		case <-t.C:
		}
	}
}

// withdraw announces the route with lifetime zero and closes the socket.
func (a *Advertiser) withdraw() error {
	err := a.send(a.allNodes, 0)
	if cerr := a.conn.Close(); err == nil {
		err = cerr
	}
	return err
}

func (a *Advertiser) send(dst net.Addr, lifetime time.Duration) error {
	msg := a.build(uint32(lifetime / time.Second))
	cm := &ipv6.ControlMessage{Src: a.cfg.Source.AsSlice(), IfIndex: a.cfg.Interface.Index}
	if _, err := a.pc.WriteTo(msg, cm, dst); err != nil {
		return fmt.Errorf("sending to %s from %s: %w", dst, a.cfg.Source, err)
	}
	return nil
}

// build returns a Router Advertisement with a source link-layer address
// option and one Route Information Option. The ICMPv6 checksum is left
// zero: the kernel fills it in for raw ICMPv6 sockets.
func (a *Advertiser) build(lifetime uint32) []byte {
	b := make([]byte, 0, 48)
	b = append(b, byte(ipv6.ICMPTypeRouterAdvertisement), 0, 0, 0) // type, code, checksum
	b = append(b, 0, 0)                                            // cur hop limit (unspecified), flags
	b = append(b, 0, 0)                                            // router lifetime 0: not a default router
	b = append(b, 0, 0, 0, 0, 0, 0, 0, 0)                          // reachable time, retrans timer
	if mac := a.cfg.Interface.HardwareAddr; len(mac) == 6 {
		b = append(b, 1, 1) // source link-layer address option
		b = append(b, mac...)
	}
	b = append(b, 24, 3, byte(a.cfg.Prefix.Bits()), 0) // RIO: type, length (3 = 128-bit prefix), prefix length, prf=medium
	b = binary.BigEndian.AppendUint32(b, lifetime)
	p := a.cfg.Prefix.Masked().Addr().As16()
	b = append(b, p[:]...)
	return b
}

// answerSolicitations replies to Router Solicitations with a unicast
// advertisement so a host that just joined gets the route immediately.
func (a *Advertiser) answerSolicitations(ctx context.Context) {
	buf := make([]byte, 1500)
	var last time.Time
	for ctx.Err() == nil {
		if err := a.pc.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			return
		}
		n, cm, src, err := a.pc.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				continue
			}
			if ctx.Err() == nil {
				log.Printf("reading router solicitations: %v", err)
			}
			return
		}
		if n < 1 || buf[0] != byte(ipv6.ICMPTypeRouterSolicitation) {
			continue
		}
		if cm != nil && cm.IfIndex != 0 && cm.IfIndex != a.cfg.Interface.Index {
			continue
		}
		if time.Since(last) < 500*time.Millisecond {
			continue
		}
		last = time.Now()
		dst := &net.IPAddr{IP: src.(*net.IPAddr).IP, Zone: a.cfg.Interface.Name}
		if err := a.send(dst, a.cfg.RouteLifetime); err != nil {
			log.Printf("answering router solicitation from %s: %v", src, err)
		}
	}
}
