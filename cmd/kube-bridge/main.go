// Command kube-bridge makes a cluster's Services reachable from the LAN.
//
// It advertises an IPv6 prefix on the node's LAN interface, intercepts
// traffic to that prefix, maps each address back to the ClusterIP it stands
// for and DNATs the flow to a ready endpoint, and serves DNS names for the
// aliases. See the package docs under pkg/ for each piece.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/unix"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/justinsb/kube-bridge/pkg/dataplane"
	"github.com/justinsb/kube-bridge/pkg/dnsserver"
	"github.com/justinsb/kube-bridge/pkg/mapping"
	"github.com/justinsb/kube-bridge/pkg/ra"
	"github.com/justinsb/kube-bridge/pkg/resolver"
)

type options struct {
	prefix        string
	serviceCIDR   string
	iface         string
	routerAddr    string
	queueNum      uint
	dnsZone       string
	dnsListen     string
	dnsTTL        uint
	interval      time.Duration
	routeLifetime time.Duration
	advertise     bool
	kubeconfig    string
	verbose       bool
}

func main() {
	var o options
	flag.StringVar(&o.prefix, "prefix", "", "IPv6 prefix to advertise on the LAN; ClusterIPs are aliased under it (required)")
	flag.StringVar(&o.serviceCIDR, "service-cidr", "", "cluster service CIDR (default: the ServiceCIDR named kubernetes)")
	flag.StringVar(&o.iface, "interface", "", "LAN interface to advertise on (default: the interface of the IPv6 default route)")
	flag.StringVar(&o.routerAddr, "router-address", "", "link-local address to advertise from; it is added to the interface (default: derived from the interface MAC)")
	flag.UintVar(&o.queueNum, "queue-num", 100, "NFQUEUE number")
	flag.StringVar(&o.dnsZone, "dns-zone", "", "DNS zone to serve: <service>.<namespace>.<zone> resolves to the bridge alias (empty disables DNS)")
	flag.StringVar(&o.dnsListen, "dns-listen", "", "address:port for the DNS server, for example [2001:db8::1]:53")
	flag.UintVar(&o.dnsTTL, "dns-ttl", 30, "TTL for DNS answers, in seconds")
	flag.DurationVar(&o.interval, "advertise-interval", 30*time.Second, "time between unsolicited router advertisements")
	flag.DurationVar(&o.routeLifetime, "route-lifetime", 30*time.Minute, "route lifetime carried in advertisements")
	flag.BoolVar(&o.advertise, "advertise", true, "send router advertisements for the prefix")
	flag.StringVar(&o.kubeconfig, "kubeconfig", "", "path to a kubeconfig (default: in-cluster configuration)")
	flag.BoolVar(&o.verbose, "v", false, "log every flow decision")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, o); err != nil {
		log.Fatalf("kube-bridge: %v", err)
	}
}

func run(ctx context.Context, o options) error {
	if o.prefix == "" {
		return errors.New("--prefix is required")
	}
	bridgePrefix, err := netip.ParsePrefix(o.prefix)
	if err != nil {
		return fmt.Errorf("parsing --prefix: %w", err)
	}

	client, err := newClient(o.kubeconfig)
	if err != nil {
		return err
	}
	serviceCIDR, err := findServiceCIDR(ctx, client, o.serviceCIDR)
	if err != nil {
		return err
	}
	m, err := mapping.New(bridgePrefix, serviceCIDR)
	if err != nil {
		return err
	}
	log.Printf("mapping service CIDR %s to bridge prefix %s", m.Service, m.Bridge)

	res, err := resolver.New(client)
	if err != nil {
		return err
	}
	if err := res.Start(ctx); err != nil {
		return err
	}

	ifi, err := findInterface(o.iface)
	if err != nil {
		return err
	}
	routerAddr, err := routerAddress(o.routerAddr, ifi)
	if err != nil {
		return err
	}
	if o.advertise {
		if err := addLinkLocal(ifi, routerAddr); err != nil {
			return err
		}
		defer func() {
			if err := removeLinkLocal(ifi, routerAddr); err != nil {
				log.Printf("removing %s from %s: %v", routerAddr, ifi.Name, err)
			}
		}()
	}

	dp := dataplane.New(dataplane.Config{
		QueueNum: uint16(o.queueNum),
		Mapping:  m,
		Resolver: res,
		Verbose:  o.verbose,
	})
	if err := dp.Install(); err != nil {
		return err
	}
	defer func() {
		if err := dp.Uninstall(); err != nil {
			log.Printf("uninstalling data plane: %v", err)
		}
	}()
	log.Printf("intercepting %s on nfqueue %d", m.Bridge, o.queueNum)

	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() error { return dp.Run(gctx) })

	if o.advertise {
		adv, err := ra.New(ra.Config{
			Interface:     ifi,
			Source:        routerAddr,
			Prefix:        m.Bridge,
			Interval:      o.interval,
			RouteLifetime: o.routeLifetime,
		})
		if err != nil {
			return err
		}
		log.Printf("advertising %s on %s from %s every %s", m.Bridge, ifi.Name, routerAddr, o.interval)
		g.Go(func() error { return adv.Run(gctx) })
	}

	if o.dnsZone != "" {
		if o.dnsListen == "" {
			return errors.New("--dns-listen is required with --dns-zone")
		}
		srv := &dnsserver.Server{Zone: o.dnsZone, Mapping: m, Resolver: res, TTL: uint32(o.dnsTTL)}
		log.Printf("serving DNS zone %s on %s", o.dnsZone, o.dnsListen)
		g.Go(func() error { return srv.ListenAndServe(gctx, o.dnsListen) })
	}

	return g.Wait()
}

func newClient(kubeconfig string) (kubernetes.Interface, error) {
	var cfg *rest.Config
	var err error
	if kubeconfig != "" {
		cfg, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
	} else {
		cfg, err = rest.InClusterConfig()
	}
	if err != nil {
		return nil, fmt.Errorf("building kubernetes client config: %w", err)
	}
	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("building kubernetes client: %w", err)
	}
	return client, nil
}

// findServiceCIDR returns the configured CIDR, or the cluster's IPv6 service
// CIDR from the ServiceCIDR API.
func findServiceCIDR(ctx context.Context, client kubernetes.Interface, flagValue string) (netip.Prefix, error) {
	if flagValue != "" {
		p, err := netip.ParsePrefix(flagValue)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("parsing --service-cidr: %w", err)
		}
		return p, nil
	}
	sc, err := client.NetworkingV1().ServiceCIDRs().Get(ctx, "kubernetes", metav1.GetOptions{})
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("reading ServiceCIDR kubernetes (pass --service-cidr instead): %w", err)
	}
	for _, c := range sc.Spec.CIDRs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("parsing service CIDR %q: %w", c, err)
		}
		if p.Addr().Is6() {
			return p, nil
		}
	}
	return netip.Prefix{}, fmt.Errorf("ServiceCIDR kubernetes has no IPv6 CIDR: %v", sc.Spec.CIDRs)
}

// findInterface returns the named interface, or the one carrying the IPv6
// default route.
func findInterface(name string) (*net.Interface, error) {
	if name != "" {
		ifi, err := net.InterfaceByName(name)
		if err != nil {
			return nil, fmt.Errorf("looking up interface %s: %w", name, err)
		}
		return ifi, nil
	}
	routes, err := netlink.RouteList(nil, netlink.FAMILY_V6)
	if err != nil {
		return nil, fmt.Errorf("listing IPv6 routes: %w", err)
	}
	for _, r := range routes {
		if r.Dst != nil && !r.Dst.IP.IsUnspecified() {
			continue
		}
		if r.Dst != nil {
			if ones, _ := r.Dst.Mask.Size(); ones != 0 {
				continue
			}
		}
		link, err := netlink.LinkByIndex(r.LinkIndex)
		if err != nil {
			return nil, fmt.Errorf("looking up link %d of the default route: %w", r.LinkIndex, err)
		}
		return net.InterfaceByName(link.Attrs().Name)
	}
	return nil, errors.New("no IPv6 default route found; pass --interface")
}

// routerAddress returns the link-local address to advertise from. The
// default is derived from the interface's MAC so that each node gets its
// own, distinct from the address the kernel or any other daemon uses, which
// keeps kube-bridge's advertisements from touching other router state.
func routerAddress(flagValue string, ifi *net.Interface) (netip.Addr, error) {
	if flagValue != "" {
		a, err := netip.ParseAddr(flagValue)
		if err != nil {
			return netip.Addr{}, fmt.Errorf("parsing --router-address: %w", err)
		}
		if !a.IsLinkLocalUnicast() {
			return netip.Addr{}, fmt.Errorf("--router-address %s is not link-local", a)
		}
		return a, nil
	}
	mac := ifi.HardwareAddr
	if len(mac) != 6 {
		return netip.Addr{}, fmt.Errorf("interface %s has no 48-bit MAC; pass --router-address", ifi.Name)
	}
	var b [16]byte
	b[0], b[1] = 0xfe, 0x80
	b[8], b[9] = 0xb1, 0xd6
	copy(b[10:16], mac)
	return netip.AddrFrom16(b), nil
}

func addLinkLocal(ifi *net.Interface, addr netip.Addr) error {
	link, err := netlink.LinkByIndex(ifi.Index)
	if err != nil {
		return fmt.Errorf("looking up link %s: %w", ifi.Name, err)
	}
	a := &netlink.Addr{
		IPNet: &net.IPNet{IP: addr.AsSlice(), Mask: net.CIDRMask(64, 128)},
		Scope: unix.RT_SCOPE_LINK,
		Flags: unix.IFA_F_NODAD,
	}
	if err := netlink.AddrAdd(link, a); err != nil && !errors.Is(err, os.ErrExist) && !errors.Is(err, unix.EEXIST) {
		return fmt.Errorf("adding %s to %s: %w", addr, ifi.Name, err)
	}
	return nil
}

func removeLinkLocal(ifi *net.Interface, addr netip.Addr) error {
	link, err := netlink.LinkByIndex(ifi.Index)
	if err != nil {
		return err
	}
	return netlink.AddrDel(link, &netlink.Addr{IPNet: &net.IPNet{IP: addr.AsSlice(), Mask: net.CIDRMask(64, 128)}})
}
