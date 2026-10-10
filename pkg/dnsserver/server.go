// Package dnsserver serves <service>.<namespace>.<zone> as AAAA records
// pointing at the bridge alias of the service's ClusterIP.
package dnsserver

import (
	"context"
	"fmt"
	"log"
	"net/netip"
	"strings"

	"github.com/miekg/dns"

	"github.com/justinsb/kube-bridge/pkg/mapping"
	"github.com/justinsb/kube-bridge/pkg/resolver"
)

// Server is an authoritative server for one zone.
type Server struct {
	Zone     string
	Mapping  mapping.Mapping
	Resolver *resolver.Resolver
	TTL      uint32
}

// ListenAndServe serves UDP and TCP on addr until ctx is done.
func (s *Server) ListenAndServe(ctx context.Context, addr string) error {
	h := dns.HandlerFunc(s.serve)
	servers := []*dns.Server{
		{Addr: addr, Net: "udp", Handler: h},
		{Addr: addr, Net: "tcp", Handler: h},
	}
	errc := make(chan error, len(servers))
	for _, srv := range servers {
		go func() { errc <- srv.ListenAndServe() }()
	}
	select {
	case <-ctx.Done():
		for _, srv := range servers {
			if err := srv.Shutdown(); err != nil {
				log.Printf("dns: shutdown %s: %v", srv.Net, err)
			}
		}
		return nil
	case err := <-errc:
		return fmt.Errorf("dns server on %s: %w", addr, err)
	}
}

func (s *Server) serve(w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(req)
	m.Authoritative = true
	defer func() {
		if err := w.WriteMsg(m); err != nil {
			log.Printf("dns: writing reply to %s: %v", w.RemoteAddr(), err)
		}
	}()
	if len(req.Question) != 1 {
		m.Rcode = dns.RcodeFormatError
		return
	}
	q := req.Question[0]
	zone := dns.Fqdn(strings.ToLower(s.Zone))
	name := strings.ToLower(q.Name)
	if !dns.IsSubDomain(zone, name) {
		m.Rcode = dns.RcodeRefused
		return
	}
	soa := s.soa(zone)
	labels := dns.SplitDomainName(strings.TrimSuffix(name, zone))
	if len(labels) == 3 && labels[2] == "svc" {
		labels = labels[:2] // accept <service>.<namespace>.svc.<zone> too
	}
	if len(labels) == 0 {
		if q.Qtype == dns.TypeSOA || q.Qtype == dns.TypeANY {
			m.Answer = append(m.Answer, soa)
		} else {
			m.Ns = append(m.Ns, soa)
		}
		return
	}
	if len(labels) != 2 {
		m.Rcode = dns.RcodeNameError
		m.Ns = append(m.Ns, soa)
		return
	}
	svc, ok := s.Resolver.Service(labels[1], labels[0])
	if !ok {
		m.Rcode = dns.RcodeNameError
		m.Ns = append(m.Ns, soa)
		return
	}
	var addrs []netip.Addr
	for _, ipStr := range svc.Spec.ClusterIPs {
		ip, err := netip.ParseAddr(ipStr)
		if err != nil {
			continue // "None" for headless services
		}
		if b, ok := s.Mapping.ToBridge(ip); ok {
			addrs = append(addrs, b)
		}
	}
	if (q.Qtype != dns.TypeAAAA && q.Qtype != dns.TypeANY) || len(addrs) == 0 {
		m.Ns = append(m.Ns, soa) // NODATA
		return
	}
	for _, a := range addrs {
		m.Answer = append(m.Answer, &dns.AAAA{
			Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: s.TTL},
			AAAA: a.AsSlice(),
		})
	}
}

func (s *Server) soa(zone string) dns.RR {
	return &dns.SOA{
		Hdr:     dns.RR_Header{Name: zone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: s.TTL},
		Ns:      "ns." + zone,
		Mbox:    "hostmaster." + zone,
		Serial:  1,
		Refresh: 3600,
		Retry:   600,
		Expire:  86400,
		Minttl:  s.TTL,
	}
}
