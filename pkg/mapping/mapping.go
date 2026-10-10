// Package mapping translates between ClusterIPs and their aliases under the
// bridge prefix. The translation is a fixed bijection on address bits, so it
// needs no state: the host part of a ClusterIP within the service CIDR is
// placed under the bridge prefix, and back.
package mapping

import (
	"fmt"
	"net/netip"
)

// Mapping holds the two prefixes being translated between.
type Mapping struct {
	// Bridge is the LAN-routable prefix that kube-bridge advertises.
	Bridge netip.Prefix
	// Service is the cluster's service CIDR.
	Service netip.Prefix
}

// New validates the prefixes and returns a Mapping.
func New(bridge, service netip.Prefix) (Mapping, error) {
	if !bridge.IsValid() || !service.IsValid() {
		return Mapping{}, fmt.Errorf("invalid prefix: bridge=%v service=%v", bridge, service)
	}
	if !bridge.Addr().Is6() || !service.Addr().Is6() {
		return Mapping{}, fmt.Errorf("both prefixes must be IPv6: bridge=%s service=%s", bridge, service)
	}
	if bridge.Bits() > service.Bits() {
		return Mapping{}, fmt.Errorf("bridge prefix %s is longer than the service CIDR %s and cannot hold every ClusterIP", bridge, service)
	}
	if bridge.Overlaps(service) {
		return Mapping{}, fmt.Errorf("bridge prefix %s overlaps the service CIDR %s", bridge, service)
	}
	return Mapping{Bridge: bridge.Masked(), Service: service.Masked()}, nil
}

// ToBridge returns the bridge alias of a ClusterIP.
func (m Mapping) ToBridge(clusterIP netip.Addr) (netip.Addr, bool) {
	if !m.Service.Contains(clusterIP) {
		return netip.Addr{}, false
	}
	return combine(m.Bridge.Addr(), clusterIP, m.Service.Bits()), true
}

// ToCluster returns the ClusterIP that a bridge alias stands for.
func (m Mapping) ToCluster(bridgeAddr netip.Addr) (netip.Addr, bool) {
	if !m.Bridge.Contains(bridgeAddr) {
		return netip.Addr{}, false
	}
	return combine(m.Service.Addr(), bridgeAddr, m.Service.Bits()), true
}

// combine takes the first bits bits from prefixAddr and the remaining bits
// from hostAddr.
func combine(prefixAddr, hostAddr netip.Addr, bits int) netip.Addr {
	p := prefixAddr.As16()
	h := hostAddr.As16()
	var out [16]byte
	for i := 0; i < 16; i++ {
		var mask byte
		switch {
		case bits >= (i+1)*8:
			mask = 0xff
		case bits > i*8:
			mask = byte(0xff << (8 - (bits - i*8)))
		}
		out[i] = p[i]&mask | h[i]&^mask
	}
	return netip.AddrFrom16(out)
}
