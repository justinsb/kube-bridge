package mapping

import (
	"net/netip"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	m, err := New(netip.MustParsePrefix("fd00:b1d6::/108"), netip.MustParsePrefix("fd00:5e4f:ce::/108"))
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"fd00:5e4f:ce::d:efaa": "fd00:b1d6::d:efaa",
		"fd00:5e4f:ce::a":      "fd00:b1d6::a",
		"fd00:5e4f:ce::f:ffff": "fd00:b1d6::f:ffff",
	}
	for cluster, want := range cases {
		got, ok := m.ToBridge(netip.MustParseAddr(cluster))
		if !ok || got.String() != want {
			t.Errorf("ToBridge(%s) = %s, %v; want %s", cluster, got, ok, want)
		}
		back, ok := m.ToCluster(got)
		if !ok || back.String() != cluster {
			t.Errorf("ToCluster(%s) = %s, %v; want %s", got, back, ok, cluster)
		}
	}
	if _, ok := m.ToBridge(netip.MustParseAddr("2001:db8::1")); ok {
		t.Error("ToBridge accepted an address outside the service CIDR")
	}
	if _, ok := m.ToCluster(netip.MustParseAddr("fd00:5e4f:ce::1")); ok {
		t.Error("ToCluster accepted an address outside the bridge prefix")
	}
}

func TestShorterBridgePrefix(t *testing.T) {
	// A /64 bridge prefix can hold a /108 service CIDR; the bits in between
	// come from the bridge prefix going out and from the service CIDR coming back.
	m, err := New(netip.MustParsePrefix("2001:db8:1:2::/64"), netip.MustParsePrefix("fd00:5e4f:ce::/108"))
	if err != nil {
		t.Fatal(err)
	}
	got, _ := m.ToBridge(netip.MustParseAddr("fd00:5e4f:ce::d:efaa"))
	if got.String() != "2001:db8:1:2::d:efaa" {
		t.Errorf("got %s", got)
	}
	back, _ := m.ToCluster(got)
	if back.String() != "fd00:5e4f:ce::d:efaa" {
		t.Errorf("got %s", back)
	}
}

func TestRejects(t *testing.T) {
	if _, err := New(netip.MustParsePrefix("fd00:b1d6::/112"), netip.MustParsePrefix("fd00:5e4f:ce::/108")); err == nil {
		t.Error("expected error for a bridge prefix longer than the service CIDR")
	}
	if _, err := New(netip.MustParsePrefix("fd00:5e4f::/32"), netip.MustParsePrefix("fd00:5e4f:ce::/108")); err == nil {
		t.Error("expected error for overlapping prefixes")
	}
}
