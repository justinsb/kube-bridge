# kube-bridge

kube-bridge makes a Kubernetes cluster's Services reachable from the LAN it
sits on, with nothing to configure on the router, on the hosts, or in the
cluster's existing networking. The goal is to stop the cluster being an
island: a developer's machine on the LAN talks to `nginx.default` the
same way a pod does.

It is an early prototype. It works end to end on one IPv6 cluster and has
not been tested anywhere else yet.

## What it does

Each kube-bridge pod runs on the host network of a node and does three
things:

1. **Advertises a prefix.** It sends IPv6 Router Advertisements on the
   node's LAN interface carrying a Route Information Option (RFC 4191) for
   a configured *bridge prefix*. Hosts on the LAN install a route for the
   prefix via the node. The advertisement has a router lifetime of zero, so
   the node never becomes anyone's default router. It is sent from a
   dedicated link-local address derived from the interface MAC, so it does
   not interfere with any other router advertisements the node sends.
2. **Intercepts traffic to the prefix.** Every ClusterIP has an alias under
   the bridge prefix: the host bits of the ClusterIP within the service
   CIDR, placed under the bridge prefix. A packet for an alias arrives at the
   node, where a small static nftables ruleset hands the first packet of each
   flow to userspace through NFQUEUE. kube-bridge maps the alias back to the
   ClusterIP, finds the Service and a ready endpoint from informer caches,
   and reinjects the packet with a mark. A static rule DNATs by mark through
   a `mark -> endpoint` map, and conntrack carries the rest of the flow in
   the kernel. A masquerade rule on marked flows makes replies from pods on
   other nodes come back through the same node. No nftables operation
   happens per flow; the map only grows when a new endpoint is first used.
3. **Serves DNS.** `<service>.<namespace>.<zone>` (and
   `<service>.<namespace>.svc.<zone>`) resolve to the alias.

The data plane is the mark-based design from
[kube-on-mac](https://github.com/justinsb/kube-on-mac)'s service load
balancer, moved from a pod VM's output hook to a node's prerouting hook.

## Requirements

- An IPv6 single-stack or dual-stack cluster. ClusterIPs must be IPv6 and
  pods must have IPv6 addresses reachable from the nodes.
- Nodes with `net.ipv6.conf.all.forwarding=1` and the `nf_tables`,
  `nft_queue`, `nfnetlink_queue` and `nft_masq` kernel modules.
- Hosts that honour Route Information Options. macOS and Linux with
  `accept_ra_rt_info_max_plen` do; Windows does not, so a static route is
  needed there.
- A bridge prefix at least as wide as the service CIDR and not overlapping
  it. A ULA such as `fd00:b1d6::/108` works; a global prefix lets the
  aliases be reached from anywhere the prefix is routed.

## Deploy

Edit the ConfigMap in `k8s/kube-bridge.yaml` (bridge prefix, DNS zone), set
the image, and apply it. It runs as a DaemonSet in `kube-bridge-system`
with `NET_ADMIN` and `NET_RAW`. Every node advertises the prefix; hosts pick
one of them as the next hop. A Deployment with one replica works too and
costs one less process per node, at the price of a single entry point.

The resolver is reached the same way as everything else: the manifest
includes a ClusterIP Service for kube-bridge on port 53, and its alias under
the bridge prefix is the nameserver address. Pinning `spec.clusterIP` gives
a memorable one; with service CIDR `fd00:5e4f:ce::/108`, bridge prefix
`fd00:b1d6::/108` and `clusterIP: fd00:5e4f:ce::53` the nameserver is
`fd00:b1d6::53`. Queries to it are load-balanced across the nodes by the
data plane like any other Service.

Then, on a Mac, send the zone there:

```
sudo mkdir -p /etc/resolver
printf 'nameserver fd00:b1d6::53\n' | sudo tee /etc/resolver/kube-bridge.example
```

and `nginx.default.kube-bridge.example` resolves and connects. On
Linux, use a per-domain forward in systemd-resolved or dnsmasq. Delegating
the zone from public DNS to the nameserver alias makes every device on the
LAN work with no local configuration.

## Flags

| Flag | Default | Meaning |
|---|---|---|
| `--prefix` | required | bridge prefix to advertise and intercept |
| `--service-cidr` | from the `kubernetes` ServiceCIDR | the cluster's service CIDR |
| `--interface` | interface of the IPv6 default route | LAN interface |
| `--router-address` | derived from the MAC | link-local address to advertise from |
| `--queue-num` | 100 | NFQUEUE number |
| `--dns-zone` | off | zone to serve |
| `--dns-listen` | | address:port for DNS, usually `[$(HOST_IP)]:53` |
| `--advertise-interval` | 30s | time between advertisements |
| `--route-lifetime` | 30m | route lifetime in advertisements |
| `-v` | off | log every flow decision |

## Status and limitations

Verified on a three-node kops cluster (kube-proxy in iptables mode, kindnet,
IPv6-only pods) from a Mac on the same LAN:

- the route appears on the Mac within one advertisement interval, pointing
  at one of the nodes;
- HTTP to a Service alias returns in about 2ms;
- TCP and UDP DNS queries to the CoreDNS alias are answered;
- a flow routed through one node to a pod on another node works, so the
  masquerade path is doing its job;
- the kube-bridge DNS zone resolves `<service>.<namespace>.<zone>`, queried
  through the resolver's own alias over UDP and TCP.

Known gaps, roughly in the order they should be fixed:

- Map elements are never removed. An endpoint that goes away leaves a stale
  map entry (harmless, it is only reachable by a mark nobody sets any more)
  and established flows pinned to it are not reset. Watching EndpointSlices
  and deleting elements plus flushing conntrack is the fix.
- Only TCP and UDP. ICMPv6 to an alias is dropped, so `ping` does not work.
- Service ports with `externalTrafficPolicy` or session affinity are not
  honoured; endpoints are chosen uniformly at random per flow.
- Clients see the node's address as the source after masquerade, so pods
  cannot tell LAN hosts apart.
- No metrics, no health endpoint, no leader election. Every node runs
  independently and advertises the same prefix.
- Hosts that pick a node that has gone away keep the route until the
  lifetime expires. A shorter lifetime bounds that at the cost of more
  advertisements.
