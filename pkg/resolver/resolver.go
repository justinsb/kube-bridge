// Package resolver answers "which endpoints back this ClusterIP and port?"
// from informer caches of Services and EndpointSlices, so the data plane
// never makes an API request while deciding a flow.
package resolver

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net/netip"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	corelisters "k8s.io/client-go/listers/core/v1"
	discoverylisters "k8s.io/client-go/listers/discovery/v1"
	"k8s.io/client-go/tools/cache"
)

const clusterIPIndex = "clusterIP"

// Endpoint is one backend address and port.
type Endpoint struct {
	Addr netip.Addr
	Port uint16
}

// Resolver serves lookups from informer caches.
type Resolver struct {
	factory    informers.SharedInformerFactory
	services   corelisters.ServiceLister
	svcIndexer cache.Indexer
	slices     discoverylisters.EndpointSliceLister
}

// New builds the informers. Call Start before using the lookups.
func New(client kubernetes.Interface) (*Resolver, error) {
	factory := informers.NewSharedInformerFactory(client, 0)
	svcInformer := factory.Core().V1().Services().Informer()
	if err := svcInformer.AddIndexers(cache.Indexers{clusterIPIndex: func(obj interface{}) ([]string, error) {
		svc, ok := obj.(*corev1.Service)
		if !ok {
			return nil, nil
		}
		return svc.Spec.ClusterIPs, nil
	}}); err != nil {
		return nil, fmt.Errorf("adding ClusterIP index: %w", err)
	}
	// Register the EndpointSlice informer so Start runs it.
	_ = factory.Discovery().V1().EndpointSlices().Informer()
	return &Resolver{
		factory:    factory,
		services:   factory.Core().V1().Services().Lister(),
		svcIndexer: svcInformer.GetIndexer(),
		slices:     factory.Discovery().V1().EndpointSlices().Lister(),
	}, nil
}

// Start runs the informers and waits for the first full sync.
func (r *Resolver) Start(ctx context.Context) error {
	r.factory.Start(ctx.Done())
	for typ, ok := range r.factory.WaitForCacheSync(ctx.Done()) {
		if !ok {
			return fmt.Errorf("informer cache for %v did not sync", typ)
		}
	}
	return nil
}

// ServiceByClusterIP finds the Service that owns a ClusterIP.
func (r *Resolver) ServiceByClusterIP(ip netip.Addr) (*corev1.Service, bool) {
	objs, err := r.svcIndexer.ByIndex(clusterIPIndex, ip.String())
	if err != nil || len(objs) == 0 {
		return nil, false
	}
	svc, ok := objs[0].(*corev1.Service)
	return svc, ok
}

// Service looks a Service up by namespace and name.
func (r *Resolver) Service(namespace, name string) (*corev1.Service, bool) {
	svc, err := r.services.Services(namespace).Get(name)
	if err != nil {
		return nil, false
	}
	return svc, true
}

// Endpoints returns the ready IPv6 endpoints behind a Service port.
func (r *Resolver) Endpoints(svc *corev1.Service, port uint16, proto corev1.Protocol) ([]Endpoint, error) {
	var svcPort *corev1.ServicePort
	for i := range svc.Spec.Ports {
		p := &svc.Spec.Ports[i]
		pp := p.Protocol
		if pp == "" {
			pp = corev1.ProtocolTCP
		}
		if uint16(p.Port) == port && pp == proto {
			svcPort = p
			break
		}
	}
	if svcPort == nil {
		return nil, fmt.Errorf("service %s/%s has no %s port %d", svc.Namespace, svc.Name, proto, port)
	}
	selector := labels.SelectorFromSet(labels.Set{discoveryv1.LabelServiceName: svc.Name})
	slices, err := r.slices.EndpointSlices(svc.Namespace).List(selector)
	if err != nil {
		return nil, fmt.Errorf("listing endpointslices for %s/%s: %w", svc.Namespace, svc.Name, err)
	}
	var out []Endpoint
	for _, s := range slices {
		if s.AddressType != discoveryv1.AddressTypeIPv6 {
			continue
		}
		targetPort := int32(-1)
		for _, sp := range s.Ports {
			if sp.Port == nil {
				continue
			}
			name := ""
			if sp.Name != nil {
				name = *sp.Name
			}
			sproto := corev1.ProtocolTCP
			if sp.Protocol != nil {
				sproto = *sp.Protocol
			}
			if name == svcPort.Name && sproto == proto {
				targetPort = *sp.Port
				break
			}
		}
		if targetPort < 0 {
			continue
		}
		for _, ep := range s.Endpoints {
			if ep.Conditions.Ready != nil && !*ep.Conditions.Ready {
				continue
			}
			for _, a := range ep.Addresses {
				addr, err := netip.ParseAddr(a)
				if err != nil {
					continue
				}
				out = append(out, Endpoint{Addr: addr, Port: uint16(targetPort)})
			}
		}
	}
	return out, nil
}

// Pick chooses one endpoint uniformly at random.
func Pick(eps []Endpoint) (Endpoint, bool) {
	if len(eps) == 0 {
		return Endpoint{}, false
	}
	return eps[rand.IntN(len(eps))], true
}
