// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package forensics

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
)

// FreezeBackend identifies which NetworkPolicy API the operator
// uses to isolate suspect Pods. The lab targets Cilium per design
// 20 §F4; the core v1 fallback shipped in the chart so non-Cilium
// clusters still get a coarse-grained quarantine.
type FreezeBackend string

const (
	// FreezeBackendCilium maps to cilium.io/v2 CiliumNetworkPolicy.
	FreezeBackendCilium FreezeBackend = "Cilium"
	// FreezeBackendCoreV1 maps to networking.k8s.io/v1 NetworkPolicy.
	FreezeBackendCoreV1 FreezeBackend = "CoreV1"
)

// CiliumNetworkPolicyGVR is the typed GVR forensics looks up at
// startup to decide between FreezeBackendCilium and FreezeBackendCoreV1.
var CiliumNetworkPolicyGVR = schema.GroupVersionResource{
	Group:    "cilium.io",
	Version:  "v2",
	Resource: "ciliumnetworkpolicies",
}

// CNIDetector caches the detected freeze backend. The choice is
// refreshed periodically so a Cilium install added after the
// forensics deployment is picked up without a restart.
//
// Concurrency: the backend value lives in atomic.Value so callers
// from different goroutines (the SE reconciler, the freeze step)
// always observe a consistent snapshot.
type CNIDetector struct {
	disco    discovery.DiscoveryInterface
	interval time.Duration

	backend  atomic.Value // FreezeBackend
	failures atomic.Int64

	once sync.Once
	stop chan struct{}
}

// NewCNIDetector validates the discovery client and seeds the
// backend cache with a synchronous probe so the first reconcile
// already has a value.
func NewCNIDetector(disco discovery.DiscoveryInterface, refresh time.Duration) (*CNIDetector, error) {
	if disco == nil {
		return nil, errors.New("forensics: discovery client is nil")
	}
	if refresh <= 0 {
		refresh = 10 * time.Minute
	}
	d := &CNIDetector{
		disco:    disco,
		interval: refresh,
		stop:     make(chan struct{}),
	}
	d.refresh(context.Background())
	return d, nil
}

// Backend returns the currently-cached freeze backend. Defaults to
// CoreV1 when no probe has run yet - the safer fallback if Cilium
// isn't on this cluster.
func (d *CNIDetector) Backend() FreezeBackend {
	if v, ok := d.backend.Load().(FreezeBackend); ok && v != "" {
		return v
	}
	return FreezeBackendCoreV1
}

// FailureCount returns the number of detection probes that failed
// since startup, exposed via the freeze backend status condition so
// operators can spot a discovery RBAC issue without log diving.
func (d *CNIDetector) FailureCount() int64 {
	return d.failures.Load()
}

// Run drives the periodic refresh loop. Blocks until ctx is
// cancelled. Safe to call once per Detector.
func (d *CNIDetector) Run(ctx context.Context) {
	t := time.NewTicker(d.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-d.stop:
			return
		case <-t.C:
			d.refresh(ctx)
		}
	}
}

// Stop is callable from tests / shutdown to break Run() without
// going through ctx. Idempotent.
func (d *CNIDetector) Stop() {
	d.once.Do(func() { close(d.stop) })
}

// refresh probes the discovery API for the Cilium CRD and updates
// the cached backend accordingly. A discovery error counts as a
// failure but does not change the cached value (the previous
// observation stays in effect).
func (d *CNIDetector) refresh(_ context.Context) {
	gvr := CiliumNetworkPolicyGVR
	mapper, err := d.findResource(gvr)
	switch {
	case err == nil && mapper:
		d.backend.Store(FreezeBackendCilium)
	case err == nil:
		d.backend.Store(FreezeBackendCoreV1)
	default:
		d.failures.Add(1)
		// Keep whatever was cached. First-run fallthrough already
		// stored CoreV1 via Backend()'s default branch, so the
		// reconciler stays usable.
	}
}

// findResource consults discovery for the GVR. Returns true when
// the CRD is registered, false when the apiserver explicitly
// reports it absent. Network / 5xx errors propagate as err.
func (d *CNIDetector) findResource(gvr schema.GroupVersionResource) (bool, error) {
	gv := gvr.GroupVersion().String()
	list, err := d.disco.ServerResourcesForGroupVersion(gv)
	switch {
	case err == nil:
		for i := range list.APIResources {
			if list.APIResources[i].Name == gvr.Resource {
				return true, nil
			}
		}
		return false, nil
	case apierrors.IsNotFound(err):
		return false, nil
	case meta.IsNoMatchError(err):
		return false, nil
	default:
		// discovery may also surface group-not-registered as a
		// generic error string; map any unrecognised shape to a soft
		// "absent" so the operator does not crash-loop on a
		// transient apiserver failure.
		if isGroupAbsent(err) {
			return false, nil
		}
		return false, fmt.Errorf("discovery %s: %w", gv, err)
	}
}

// isGroupAbsent recognises the various string shapes the apiserver /
// discovery client produce when the requested group is not
// registered. Discovery returns a typed StatusError sometimes and a
// plain `errors.Errorf("the server could not find the requested
// resource")` other times; treat both as absence.
func isGroupAbsent(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "could not find the requested resource") ||
		strings.Contains(msg, "no matches for kind")
}
