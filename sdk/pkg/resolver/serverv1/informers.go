// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package serverv1

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

// DefaultInformerResync is the periodic full re-list interval for the
// shared informer factory. 10 minutes is a sensible balance between
// drift recovery and apiserver load (matches the controller-runtime
// default).
const DefaultInformerResync = 10 * time.Minute

// AttachInformers wires Add/Update/Delete handlers from the shared
// informer factory into the resolver Cache. The factory must be
// started by the caller (or via WaitForCacheSync below).
//
// SaLister and NodeLister on the Cache are populated as a side
// effect so the gRPC server can use the standard listers for
// lookups by namespace/name.
func AttachInformers(c *Cache, factory informers.SharedInformerFactory) error {
	podInformer := factory.Core().V1().Pods().Informer()
	saInformer := factory.Core().V1().ServiceAccounts().Informer()
	nodeInformer := factory.Core().V1().Nodes().Informer()

	c.SaLister = factory.Core().V1().ServiceAccounts().Lister()
	c.NodeLister = factory.Core().V1().Nodes().Lister()

	if _, err := podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj any) { handlePodUpsert(c, obj) },
		UpdateFunc: func(_, newObj any) { handlePodUpsert(c, newObj) },
		DeleteFunc: func(obj any) { handlePodDelete(c, obj) },
	}); err != nil {
		return fmt.Errorf("pod informer event handler: %w", err)
	}

	// SA + Node currently have no secondary index; only the listers
	// are needed. The handler registrations above are sufficient
	// because AddEventHandler triggers a full LIST on Run() which
	// seeds the lister cache. The empty handler is just a no-op so
	// the registration takes effect.
	if _, err := saInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{}); err != nil {
		return fmt.Errorf("sa informer event handler: %w", err)
	}
	if _, err := nodeInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{}); err != nil {
		return fmt.Errorf("node informer event handler: %w", err)
	}
	return nil
}

// WaitForCacheSync starts the factory and blocks until all informers
// have completed their initial LIST. Returns an error when the
// context is cancelled before sync completes.
func WaitForCacheSync(ctx context.Context, factory informers.SharedInformerFactory) error {
	factory.Start(ctx.Done())
	for typ, ok := range factory.WaitForCacheSync(ctx.Done()) {
		if !ok {
			return fmt.Errorf("informer for %v failed to sync", typ)
		}
	}
	return nil
}

// NewSharedInformerFactory builds a factory bound to a clientset.
// Provided as a convenience so main.go doesn't import the client-go
// informers package directly.
func NewSharedInformerFactory(client kubernetes.Interface, resync time.Duration) informers.SharedInformerFactory {
	if resync <= 0 {
		resync = DefaultInformerResync
	}
	return informers.NewSharedInformerFactory(client, resync)
}

func handlePodUpsert(c *Cache, obj any) {
	p, ok := obj.(*corev1.Pod)
	if !ok {
		return
	}
	c.upsertPod(p)
}

func handlePodDelete(c *Cache, obj any) {
	uid := uidFromTombstone(obj)
	if uid == "" {
		return
	}
	c.MarkTombstone(uid, time.Now())
}

// uidFromTombstone unwraps the cache.DeletedFinalStateUnknown wrapper
// that informers emit when the watch missed the DELETE event itself.
func uidFromTombstone(obj any) types.UID {
	if p, ok := obj.(*corev1.Pod); ok {
		return p.UID
	}
	if t, ok := obj.(cache.DeletedFinalStateUnknown); ok {
		if p, ok := t.Obj.(*corev1.Pod); ok {
			return p.UID
		}
	}
	return ""
}
