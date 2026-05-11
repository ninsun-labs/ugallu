// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package dnsdetect

import (
	"context"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"

	"github.com/ninsun-labs/ugallu/operators/dns-detect/pkg/dnsdetect/detector"
)

// loadBlocklistEntries reads every ConfigMap referenced in
// DNSDetectConfig.spec.detectors.blocklist.configMaps[] and pushes
// the parsed entries to the BlocklistDetector.
//
// CM data shape (one key, multi-line value):
//
//	data:
//	  blocklist: |
//	    # comments
//	    *.bit
//	    evil.example.com
//
// All keys are flattened - every line in every key contributes
// entries. Lines starting with `#` or empty after Trim are skipped.
// The BlocklistDetector key carries `<ns>/<name>` so emitted
// SecurityEvents can attribute which list flagged the query.
func loadBlocklistEntries(ctx context.Context, reader client.Reader, refs []securityv1alpha1.DNSBlocklistRef) (map[string]string, error) {
	entries := map[string]string{}
	for _, ref := range refs {
		var cm corev1.ConfigMap
		key := types.NamespacedName{Namespace: ref.Namespace, Name: ref.Name}
		if err := reader.Get(ctx, key, &cm); err != nil {
			if apierrors.IsNotFound(err) {
				// Tolerate: an absent CM is treated as empty so the
				// reconciler doesn't crashloop on transient delete.
				continue
			}
			return nil, fmt.Errorf("get configmap %s: %w", key, err)
		}
		src := key.String()
		for _, body := range cm.Data {
			for _, line := range strings.Split(body, "\n") {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				entries[line] = src
			}
		}
	}
	return entries, nil
}

// blocklistRefresher refreshes the BlocklistDetector's entries on a
// fixed cadence. Cheap (one Get per CM, ~ms) and avoids wiring a
// full ConfigMap watch + RBAC for it. ctx cancellation stops the
// loop cleanly.
type blocklistRefresher struct {
	reader   client.Reader
	detector *detector.BlocklistDetector
	refs     []securityv1alpha1.DNSBlocklistRef
	period   time.Duration
}

// Start runs the refresh loop. Implements manager.Runnable.
func (r *blocklistRefresher) Start(ctx context.Context) error {
	ticker := time.NewTicker(r.period)
	defer ticker.Stop()

	// Prime once at boot so the detector has entries before the
	// dispatcher receives the first event.
	r.refresh(ctx)

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			r.refresh(ctx)
		}
	}
}

func (r *blocklistRefresher) refresh(ctx context.Context) {
	log := ctrl.Log.WithName("dns-detect-blocklist")
	entries, err := loadBlocklistEntries(ctx, r.reader, r.refs)
	if err != nil {
		log.Error(err, "load entries")
		return
	}
	r.detector.SetEntries(entries)
	log.Info("blocklist entries refreshed", "count", len(entries))
}

// addBlocklistRefresher registers the refresher with the manager so
// it runs alongside the dispatcher. period defaults to 30s.
func addBlocklistRefresher(mgr ctrl.Manager, det *detector.BlocklistDetector, refs []securityv1alpha1.DNSBlocklistRef, period time.Duration) error {
	if period <= 0 {
		period = 30 * time.Second
	}
	return mgr.Add(manager.RunnableFunc((&blocklistRefresher{
		reader:   mgr.GetAPIReader(),
		detector: det,
		refs:     refs,
		period:   period,
	}).Start))
}
