// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
)

// ConfigSummary is the row used by the /configurations list.
type ConfigSummary struct {
	Kind              string `json:"kind"`
	Namespace         string `json:"namespace,omitempty"`
	Name              string `json:"name"`
	UID               string `json:"uid"`
	CreationTimestamp string `json:"creationTimestamp"`
	Generation        int64  `json:"generation,omitempty"`
	LastConfigLoadAt  string `json:"lastConfigLoadAt,omitempty"`
	Healthy           bool   `json:"healthy"`
}

// ConfigListResponse wraps the list.
type ConfigListResponse struct {
	Items []ConfigSummary `json:"items"`
}

// ConfigDetailResponse returns the raw CR so the SPA can render
// a YAML pane without re-mapping fields.
type ConfigDetailResponse struct {
	Kind   string `json:"kind"`
	Object any    `json:"object"`
}

// configKinds is the canonical list of configuration kinds the
// UI shows. Singletons are listed first; non-singleton kinds
// (TenantBoundary) are skipped here because they live on their
// own page.
var configKinds = []string{
	"AuditDetectionConfig",
	"DNSDetectConfig",
	"ForensicsConfig",
	"HoneypotConfig",
	"WebhookAuditorConfig",
	"TTLConfig",
	"WORMConfig",
	"AttestorConfig",
	"GitOpsResponderConfig",
}

func (s *Server) handleConfigurationsList(w http.ResponseWriter, r *http.Request) {
	var (
		mu  sync.Mutex
		all []ConfigSummary
		wg  sync.WaitGroup
	)
	collect := func(items []ConfigSummary) {
		mu.Lock()
		all = append(all, items...)
		mu.Unlock()
	}

	wg.Add(9)

	// Cluster-scoped singletons.
	go func() {
		defer wg.Done()
		var l securityv1alpha1.AuditDetectionConfigList
		if err := s.opts.K8sClient.List(r.Context(), &l); err == nil {
			out := make([]ConfigSummary, 0, len(l.Items))
			for i := range l.Items {
				out = append(out, summariseAudit(&l.Items[i]))
			}
			collect(out)
		}
	}()
	go func() {
		defer wg.Done()
		var l securityv1alpha1.DNSDetectConfigList
		if err := s.opts.K8sClient.List(r.Context(), &l); err == nil {
			out := make([]ConfigSummary, 0, len(l.Items))
			for i := range l.Items {
				out = append(out, summariseDNS(&l.Items[i]))
			}
			collect(out)
		}
	}()
	go func() {
		defer wg.Done()
		var l securityv1alpha1.ForensicsConfigList
		if err := s.opts.K8sClient.List(r.Context(), &l); err == nil {
			out := make([]ConfigSummary, 0, len(l.Items))
			for i := range l.Items {
				out = append(out, summariseForensics(&l.Items[i]))
			}
			collect(out)
		}
	}()
	go func() {
		defer wg.Done()
		var l securityv1alpha1.HoneypotConfigList
		if err := s.opts.K8sClient.List(r.Context(), &l); err == nil {
			out := make([]ConfigSummary, 0, len(l.Items))
			for i := range l.Items {
				out = append(out, summariseHoneypot(&l.Items[i]))
			}
			collect(out)
		}
	}()
	go func() {
		defer wg.Done()
		var l securityv1alpha1.WebhookAuditorConfigList
		if err := s.opts.K8sClient.List(r.Context(), &l); err == nil {
			out := make([]ConfigSummary, 0, len(l.Items))
			for i := range l.Items {
				out = append(out, summariseWebhookAuditor(&l.Items[i]))
			}
			collect(out)
		}
	}()

	// Namespaced singletons. We list cluster-wide; a namespace
	// filter happens on the SPA side.
	go func() {
		defer wg.Done()
		var l securityv1alpha1.TTLConfigList
		if err := s.opts.K8sClient.List(r.Context(), &l); err == nil {
			out := make([]ConfigSummary, 0, len(l.Items))
			for i := range l.Items {
				out = append(out, summariseTTL(&l.Items[i]))
			}
			collect(out)
		}
	}()
	go func() {
		defer wg.Done()
		var l securityv1alpha1.WORMConfigList
		if err := s.opts.K8sClient.List(r.Context(), &l); err == nil {
			out := make([]ConfigSummary, 0, len(l.Items))
			for i := range l.Items {
				out = append(out, summariseWORM(&l.Items[i]))
			}
			collect(out)
		}
	}()
	go func() {
		defer wg.Done()
		var l securityv1alpha1.AttestorConfigList
		if err := s.opts.K8sClient.List(r.Context(), &l); err == nil {
			out := make([]ConfigSummary, 0, len(l.Items))
			for i := range l.Items {
				out = append(out, summariseAttestor(&l.Items[i]))
			}
			collect(out)
		}
	}()
	go func() {
		defer wg.Done()
		var l securityv1alpha1.GitOpsResponderConfigList
		if err := s.opts.K8sClient.List(r.Context(), &l); err == nil {
			out := make([]ConfigSummary, 0, len(l.Items))
			for i := range l.Items {
				out = append(out, summariseGitOpsResponder(&l.Items[i]))
			}
			collect(out)
		}
	}()

	wg.Wait()

	if filterKind := r.URL.Query().Get("kind"); filterKind != "" {
		filtered := all[:0]
		for _, e := range all {
			if e.Kind == filterKind {
				filtered = append(filtered, e)
			}
		}
		all = filtered
	}

	sort.Slice(all, func(i, j int) bool {
		if all[i].Kind != all[j].Kind {
			return all[i].Kind < all[j].Kind
		}
		return all[i].Name < all[j].Name
	})

	s.writeJSON(w, http.StatusOK, ConfigListResponse{Items: all})
}

func (s *Server) handleConfigurationGet(w http.ResponseWriter, r *http.Request) {
	kind := r.PathValue("kind")
	ns := r.PathValue("namespace")
	name := r.PathValue("name")
	if kind == "" || name == "" {
		s.writeError(w, http.StatusBadRequest, "missing_path", "kind and name are required")
		return
	}
	key := types.NamespacedName{Namespace: ns, Name: name}

	var obj client.Object
	switch kind {
	case "AuditDetectionConfig":
		obj = &securityv1alpha1.AuditDetectionConfig{}
	case "DNSDetectConfig":
		obj = &securityv1alpha1.DNSDetectConfig{}
	case "ForensicsConfig":
		obj = &securityv1alpha1.ForensicsConfig{}
	case "HoneypotConfig":
		obj = &securityv1alpha1.HoneypotConfig{}
	case "WebhookAuditorConfig":
		obj = &securityv1alpha1.WebhookAuditorConfig{}
	case "TTLConfig":
		obj = &securityv1alpha1.TTLConfig{}
	case "WORMConfig":
		obj = &securityv1alpha1.WORMConfig{}
	case "AttestorConfig":
		obj = &securityv1alpha1.AttestorConfig{}
	case "GitOpsResponderConfig":
		obj = &securityv1alpha1.GitOpsResponderConfig{}
	default:
		s.writeError(w, http.StatusBadRequest, "unknown_kind",
			"kind must be one of: "+strings.Join(configKinds, ", "))
		return
	}

	err := s.opts.K8sClient.Get(r.Context(), key, obj)
	if apierrors.IsNotFound(err) {
		s.writeError(w, http.StatusNotFound, "not_found", "no "+kind+" "+key.String())
		return
	}
	if err != nil {
		s.opts.Logger.Warn("get config", "kind", kind, "key", key.String(), "err", err)
		s.writeError(w, http.StatusInternalServerError, "get_failed", err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, ConfigDetailResponse{Kind: kind, Object: obj})
}

// --- per-kind summarisers ----------------------------------------

func baseConfig(kind string, m *metav1.ObjectMeta) ConfigSummary {
	out := ConfigSummary{
		Kind:       kind,
		Namespace:  m.Namespace,
		Name:       m.Name,
		UID:        string(m.UID),
		Generation: m.Generation,
		Healthy:    true,
	}
	if !m.CreationTimestamp.IsZero() {
		out.CreationTimestamp = m.CreationTimestamp.UTC().Format(time.RFC3339)
	}
	return out
}

func formatLoadTime(t *metav1.Time) string {
	if t == nil || t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func summariseAudit(c *securityv1alpha1.AuditDetectionConfig) ConfigSummary {
	out := baseConfig("AuditDetectionConfig", &c.ObjectMeta)
	out.LastConfigLoadAt = formatLoadTime(c.Status.LastConfigLoadAt)
	out.Healthy = isReady(c.Status.Conditions)
	return out
}

func summariseDNS(c *securityv1alpha1.DNSDetectConfig) ConfigSummary {
	out := baseConfig("DNSDetectConfig", &c.ObjectMeta)
	out.LastConfigLoadAt = formatLoadTime(c.Status.LastConfigLoadAt)
	out.Healthy = isReady(c.Status.Conditions)
	return out
}

func summariseForensics(c *securityv1alpha1.ForensicsConfig) ConfigSummary {
	out := baseConfig("ForensicsConfig", &c.ObjectMeta)
	out.LastConfigLoadAt = formatLoadTime(c.Status.LastConfigLoadAt)
	out.Healthy = isReady(c.Status.Conditions)
	return out
}

func summariseHoneypot(c *securityv1alpha1.HoneypotConfig) ConfigSummary {
	out := baseConfig("HoneypotConfig", &c.ObjectMeta)
	out.LastConfigLoadAt = formatLoadTime(c.Status.LastReconcileAt)
	out.Healthy = isReady(c.Status.Conditions)
	return out
}

func summariseWebhookAuditor(c *securityv1alpha1.WebhookAuditorConfig) ConfigSummary {
	out := baseConfig("WebhookAuditorConfig", &c.ObjectMeta)
	out.LastConfigLoadAt = formatLoadTime(c.Status.LastConfigLoadAt)
	out.Healthy = isReady(c.Status.Conditions)
	return out
}

func summariseTTL(c *securityv1alpha1.TTLConfig) ConfigSummary {
	return baseConfig("TTLConfig", &c.ObjectMeta)
}

func summariseWORM(c *securityv1alpha1.WORMConfig) ConfigSummary {
	return baseConfig("WORMConfig", &c.ObjectMeta)
}

func summariseAttestor(c *securityv1alpha1.AttestorConfig) ConfigSummary {
	return baseConfig("AttestorConfig", &c.ObjectMeta)
}

func summariseGitOpsResponder(c *securityv1alpha1.GitOpsResponderConfig) ConfigSummary {
	return baseConfig("GitOpsResponderConfig", &c.ObjectMeta)
}

func isReady(conds []metav1.Condition) bool {
	if len(conds) == 0 {
		// no conditions reported yet - assume healthy until the
		// operator surfaces a problem.
		return true
	}
	for _, c := range conds {
		if c.Type == "Ready" {
			return c.Status == metav1.ConditionTrue
		}
	}
	// no Ready condition - check for an explicit Failure-type
	// condition; absence means we treat as healthy.
	for _, c := range conds {
		if (c.Type == "Failed" || c.Type == "Degraded") && c.Status == metav1.ConditionTrue {
			return false
		}
	}
	return true
}

var _ = context.Background // referenced in some build tag combos
