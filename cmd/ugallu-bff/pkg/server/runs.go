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

// RunSummary is the unified row used by the /runs list. Fields
// that exist on a subset of kinds (backend, mode, profile,
// targetNode, ...) live in `details` so the SPA can render a
// kind-specific subtitle without the BFF having to know the layout.
type RunSummary struct {
	Kind              string            `json:"kind"`
	Namespace         string            `json:"namespace"`
	Name              string            `json:"name"`
	Phase             string            `json:"phase,omitempty"`
	StartTime         string            `json:"startTime,omitempty"`
	CompletionTime    string            `json:"completionTime,omitempty"`
	CreationTimestamp string            `json:"creationTimestamp"`
	UID               string            `json:"uid"`
	WorstSeverity     string            `json:"worstSeverity,omitempty"`
	ResultName        string            `json:"resultName,omitempty"`
	Details           map[string]string `json:"details,omitempty"`
}

// RunListResponse is the wrapper returned by GET /api/v1/runs.
type RunListResponse struct {
	Items []RunSummary `json:"items"`
}

// RunDetailResponse joins a Run with its Result (or Profile, for
// seccomp). The two top-level fields are the raw apiserver objects
// so the SPA can render a YAML pane without re-mapping fields.
type RunDetailResponse struct {
	Kind   string `json:"kind"`
	Run    any    `json:"run"`
	Result any    `json:"result,omitempty"`
}

// runKinds lists the four canonical Run kinds in the order they
// appear in the catalog. This is the single point where a new
// Run kind gets registered for the UI.
var runKinds = []string{
	"BackupVerifyRun",
	"ComplianceScanRun",
	"ConfidentialAttestationRun",
	"SeccompTrainingRun",
}

func (s *Server) handleRunsList(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	ns := q.Get("namespace")

	var (
		mu  sync.Mutex
		all []RunSummary
		wg  sync.WaitGroup
	)
	collect := func(items []RunSummary) {
		mu.Lock()
		all = append(all, items...)
		mu.Unlock()
	}

	listOpts := []client.ListOption{}
	if ns != "" {
		listOpts = append(listOpts, client.InNamespace(ns))
	}

	wg.Add(4)
	go func() {
		defer wg.Done()
		var l securityv1alpha1.BackupVerifyRunList
		if err := s.opts.K8sClient.List(r.Context(), &l, listOpts...); err == nil {
			collect(s.summariseBackupVerify(r.Context(), l.Items))
		} else {
			s.opts.Logger.Warn("list BackupVerifyRun", "err", err)
		}
	}()
	go func() {
		defer wg.Done()
		var l securityv1alpha1.ComplianceScanRunList
		if err := s.opts.K8sClient.List(r.Context(), &l, listOpts...); err == nil {
			collect(s.summariseComplianceScan(r.Context(), l.Items))
		} else {
			s.opts.Logger.Warn("list ComplianceScanRun", "err", err)
		}
	}()
	go func() {
		defer wg.Done()
		var l securityv1alpha1.ConfidentialAttestationRunList
		if err := s.opts.K8sClient.List(r.Context(), &l, listOpts...); err == nil {
			collect(s.summariseConfidentialAttestation(r.Context(), l.Items))
		} else {
			s.opts.Logger.Warn("list ConfidentialAttestationRun", "err", err)
		}
	}()
	go func() {
		defer wg.Done()
		var l securityv1alpha1.SeccompTrainingRunList
		if err := s.opts.K8sClient.List(r.Context(), &l, listOpts...); err == nil {
			collect(s.summariseSeccompTraining(r.Context(), l.Items))
		} else {
			s.opts.Logger.Warn("list SeccompTrainingRun", "err", err)
		}
	}()
	wg.Wait()

	if filterKind := q.Get("kind"); filterKind != "" {
		filtered := all[:0]
		for i := range all {
			if all[i].Kind == filterKind {
				filtered = append(filtered, all[i])
			}
		}
		all = filtered
	}
	if filterPhase := q.Get("phase"); filterPhase != "" {
		filtered := all[:0]
		for i := range all {
			if all[i].Phase == filterPhase {
				filtered = append(filtered, all[i])
			}
		}
		all = filtered
	}

	// Newest first.
	sort.Slice(all, func(i, j int) bool {
		return all[i].CreationTimestamp > all[j].CreationTimestamp
	})

	s.writeJSON(w, http.StatusOK, RunListResponse{Items: all})
}

func (s *Server) handleRunGet(w http.ResponseWriter, r *http.Request) {
	kind := r.PathValue("kind")
	ns := r.PathValue("namespace")
	name := r.PathValue("name")
	if kind == "" || ns == "" || name == "" {
		s.writeError(w, http.StatusBadRequest, "missing_path", "kind, namespace, name are required")
		return
	}
	key := types.NamespacedName{Namespace: ns, Name: name}

	switch kind {
	case "BackupVerifyRun":
		var run securityv1alpha1.BackupVerifyRun
		if err := s.getOr404(r.Context(), w, key, &run); err != nil {
			return
		}
		var result *securityv1alpha1.BackupVerifyResult
		if run.Status.ResultRef != nil && run.Status.ResultRef.Name != "" {
			var got securityv1alpha1.BackupVerifyResult
			if err := s.opts.K8sClient.Get(r.Context(), types.NamespacedName{
				Namespace: run.Namespace, Name: run.Status.ResultRef.Name,
			}, &got); err == nil {
				result = &got
			}
		}
		s.writeJSON(w, http.StatusOK, RunDetailResponse{Kind: kind, Run: &run, Result: result})

	case "ComplianceScanRun":
		var run securityv1alpha1.ComplianceScanRun
		if err := s.getOr404(r.Context(), w, key, &run); err != nil {
			return
		}
		var result *securityv1alpha1.ComplianceScanResult
		if run.Status.ResultRef != nil && run.Status.ResultRef.Name != "" {
			var got securityv1alpha1.ComplianceScanResult
			if err := s.opts.K8sClient.Get(r.Context(), types.NamespacedName{
				Namespace: run.Namespace, Name: run.Status.ResultRef.Name,
			}, &got); err == nil {
				result = &got
			}
		}
		s.writeJSON(w, http.StatusOK, RunDetailResponse{Kind: kind, Run: &run, Result: result})

	case "ConfidentialAttestationRun":
		var run securityv1alpha1.ConfidentialAttestationRun
		if err := s.getOr404(r.Context(), w, key, &run); err != nil {
			return
		}
		var result *securityv1alpha1.ConfidentialAttestationResult
		if run.Status.ResultRef != nil && run.Status.ResultRef.Name != "" {
			var got securityv1alpha1.ConfidentialAttestationResult
			if err := s.opts.K8sClient.Get(r.Context(), types.NamespacedName{
				Namespace: run.Namespace, Name: run.Status.ResultRef.Name,
			}, &got); err == nil {
				result = &got
			}
		}
		s.writeJSON(w, http.StatusOK, RunDetailResponse{Kind: kind, Run: &run, Result: result})

	case "SeccompTrainingRun":
		var run securityv1alpha1.SeccompTrainingRun
		if err := s.getOr404(r.Context(), w, key, &run); err != nil {
			return
		}
		var profile *securityv1alpha1.SeccompTrainingProfile
		if run.Status.ProfileRef != nil && run.Status.ProfileRef.Name != "" {
			var got securityv1alpha1.SeccompTrainingProfile
			if err := s.opts.K8sClient.Get(r.Context(), types.NamespacedName{
				Namespace: run.Namespace, Name: run.Status.ProfileRef.Name,
			}, &got); err == nil {
				profile = &got
			}
		}
		s.writeJSON(w, http.StatusOK, RunDetailResponse{Kind: kind, Run: &run, Result: profile})

	default:
		s.writeError(w, http.StatusBadRequest, "unknown_kind",
			"kind must be one of: "+strings.Join(runKinds, ", "))
	}
}

func (s *Server) getOr404(ctx context.Context, w http.ResponseWriter, key types.NamespacedName, obj client.Object) error {
	err := s.opts.K8sClient.Get(ctx, key, obj)
	if apierrors.IsNotFound(err) {
		s.writeError(w, http.StatusNotFound, "not_found", "no "+obj.GetObjectKind().GroupVersionKind().Kind+" "+key.String())
		return err
	}
	if err != nil {
		s.opts.Logger.Warn("get run", "key", key.String(), "err", err)
		s.writeError(w, http.StatusInternalServerError, "get_failed", err.Error())
		return err
	}
	return nil
}

// --- per-kind summarisers ------------------------------------------------

func (s *Server) summariseBackupVerify(ctx context.Context, items []securityv1alpha1.BackupVerifyRun) []RunSummary {
	out := make([]RunSummary, 0, len(items))
	for i := range items {
		r := &items[i]
		sum := baseSummary("BackupVerifyRun", &r.ObjectMeta, r.Status.Phase, r.Status.StartTime, r.Status.CompletionTime)
		sum.Details = map[string]string{
			"backend": string(r.Spec.Backend),
			"mode":    string(r.Spec.Mode),
		}
		if r.Status.ResultRef != nil {
			sum.ResultName = r.Status.ResultRef.Name
			var res securityv1alpha1.BackupVerifyResult
			if err := s.opts.K8sClient.Get(ctx, types.NamespacedName{
				Namespace: r.Namespace, Name: r.Status.ResultRef.Name,
			}, &res); err == nil {
				sum.WorstSeverity = string(res.Status.WorstSeverity)
			}
		}
		out = append(out, sum)
	}
	return out
}

func (s *Server) summariseComplianceScan(ctx context.Context, items []securityv1alpha1.ComplianceScanRun) []RunSummary {
	out := make([]RunSummary, 0, len(items))
	for i := range items {
		r := &items[i]
		sum := baseSummary("ComplianceScanRun", &r.ObjectMeta, r.Status.Phase, r.Status.StartTime, r.Status.CompletionTime)
		sum.Details = map[string]string{
			"backend": string(r.Spec.Backend),
			"profile": r.Spec.Profile,
		}
		if r.Status.ResultRef != nil {
			sum.ResultName = r.Status.ResultRef.Name
			var res securityv1alpha1.ComplianceScanResult
			if err := s.opts.K8sClient.Get(ctx, types.NamespacedName{
				Namespace: r.Namespace, Name: r.Status.ResultRef.Name,
			}, &res); err == nil {
				sum.WorstSeverity = string(res.Status.WorstSeverity)
			}
		}
		out = append(out, sum)
	}
	return out
}

func (s *Server) summariseConfidentialAttestation(_ context.Context, items []securityv1alpha1.ConfidentialAttestationRun) []RunSummary {
	out := make([]RunSummary, 0, len(items))
	for i := range items {
		r := &items[i]
		sum := baseSummary("ConfidentialAttestationRun", &r.ObjectMeta, r.Status.Phase, r.Status.StartTime, r.Status.CompletionTime)
		sum.Details = map[string]string{
			"backend": string(r.Spec.Backend),
			"node":    r.Spec.TargetNodeName,
		}
		if r.Status.ResultRef != nil {
			sum.ResultName = r.Status.ResultRef.Name
		}
		out = append(out, sum)
	}
	return out
}

func (s *Server) summariseSeccompTraining(_ context.Context, items []securityv1alpha1.SeccompTrainingRun) []RunSummary {
	out := make([]RunSummary, 0, len(items))
	for i := range items {
		r := &items[i]
		sum := baseSummary("SeccompTrainingRun", &r.ObjectMeta, r.Status.Phase, r.Status.StartTime, r.Status.CompletionTime)
		sum.Details = map[string]string{
			"targetNamespace":  r.Spec.TargetNamespace,
			"durationSeconds":  formatDurationSeconds(r.Spec.Duration.Duration),
			"observedSyscalls": itoa(r.Status.ObservedSyscallCount),
		}
		if r.Status.ProfileRef != nil {
			sum.ResultName = r.Status.ProfileRef.Name
		}
		out = append(out, sum)
	}
	return out
}

func baseSummary(kind string, m *metav1.ObjectMeta, phase string, start, end *metav1.Time) RunSummary {
	out := RunSummary{
		Kind:      kind,
		Namespace: m.Namespace,
		Name:      m.Name,
		UID:       string(m.UID),
		Phase:     phase,
	}
	if !m.CreationTimestamp.IsZero() {
		out.CreationTimestamp = m.CreationTimestamp.UTC().Format(time.RFC3339)
	}
	if start != nil && !start.IsZero() {
		out.StartTime = start.UTC().Format(time.RFC3339)
	}
	if end != nil && !end.IsZero() {
		out.CompletionTime = end.UTC().Format(time.RFC3339)
	}
	return out
}

func formatDurationSeconds(d time.Duration) string {
	if d <= 0 {
		return ""
	}
	return itoa(int(d / time.Second))
}

func itoa(n int) string {
	// avoid pulling strconv just for this; the values are tiny.
	if n == 0 {
		return "0"
	}
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
