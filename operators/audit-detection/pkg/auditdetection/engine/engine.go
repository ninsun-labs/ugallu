// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

// Package engine wires the audit-event Source into the Sigma rule
// evaluator and onwards to the Emitter SDK. It lives under
// pkg/auditdetection/engine to avoid the import cycle that would
// arise if it sat alongside auditdetection.AuditEvent (which
// pkg/auditdetection/sigma already depends on).
package engine

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
	emitterv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/emitter/v1alpha1"

	"github.com/ninsun-labs/ugallu/operators/audit-detection/pkg/auditdetection"
	"github.com/ninsun-labs/ugallu/operators/audit-detection/pkg/auditdetection/sigma"
)

// DefaultRuleBurst is the per-rule token bucket peak when the
// SigmaRule does not override SigmaRateLimit.
const DefaultRuleBurst = 50

// DefaultRuleSustainedPerSec is the per-rule sustained refill rate.
const DefaultRuleSustainedPerSec = 5

// Engine consumes AuditEvents from a Source and dispatches each event
// through the active rule set, calling the Emitter when a rule
// matches. Rules are managed by SigmaRuleReconciler via the embedded
// RuleSet; the engine itself is a simple fan-out evaluator.
type Engine struct {
	emitter         *emitterv1alpha1.Emitter
	clusterIdentity securityv1alpha1.ClusterIdentity
	log             *slog.Logger
	rules           *RuleSet
	publisher       Publisher
}

// Publisher is the optional fan-out hook the engine calls for every
// AuditEvent it consumes, before the sigma matcher runs. The
// audit-detection event bus plugs in here so other operators can
// subscribe to the raw stream without re-tailing the audit log.
// nil = no-op.
type Publisher interface {
	Publish(*auditdetection.AuditEvent)
}

// Options configures NewEngine.
type Options struct {
	// Emitter publishes the SecurityEvent. Required.
	Emitter *emitterv1alpha1.Emitter

	// ClusterIdentity is stamped on every emitted SE.
	ClusterIdentity securityv1alpha1.ClusterIdentity

	// Log routes diagnostics. nil → discard.
	Log *slog.Logger

	// Publisher receives every AuditEvent before sigma matching.
	// Optional; nil disables the fan-out.
	Publisher Publisher
}

// New validates opts and returns a ready Engine. The returned RuleSet
// is exposed as Engine.Rules() so the reconciler can hot-swap
// compiled rules without restarting Run.
func New(opts *Options) (*Engine, error) {
	if opts == nil || opts.Emitter == nil {
		return nil, errors.New("engine: Emitter is required")
	}
	log := opts.Log
	if log == nil {
		log = slog.New(slog.NewTextHandler(discardWriter{}, &slog.HandlerOptions{Level: slog.LevelError}))
	}
	return &Engine{
		emitter:         opts.Emitter,
		clusterIdentity: opts.ClusterIdentity,
		log:             log,
		rules:           NewRuleSet(),
		publisher:       opts.Publisher,
	}, nil
}

// Rules exposes the live RuleSet so the reconciler can add/remove
// compiled rules at runtime.
func (e *Engine) Rules() *RuleSet { return e.rules }

// Run consumes events from src.Run() and evaluates them against the
// current RuleSet. It returns when src closes the channel (typically
// after ctx is cancelled). Errors from src.Run() are surfaced
// synchronously.
func (e *Engine) Run(ctx context.Context, src auditdetection.Source) error {
	out, err := src.Run(ctx)
	if err != nil {
		return err
	}
	e.log.Info("engine running", "source", src.Name())
	for ev := range out {
		if ev == nil {
			continue
		}
		if e.publisher != nil {
			e.publisher.Publish(ev)
		}
		e.dispatch(ctx, ev)
	}
	e.log.Info("engine stopped", "source", src.Name())
	return nil
}

// dispatch evaluates ev against every active rule. Each match is
// routed through the per-rule rate limiter before reaching the
// Emitter.
func (e *Engine) dispatch(ctx context.Context, ev *auditdetection.AuditEvent) {
	for _, entry := range e.rules.Snapshot() {
		if !entry.Enabled {
			continue
		}
		if !entry.Compiled.Match(ev) {
			continue
		}
		if !entry.Limiter.Allow() {
			entry.DroppedRateLimit.Add(1)
			ruleDropsTotal.WithLabelValues(entry.Compiled.Name).Inc()
			continue
		}
		entry.MatchCount.Add(1)
		entry.LastMatchedAt.Store(timePtr(time.Now()))
		ruleMatchesTotal.WithLabelValues(entry.Compiled.Name).Inc()
		if err := e.emit(ctx, entry.Compiled, ev); err != nil {
			e.log.Warn("engine emit", "rule", entry.Compiled.Name, "err", err)
			ruleEmitErrorsTotal.WithLabelValues(entry.Compiled.Name).Inc()
		}
	}
}

// emit translates a CompiledRule + AuditEvent into an EmitOpts and
// hands it to the Emitter SDK.
func (e *Engine) emit(ctx context.Context, cr *sigma.CompiledRule, ev *auditdetection.AuditEvent) error {
	subjectKind, subjectName, subjectNamespace, subjectUID := subjectFrom(ev.ObjectRef)
	signals := renderSignals(cr.Spec.Emit.Signals, ev)
	opts := &emitterv1alpha1.EmitOpts{
		Class:            classOrDefault(cr.Spec.Emit.Class),
		Type:             cr.Spec.Emit.SecurityEventType,
		Severity:         cr.Spec.Emit.Severity,
		SubjectKind:      subjectKind,
		SubjectName:      subjectName,
		SubjectNamespace: subjectNamespace,
		SubjectUID:       subjectUID,
		Signals:          signals,
		CorrelationID:    ev.AuditID,
		ClusterIdentity:  e.clusterIdentity,
		DetectedAt:       eventTimestamp(ev),
	}
	_, err := e.emitter.Emit(ctx, opts)
	return err
}

// RuleSet is the engine's hot-swappable rule store. Reconcile writes,
// dispatch reads. Each entry carries the compiled matcher plus the
// per-rule mutable state (rate limiter, counters) so a SigmaRule
// re-compile preserves nothing — it's a fresh slot.
type RuleSet struct {
	mu       sync.RWMutex
	entries  map[string]*RuleEntry
	snapshot atomic.Pointer[[]*RuleEntry]
}

// NewRuleSet returns an empty RuleSet.
func NewRuleSet() *RuleSet {
	rs := &RuleSet{entries: make(map[string]*RuleEntry)}
	empty := []*RuleEntry{}
	rs.snapshot.Store(&empty)
	return rs
}

// RuleEntry is a single live rule slot. Counters are atomic so the
// engine writes them lock-free; LastMatchedAt is stored as a pointer
// for the same reason.
type RuleEntry struct {
	Compiled         *sigma.CompiledRule
	Enabled          bool
	Limiter          *rate.Limiter
	MatchCount       atomic.Int64
	DroppedRateLimit atomic.Int64
	LastMatchedAt    atomic.Pointer[time.Time]
	ParseError       string
}

// AddOrUpdate installs a freshly compiled rule in the slot named by
// cr.Name. Lifetime counters (MatchCount, DroppedRateLimit,
// LastMatchedAt) are preserved across re-compile so a rule edit does
// not blow away history; the rate limiter, however, is rebuilt with
// the new budget. Pass nil compiledRule + parseErr to mark the rule
// disabled with an error.
func (r *RuleSet) AddOrUpdate(name string, enabled bool, compiledRule *sigma.CompiledRule, parseErr string, burst, sustained int) {
	if burst <= 0 {
		burst = DefaultRuleBurst
	}
	if sustained <= 0 {
		sustained = DefaultRuleSustainedPerSec
	}
	entry := &RuleEntry{
		Compiled:   compiledRule,
		Enabled:    enabled && compiledRule != nil,
		Limiter:    rate.NewLimiter(rate.Limit(sustained), burst),
		ParseError: parseErr,
	}
	r.mu.Lock()
	if prev, ok := r.entries[name]; ok {
		entry.MatchCount.Store(prev.MatchCount.Load())
		entry.DroppedRateLimit.Store(prev.DroppedRateLimit.Load())
		if last := prev.LastMatchedAt.Load(); last != nil {
			entry.LastMatchedAt.Store(last)
		}
	}
	r.entries[name] = entry
	r.refreshSnapshot()
	r.mu.Unlock()
}

// Delete removes the named rule. No-op if absent.
func (r *RuleSet) Delete(name string) {
	r.mu.Lock()
	delete(r.entries, name)
	r.refreshSnapshot()
	r.mu.Unlock()
}

// Get returns the live entry for name (or nil). Used by the
// reconciler when reading back counters for status.
func (r *RuleSet) Get(name string) *RuleEntry {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.entries[name]
}

// Snapshot returns the current set of entries as a flat slice. The
// underlying slice is owned by RuleSet — callers must not mutate it.
// dispatch() relies on this being a single atomic load.
func (r *RuleSet) Snapshot() []*RuleEntry {
	return *r.snapshot.Load()
}

// refreshSnapshot rebuilds the atomic slice. Caller must hold mu.
func (r *RuleSet) refreshSnapshot() {
	out := make([]*RuleEntry, 0, len(r.entries))
	for _, e := range r.entries {
		out = append(out, e)
	}
	r.snapshot.Store(&out)
}

// --- helpers ----------------------------------------------------------------

// subjectFrom maps an AuditEvent.ObjectRef onto a SecurityEvent
// SubjectTier1. Unknown resources fall back to "External" so the SE
// stays valid against the SubjectKind enum.
func subjectFrom(ref *auditdetection.ObjectReference) (kind securityv1alpha1.SubjectKind, name, namespace string, uid types.UID) {
	if ref == nil {
		return "External", "", "", ""
	}
	return resourceToKind(ref.Resource), ref.Name, ref.Namespace, types.UID(ref.UID)
}

// resourceToKind covers the resources audit-detection rules typically
// target. It is intentionally not exhaustive — additions only when a
// rule needs a new mapping.
func resourceToKind(resource string) securityv1alpha1.SubjectKind {
	switch strings.ToLower(resource) {
	case "pods":
		return "Pod"
	case "nodes":
		return "Node"
	case "namespaces":
		return "Namespace"
	case "services":
		return "Service"
	case "secrets":
		return "Secret"
	case "configmaps":
		return "ConfigMap"
	case "serviceaccounts":
		return "ServiceAccount"
	case "deployments":
		return "Deployment"
	case "statefulsets":
		return "StatefulSet"
	case "daemonsets":
		return "DaemonSet"
	case "jobs":
		return "Job"
	case "cronjobs":
		return "CronJob"
	case "roles":
		return "Role"
	case "clusterroles":
		return "ClusterRole"
	case "rolebindings":
		return "RoleBinding"
	case "clusterrolebindings":
		return "ClusterRoleBinding"
	case "networkpolicies":
		return "NetworkPolicy"
	case "ciliumnetworkpolicies":
		return "CiliumNetworkPolicy"
	case "ingresses":
		return "Ingress"
	case "gateways":
		return "Gateway"
	case "mutatingwebhookconfigurations":
		return "MutatingWebhookConfiguration"
	case "validatingwebhookconfigurations":
		return "ValidatingWebhookConfiguration"
	case "customresourcedefinitions":
		return "CustomResourceDefinition"
	case "apiservices":
		return "APIService"
	case "certificatesigningrequests":
		return "CertificateSigningRequest"
	case "endpointslices":
		return "EndpointSlice"
	default:
		return "External"
	}
}

// classOrDefault falls back to Detection when the SigmaRule omits the
// class field (CRD default), keeping the SE classification stable.
func classOrDefault(c securityv1alpha1.Class) securityv1alpha1.Class {
	if c == "" {
		return "Detection"
	}
	return c
}

// renderSignals expands ${verb}, ${user.username}, ${objectRef.*}
// placeholders so SigmaRule signals can carry per-event context. Only
// the documented vars are recognised; everything else is left as-is.
func renderSignals(in map[string]string, ev *auditdetection.AuditEvent) map[string]string {
	if len(in) == 0 {
		return nil
	}
	vars := map[string]string{
		"${verb}":                 ev.Verb,
		"${user.username}":        ev.User.Username,
		"${stage}":                ev.Stage,
		"${requestURI}":           ev.RequestURI,
		"${userAgent}":            ev.UserAgent,
		"${objectRef.name}":       refField(ev, func(r *auditdetection.ObjectReference) string { return r.Name }),
		"${objectRef.namespace}":  refField(ev, func(r *auditdetection.ObjectReference) string { return r.Namespace }),
		"${objectRef.resource}":   refField(ev, func(r *auditdetection.ObjectReference) string { return r.Resource }),
		"${objectRef.apiGroup}":   refField(ev, func(r *auditdetection.ObjectReference) string { return r.APIGroup }),
		"${objectRef.apiVersion}": refField(ev, func(r *auditdetection.ObjectReference) string { return r.APIVersion }),
	}
	out := make(map[string]string, len(in))
	for k, tpl := range in {
		v := tpl
		for needle, repl := range vars {
			if strings.Contains(v, needle) {
				v = strings.ReplaceAll(v, needle, repl)
			}
		}
		out[k] = v
	}
	return out
}

func refField(ev *auditdetection.AuditEvent, get func(*auditdetection.ObjectReference) string) string {
	if ev.ObjectRef == nil {
		return ""
	}
	return get(ev.ObjectRef)
}

// eventTimestamp picks the most informative wall-clock from the audit
// entry. StageTimestamp wins when set, falling back to
// RequestReceivedTimestamp; both zero falls through to the Emitter's
// metav1.Now() default.
func eventTimestamp(ev *auditdetection.AuditEvent) metav1.Time {
	if !ev.StageTimestamp.IsZero() {
		return metav1.NewTime(ev.StageTimestamp)
	}
	if !ev.RequestReceivedTimestamp.IsZero() {
		return metav1.NewTime(ev.RequestReceivedTimestamp)
	}
	return metav1.Time{}
}

func timePtr(t time.Time) *time.Time { return &t }

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }
