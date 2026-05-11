// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

// Package router selects a target GitRepo + Provider for an incoming
// EventResponse. Routing rules in GitOpsResponderConfig let an
// operator partition responses across multiple repos by namespace
// pattern or label match.
package router

import (
	"fmt"
	"regexp"
	"sync"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
)

// Router resolves an EventResponse + parent SE labels to a (provider,
// repo) target. Routing is "first match wins" over the configured
// rules; the default repo is the catch-all.
type Router struct {
	defaultRepo     securityv1alpha1.GitRepo
	defaultProvider string
	rules           []compiledRule
}

type compiledRule struct {
	matchLabels map[string]string
	nsPattern   *regexp.Regexp
	repo        securityv1alpha1.GitRepo
}

// New compiles a config snapshot. nil cfg returns a router that rejects
// every request with a clear error so operators see a misconfiguration
// loudly rather than silently routing to a default.
func New(cfg *securityv1alpha1.GitOpsResponderConfigSpec) (*Router, error) {
	if cfg == nil {
		return nil, fmt.Errorf("router: cfg is required")
	}
	if cfg.DefaultProvider == "" || cfg.DefaultRepo.Repo == "" {
		return nil, fmt.Errorf("router: defaultProvider + defaultRepo are required")
	}
	r := &Router{defaultRepo: cfg.DefaultRepo, defaultProvider: cfg.DefaultProvider}
	for i, rule := range cfg.Routing {
		cr := compiledRule{matchLabels: rule.MatchLabels, repo: rule.Repo}
		if rule.MatchNamespacePattern != "" {
			re, err := regexp.Compile(rule.MatchNamespacePattern)
			if err != nil {
				return nil, fmt.Errorf("router: rule[%d].matchNamespacePattern: %w", i, err)
			}
			cr.nsPattern = re
		}
		if cr.repo.Repo == "" {
			return nil, fmt.Errorf("router: rule[%d].repo.repo is required", i)
		}
		r.rules = append(r.rules, cr)
	}
	return r, nil
}

// Route picks the target repo for an EventResponse with the given
// parent-SE namespace + labels. Falls back to the default repo when
// no rule matches.
func (r *Router) Route(parentNamespace string, labels map[string]string) securityv1alpha1.GitRepo {
	for _, rule := range r.rules {
		if rule.nsPattern != nil && !rule.nsPattern.MatchString(parentNamespace) {
			continue
		}
		if !labelsSatisfy(rule.matchLabels, labels) {
			continue
		}
		return rule.repo
	}
	return r.defaultRepo
}

// DefaultProvider returns the catch-all provider name configured by
// the operator.
func (r *Router) DefaultProvider() string { return r.defaultProvider }

// labelsSatisfy reports whether want is a subset of have. Empty want
// matches any.
func labelsSatisfy(want, have map[string]string) bool {
	if len(want) == 0 {
		return true
	}
	for k, v := range want {
		if have[k] != v {
			return false
		}
	}
	return true
}

// Snapshot is a thread-safe handle around a Router that callers can
// swap atomically when the config CR changes. Reconcilers read via
// Snapshot.Current and avoid holding a stale router across runs.
type Snapshot struct {
	mu sync.RWMutex
	r  *Router
}

// NewSnapshot returns an empty snapshot - Set must be called before
// Current returns a usable router.
func NewSnapshot() *Snapshot { return &Snapshot{} }

// Set installs r as the active router. nil clears.
func (s *Snapshot) Set(r *Router) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.r = r
}

// Current returns the active router (or nil when unset).
func (s *Snapshot) Current() *Router {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.r
}
