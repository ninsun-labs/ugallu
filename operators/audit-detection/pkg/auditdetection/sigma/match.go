// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package sigma

import (
	"errors"
	"fmt"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"

	"github.com/ninsun-labs/ugallu/operators/audit-detection/pkg/auditdetection"
)

// CompiledRule is the runtime form of a SigmaRule: a precompiled
// matcher plus the SE-emit metadata. Build one via Compile() then
// call Match() many times.
type CompiledRule struct {
	// Name is the SigmaRule.metadata.name, copied for telemetry +
	// error messages.
	Name string

	// Spec is the source spec, kept around for the engine that
	// reads emit/severity/signals when a match fires.
	Spec securityv1alpha1.SigmaRuleSpec

	matcher *compiledMatch
}

// compiledMatch mirrors the SigmaMatch tree but with JSONPaths
// already parsed and globs validated.
type compiledMatch struct {
	verb              []string
	objectRef         *compiledObjectRef
	user              *compiledUser
	subresource       []string
	requestObjectGlob []compiledGlob
	anyOf             []*compiledMatch
	not               *compiledMatch
}

type compiledObjectRef struct {
	apiGroup    []string
	apiVersion  []string
	resource    []string
	subresource []string
	namespace   []string
	nameGlob    []string
}

type compiledUser struct {
	usernameGlob []string
	groups       []string
}

type compiledGlob struct {
	steps    []jsonPathStep
	patterns []string
}

// Compile validates and prepares a SigmaRule for runtime evaluation.
// All errors are returned at compile time so the engine can mark the
// rule as ParseError'd in status without ever evaluating it.
func Compile(rule *securityv1alpha1.SigmaRule) (*CompiledRule, error) {
	if rule == nil {
		return nil, errors.New("sigma: nil rule")
	}
	if rule.Spec.Emit.SecurityEventType == "" {
		return nil, errors.New("sigma: spec.emit.securityEventType is required")
	}
	if _, ok := securityv1alpha1.KnownTypes[rule.Spec.Emit.SecurityEventType]; !ok {
		return nil, fmt.Errorf("sigma: spec.emit.securityEventType %q is not in the catalog",
			rule.Spec.Emit.SecurityEventType)
	}
	matcher, err := compileMatch(&rule.Spec.Match)
	if err != nil {
		return nil, fmt.Errorf("compile match: %w", err)
	}
	return &CompiledRule{
		Name:    rule.Name,
		Spec:    rule.Spec,
		matcher: matcher,
	}, nil
}

// compileMatch compiles the top-level SigmaMatch: the inline leaf
// fields plus AnyOf/Not. The split between SigmaMatch and
// SigmaMatchLeaf caps recursion at depth 1 (no nested AnyOf/Not),
// matching design 20 §A3.
func compileMatch(m *securityv1alpha1.SigmaMatch) (*compiledMatch, error) {
	if m == nil {
		return nil, nil
	}
	cm, err := compileLeaf(&m.SigmaMatchLeaf)
	if err != nil {
		return nil, err
	}
	for i := range m.AnyOf {
		sub, err := compileLeaf(&m.AnyOf[i])
		if err != nil {
			return nil, fmt.Errorf("anyOf[%d]: %w", i, err)
		}
		cm.anyOf = append(cm.anyOf, sub)
	}
	if m.Not != nil {
		sub, err := compileLeaf(m.Not)
		if err != nil {
			return nil, fmt.Errorf("not: %w", err)
		}
		cm.not = sub
	}
	return cm, nil
}

// compileLeaf compiles the primitive predicates only — no AnyOf/Not.
// Reused for the inline portion of SigmaMatch and for each AnyOf/Not
// entry.
func compileLeaf(m *securityv1alpha1.SigmaMatchLeaf) (*compiledMatch, error) {
	if m == nil {
		return nil, nil
	}
	cm := &compiledMatch{
		verb:        m.Verb,
		subresource: m.Subresource,
	}
	if m.ObjectRef != nil {
		for _, p := range m.ObjectRef.NameGlob {
			if err := ValidatePattern(p); err != nil {
				return nil, fmt.Errorf("objectRef.nameGlob %q: %w", p, err)
			}
		}
		cm.objectRef = &compiledObjectRef{
			apiGroup:    m.ObjectRef.APIGroup,
			apiVersion:  m.ObjectRef.APIVersion,
			resource:    m.ObjectRef.Resource,
			subresource: m.ObjectRef.Subresource,
			namespace:   m.ObjectRef.Namespace,
			nameGlob:    m.ObjectRef.NameGlob,
		}
	}
	if m.User != nil {
		for _, p := range m.User.UsernameGlob {
			if err := ValidatePattern(p); err != nil {
				return nil, fmt.Errorf("user.usernameGlob %q: %w", p, err)
			}
		}
		cm.user = &compiledUser{
			usernameGlob: m.User.UsernameGlob,
			groups:       m.User.Groups,
		}
	}
	for i := range m.RequestObjectGlob {
		gm := &m.RequestObjectGlob[i]
		steps, err := compileJSONPath(gm.JSONPath)
		if err != nil {
			return nil, fmt.Errorf("requestObjectGlob[%d].jsonPath: %w", i, err)
		}
		for _, p := range gm.Patterns {
			if err := ValidatePattern(p); err != nil {
				return nil, fmt.Errorf("requestObjectGlob[%d].patterns %q: %w", i, p, err)
			}
		}
		cm.requestObjectGlob = append(cm.requestObjectGlob, compiledGlob{
			steps:    steps,
			patterns: gm.Patterns,
		})
	}
	return cm, nil
}

// Match returns true when the AuditEvent satisfies the compiled
// rule's predicate. nil rule or nil event → false.
func (r *CompiledRule) Match(ev *auditdetection.AuditEvent) bool {
	if r == nil || r.matcher == nil || ev == nil {
		return false
	}
	return matchEval(r.matcher, ev)
}

// matchEval is the recursive evaluator. The structure mirrors
// compiledMatch: top-level fields combine with implicit AND, AnyOf
// is OR, Not is negation.
func matchEval(m *compiledMatch, ev *auditdetection.AuditEvent) bool {
	if m == nil {
		return true
	}
	if len(m.verb) > 0 && !AnyOfList(m.verb, ev.Verb) {
		return false
	}
	if len(m.subresource) > 0 {
		sub := ""
		if ev.ObjectRef != nil {
			sub = ev.ObjectRef.Subresource
		}
		if !AnyOfList(m.subresource, sub) {
			return false
		}
	}
	if m.objectRef != nil && !matchObjectRef(m.objectRef, ev.ObjectRef) {
		return false
	}
	if m.user != nil && !matchUser(m.user, &ev.User) {
		return false
	}
	for _, g := range m.requestObjectGlob {
		if !matchRequestObjectGlob(&g, ev.RequestObject) {
			return false
		}
	}
	if len(m.anyOf) > 0 {
		matched := false
		for _, sub := range m.anyOf {
			if matchEval(sub, ev) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	if m.not != nil {
		if matchEval(m.not, ev) {
			return false
		}
	}
	return true
}

// matchObjectRef returns true when ref satisfies the compiled
// ObjectRefMatch. nil ref + non-empty match → false (the rule wants
// a populated objectRef).
func matchObjectRef(m *compiledObjectRef, ref *auditdetection.ObjectReference) bool {
	if ref == nil {
		return false
	}
	if len(m.apiGroup) > 0 && !AnyOfList(m.apiGroup, ref.APIGroup) {
		return false
	}
	if len(m.apiVersion) > 0 && !AnyOfList(m.apiVersion, ref.APIVersion) {
		return false
	}
	if len(m.resource) > 0 && !AnyOfList(m.resource, ref.Resource) {
		return false
	}
	if len(m.subresource) > 0 && !AnyOfList(m.subresource, ref.Subresource) {
		return false
	}
	if len(m.namespace) > 0 && !AnyOfList(m.namespace, ref.Namespace) {
		return false
	}
	if len(m.nameGlob) > 0 && !MatchAny(m.nameGlob, ref.Name) {
		return false
	}
	return true
}

// matchUser returns true when info satisfies the compiled UserMatch.
func matchUser(m *compiledUser, info *auditdetection.UserInfo) bool {
	if info == nil {
		return false
	}
	if len(m.usernameGlob) > 0 && !MatchAny(m.usernameGlob, info.Username) {
		return false
	}
	if len(m.groups) > 0 {
		hit := false
		for _, want := range m.groups {
			for _, got := range info.Groups {
				if want == got {
					hit = true
					break
				}
			}
			if hit {
				break
			}
		}
		if !hit {
			return false
		}
	}
	return true
}

// matchRequestObjectGlob walks the JSONPath into the request body
// and tests at least one resolved value against at least one
// pattern (any-of).
func matchRequestObjectGlob(g *compiledGlob, body map[string]any) bool {
	values := evalJSONPath(body, g.steps)
	for _, v := range values {
		if MatchAny(g.patterns, v) {
			return true
		}
	}
	return false
}
