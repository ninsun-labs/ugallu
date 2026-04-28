// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

// Package sigma is the audit-detection rule evaluator. It implements
// the Sigma "subset" surface from design 20 §A3 (equality, glob,
// AND/OR/NOT) and intentionally rejects the full Sigma language to
// keep the engine stateless and ReDoS-free.
package sigma

import (
	"errors"
	"strings"
)

// MaxGlobWildcards bounds the number of `*` wildcards a single glob
// pattern may contain. Anything larger is rejected at compile time —
// a defence against accidentally expensive matchers more than a
// security limit.
const MaxGlobWildcards = 8

// ErrTooManyWildcards is returned when a pattern exceeds
// MaxGlobWildcards. Compile-time only; the runtime never sees it.
var ErrTooManyWildcards = errors.New("sigma: glob pattern exceeds MaxGlobWildcards")

// Glob matches s against pattern using shell-style wildcards: `*`
// expands to any (possibly empty) substring, `?` matches exactly one
// character. There is no character-class support — the design 20 §A3
// subset omits POSIX brackets to avoid pulling in a regex engine.
//
// Patterns must satisfy ValidatePattern; passing an unvalidated
// pattern still works (Glob doesn't allocate beyond the input
// strings) but a runaway pattern can degrade match latency.
func Glob(pattern, s string) bool {
	return globMatch(pattern, s)
}

// ValidatePattern returns nil iff pattern is acceptable for runtime
// evaluation. Compile callers (the rule loader) call this once per
// pattern; runtime callers can skip the check.
func ValidatePattern(pattern string) error {
	if strings.Count(pattern, "*") > MaxGlobWildcards {
		return ErrTooManyWildcards
	}
	return nil
}

// globMatch is the iterative implementation. It handles `*` with
// backtracking and `?` with a single-rune skip. Time complexity is
// O(len(pattern) * len(s)) in the worst case (alternating `*` and
// literal runs); space is O(1).
func globMatch(pattern, s string) bool {
	pi, si := 0, 0
	starP, starS := -1, -1
	for si < len(s) {
		switch {
		case pi < len(pattern) && pattern[pi] == '*':
			// Record backtrack point and skip the star.
			starP = pi
			starS = si
			pi++
		case pi < len(pattern) && (pattern[pi] == '?' || pattern[pi] == s[si]):
			pi++
			si++
		case starP != -1:
			// Backtrack: rewind pi to just past the star and consume
			// one more char of s.
			pi = starP + 1
			starS++
			si = starS
		default:
			return false
		}
	}
	// Consume any trailing stars in pattern.
	for pi < len(pattern) && pattern[pi] == '*' {
		pi++
	}
	return pi == len(pattern)
}

// MatchAny returns true when s matches at least one of the supplied
// patterns. Empty pattern slice → false (no rule = no match).
func MatchAny(patterns []string, s string) bool {
	for _, p := range patterns {
		if Glob(p, s) {
			return true
		}
	}
	return false
}

// AnyOfList reports whether s appears in candidates (exact-string
// equality, no glob). Sigma rule fields like Verb / Resource /
// Namespace use this; NameGlob and UsernameGlob use Glob/MatchAny.
func AnyOfList(candidates []string, s string) bool {
	for _, c := range candidates {
		if c == s {
			return true
		}
	}
	return false
}
