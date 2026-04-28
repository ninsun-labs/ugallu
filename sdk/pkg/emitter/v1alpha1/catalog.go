// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"

// IsKnownType reports whether t appears in the SDK type catalog
// (v1alpha1.KnownTypes). The check is local-only — admission policy 5
// validates the same enum at apiserver-side, kept in sync by
// hack/ci-local.sh's type-catalog parity step.
func IsKnownType(t string) bool {
	_, ok := securityv1alpha1.KnownTypes[t]
	return ok
}
