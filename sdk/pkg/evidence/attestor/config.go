// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package attestor

import (
	"context"

	"sigs.k8s.io/controller-runtime/pkg/client"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
)

// DefaultAttestorConfigNamespace is the namespace consulted for the
// AttestorConfig singleton (matches the TTL controller convention).
const DefaultAttestorConfigNamespace = "ugallu-system"

// LoadAttestorConfig fetches the AttestorConfig singleton from the
// given namespace, preferring name="default" when multiple exist.
// Returns (nil, nil) when no AttestorConfig is present so the caller
// can fall back to flags / baked-in defaults; only API errors are
// propagated.
func LoadAttestorConfig(ctx context.Context, c client.Client, namespace string) (*securityv1alpha1.AttestorConfigSpec, error) {
	if namespace == "" {
		namespace = DefaultAttestorConfigNamespace
	}
	list := &securityv1alpha1.AttestorConfigList{}
	if err := c.List(ctx, list, client.InNamespace(namespace)); err != nil {
		return nil, err
	}
	if len(list.Items) == 0 {
		return nil, nil
	}
	for i := range list.Items {
		if list.Items[i].Name == "default" {
			return &list.Items[i].Spec, nil
		}
	}
	return &list.Items[0].Spec, nil
}
