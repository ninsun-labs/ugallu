// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package attestor

import (
	"context"
	"errors"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
)

// DefaultWORMConfigNamespace is the namespace consulted for the
// WORMConfig singleton. Mirrors the AttestorConfig convention.
const DefaultWORMConfigNamespace = "ugallu-system"

// WORMCredentialsAccessKeyField is the Secret key holding the S3
// access-key ID.
const WORMCredentialsAccessKeyField = "access-key"

// WORMCredentialsSecretKeyField is the Secret key holding the S3
// secret-access key.
const WORMCredentialsSecretKeyField = "secret-key" //nolint:gosec // field name, not a credential value

// LoadWORMConfig fetches the WORMConfig singleton from the given
// namespace, preferring name="default" when multiple exist. Returns
// (nil, nil) when no WORMConfig is present so the caller can fall back
// to flags / baked-in defaults; only API errors are propagated.
func LoadWORMConfig(ctx context.Context, c client.Client, namespace string) (*securityv1alpha1.WORMConfigSpec, error) {
	if namespace == "" {
		namespace = DefaultWORMConfigNamespace
	}
	list := &securityv1alpha1.WORMConfigList{}
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

// ResolveWORMCredentials reads the access-key + secret-key fields out
// of the Secret referenced by the WORMConfig. The Secret is looked up
// in the supplied namespace (the WORMConfig CR's own namespace); the
// expected keys are WORMCredentialsAccessKeyField and
// WORMCredentialsSecretKeyField. A missing ref returns ("", "", nil)
// so the caller can fall back to the AWS credential chain.
func ResolveWORMCredentials(ctx context.Context, c client.Client, namespace string, spec *securityv1alpha1.WORMConfigSpec) (accessKey, secretKey string, err error) {
	if spec == nil || spec.CredentialsSecretRef == nil || spec.CredentialsSecretRef.Name == "" {
		return "", "", nil
	}
	if namespace == "" {
		return "", "", errors.New("namespace is required to resolve WORMConfig credentials secret")
	}
	sec := &corev1.Secret{}
	key := types.NamespacedName{Namespace: namespace, Name: spec.CredentialsSecretRef.Name}
	if err = c.Get(ctx, key, sec); err != nil {
		return "", "", fmt.Errorf("get worm credentials secret %s/%s: %w", key.Namespace, key.Name, err)
	}
	access := string(sec.Data[WORMCredentialsAccessKeyField])
	secret := string(sec.Data[WORMCredentialsSecretKeyField])
	if access == "" || secret == "" {
		return "", "", fmt.Errorf("worm credentials secret %s/%s is missing %q or %q",
			key.Namespace, key.Name, WORMCredentialsAccessKeyField, WORMCredentialsSecretKeyField)
	}
	return access, secret, nil
}
