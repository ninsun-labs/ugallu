// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

// +kubebuilder:object:generate=true
// +groupName=security.ugallu.io

package v1alpha1

import (
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/scheme"
)

// GroupVersion is the group version for the v1alpha1 ugallu API.
var GroupVersion = schema.GroupVersion{Group: "security.ugallu.io", Version: "v1alpha1"}

// SchemeBuilder is used to add Go types to the GroupVersionKind scheme.
var SchemeBuilder = &scheme.Builder{GroupVersion: GroupVersion}

// AddToScheme adds the types in this group-version to the given scheme.
var AddToScheme = SchemeBuilder.AddToScheme
