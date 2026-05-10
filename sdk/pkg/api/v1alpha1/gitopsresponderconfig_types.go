// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// GitOpsResponderConfigSpec is the runtime config for the GitOps responder.
type GitOpsResponderConfigSpec struct {
	Providers []GitProvider `json:"providers"`

	DefaultProvider string `json:"defaultProvider"`

	DefaultRepo GitRepo `json:"defaultRepo"`

	Bot BotIdentity `json:"bot"`

	ChangeDefaults ChangeDefaults `json:"changeDefaults,omitempty"`

	BranchStrategy BranchStrategy `json:"branchStrategy,omitempty"`

	// +kubebuilder:default=abort
	ConflictBehavior ConflictBehavior `json:"conflictBehavior,omitempty"`

	Routing []RoutingRule `json:"routing,omitempty"`
}

// GitProvider describes a configured git host.
type GitProvider struct {
	Name string          `json:"name"`
	Type GitProviderType `json:"type"`
	Host string          `json:"host"`
	Auth GitAuthConfig   `json:"auth"`
}

// GitAuthConfig is the credentials reference for a provider.
type GitAuthConfig struct {
	Mode      GitAuthMode                 `json:"mode"`
	SecretRef corev1.LocalObjectReference `json:"secretRef"`
}

// GitRepo points at a target repository on a provider.
type GitRepo struct {
	Provider string `json:"provider"`
	Owner    string `json:"owner"`
	Repo     string `json:"repo"`
	Branch   string `json:"branch,omitempty"`
}

// BotIdentity describes the GitOps bot identity.
type BotIdentity struct {
	Name          string `json:"name"`
	Email         string `json:"email"`
	SSHSigningKey string `json:"sshSigningKey,omitempty"`
}

// ChangeDefaults tunes default PR/MR behaviour.
type ChangeDefaults struct {
	Draft            bool     `json:"draft,omitempty"`
	Labels           []string `json:"labels,omitempty"`
	RequireReviewers []string `json:"requireReviewers,omitempty"`
}

// BranchStrategy controls branch naming and lifecycle.
type BranchStrategy struct {
	NamingTemplate   string `json:"namingTemplate,omitempty"`
	DeleteAfterMerge bool   `json:"deleteAfterMerge,omitempty"`
}

// RoutingRule selects a target repo based on labels or namespace pattern.
type RoutingRule struct {
	MatchLabels           map[string]string `json:"matchLabels,omitempty"`
	MatchNamespacePattern string            `json:"matchNamespacePattern,omitempty"`
	Repo                  GitRepo           `json:"repo"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Namespaced,shortName=gitopscfg
// +kubebuilder:printcolumn:name="Default-Provider",type=string,JSONPath=`.spec.defaultProvider`
// +kubebuilder:printcolumn:name="Default-Repo",type=string,JSONPath=`.spec.defaultRepo.repo`
// +kubebuilder:printcolumn:name="Conflict",type=string,JSONPath=`.spec.conflictBehavior`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// GitOpsResponderConfig is the namespaced config CR for the GitOps responder.
type GitOpsResponderConfig struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec GitOpsResponderConfigSpec `json:"spec,omitempty"`
}

// +kubebuilder:object:root=true

// GitOpsResponderConfigList is the list type for GitOpsResponderConfig.
type GitOpsResponderConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []GitOpsResponderConfig `json:"items"`
}

func init() {
	SchemeBuilder.Register(&GitOpsResponderConfig{}, &GitOpsResponderConfigList{})
}
