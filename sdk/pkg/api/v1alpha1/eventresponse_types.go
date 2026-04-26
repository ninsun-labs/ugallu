// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// EventResponseSpec describes a single atomic action taken by a responder
// in reaction to a SecurityEvent. Spec is immutable post-creation
// (enforced by admission policy, design 15).
type EventResponseSpec struct {
	// SecurityEventRef is the parent SecurityEvent this response acts on.
	SecurityEventRef SecurityEventRef `json:"securityEventRef"`

	// Responder identifies the controller emitting this response.
	Responder ResponderRef `json:"responder"`

	// Action is the typed action with parameters.
	Action Action `json:"action"`

	// RetryPolicy controls retry on transient errors.
	RetryPolicy RetryPolicy `json:"retryPolicy,omitempty"`

	// ParentResponseRef chains responses for multi-step workflows
	// (e.g., forensics IncidentResponse expands into multiple EventResponses).
	ParentResponseRef *corev1.ObjectReference `json:"parentResponseRef,omitempty"`
}

// SecurityEventRef is a stable handle on a parent SecurityEvent.
type SecurityEventRef struct {
	Name string    `json:"name"`
	UID  types.UID `json:"uid,omitempty"`
}

// ResponderRef identifies the controller that owns an EventResponse.
type ResponderRef struct {
	Kind     string `json:"kind"`
	Name     string `json:"name"`
	Version  string `json:"version,omitempty"`
	Instance string `json:"instance,omitempty"`
}

// Action is a typed action with parameters and an optional K8s target ref.
type Action struct {
	Type       ActionType              `json:"type"`
	TargetRef  *corev1.ObjectReference `json:"targetRef,omitempty"`
	Parameters map[string]string       `json:"parameters,omitempty"`
}

// RetryPolicy governs retry of transient errors only (design 04 Q11).
type RetryPolicy struct {
	// +kubebuilder:default=3
	MaxAttempts int `json:"maxAttempts,omitempty"`

	// +kubebuilder:default=Exponential
	BackoffStrategy BackoffStrategy `json:"backoffStrategy,omitempty"`

	// InitialDelay (default 10s).
	InitialDelay metav1.Duration `json:"initialDelay,omitempty"`

	// MaxDelay (default 5m).
	MaxDelay metav1.Duration `json:"maxDelay,omitempty"`
}

// EventResponseStatus is the mutable lifecycle of the response.
type EventResponseStatus struct {
	Phase         EventResponsePhase `json:"phase,omitempty"`
	Attempts      int                `json:"attempts,omitempty"`
	LastAttemptAt *metav1.Time       `json:"lastAttemptAt,omitempty"`
	NextAttemptAt *metav1.Time       `json:"nextAttemptAt,omitempty"`
	StartedAt     *metav1.Time       `json:"startedAt,omitempty"`
	CompletedAt   *metav1.Time       `json:"completedAt,omitempty"`
	Outcome       *Outcome           `json:"outcome,omitempty"`
	Evidence      []EvidenceRef      `json:"evidence,omitempty"`
	Error         *ResponseError     `json:"error,omitempty"`
	CancelReason  string             `json:"cancelReason,omitempty"`

	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// Outcome captures the typed result of an action.
type Outcome struct {
	Type    OutcomeType `json:"type"`
	Message string      `json:"message,omitempty"`
}

// ResponseError records a typed failure with retry classification.
type ResponseError struct {
	Type   ErrorCategory `json:"type"`
	Reason string        `json:"reason,omitempty"`
	Detail string        `json:"detail,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster,shortName=er
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Action",type=string,JSONPath=`.spec.action.type`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Outcome",type=string,JSONPath=`.status.outcome.type`
// +kubebuilder:printcolumn:name="Responder",type=string,JSONPath=`.spec.responder.name`
// +kubebuilder:printcolumn:name="Attempts",type=integer,JSONPath=`.status.attempts`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// EventResponse records a single atomic action taken by a responder.
// Cluster-scoped (D5). Listing per parent uses label
// `ugallu.io/security-event-uid=<uid>`.
type EventResponse struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   EventResponseSpec   `json:"spec,omitempty"`
	Status EventResponseStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// EventResponseList is the list type for EventResponse.
type EventResponseList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []EventResponse `json:"items"`
}

func init() {
	SchemeBuilder.Register(&EventResponse{}, &EventResponseList{})
}
