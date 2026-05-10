// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package auditdetection

import (
	"context"
	"time"
)

// AuditEvent is the normalised projection of an apiserver audit-log
// entry that flows through the Sigma rule engine. Both Source
// implementations (file tail and webhook) decode their respective
// wire shapes into this struct so the engine stays backend-agnostic.
//
// The schema mirrors the public fields of audit.k8s.io/v1.Event but
// keeps only what the Sigma rules consume. Fields added later must
// remain optional so old rules keep matching.
type AuditEvent struct {
	// AuditID is the apiserver-assigned UUID of the entry. Used as
	// the SecurityEvent CorrelationID seed when the rule fires.
	AuditID string `json:"auditID,omitempty"`

	// Stage is RequestReceived / ResponseStarted / ResponseComplete /
	// Panic. Most rules want ResponseComplete to dedupe the same
	// request seen at multiple stages.
	Stage string `json:"stage,omitempty"`

	// RequestURI is the full request path including query string.
	RequestURI string `json:"requestURI,omitempty"`

	// Verb maps to the K8s verb (get/list/watch/create/update/patch/
	// delete/proxy/connect). Also covers non-resource URLs ("get").
	Verb string `json:"verb,omitempty"`

	// User identifies the requester. Username is the principal
	// (email / SA path / system: identity).
	User UserInfo `json:"user,omitempty"`

	// ImpersonatedUser is set when the request used --as.
	ImpersonatedUser *UserInfo `json:"impersonatedUser,omitempty"`

	// SourceIPs is the chain (proxies first, client last).
	SourceIPs []string `json:"sourceIPs,omitempty"`

	// UserAgent of the requester.
	UserAgent string `json:"userAgent,omitempty"`

	// ObjectRef is populated for resource verbs.
	ObjectRef *ObjectReference `json:"objectRef,omitempty"`

	// ResponseStatus is the apiserver response code + message.
	ResponseStatus *ResponseStatus `json:"responseStatus,omitempty"`

	// RequestObject is the body of CREATE/UPDATE/PATCH when the
	// audit policy requested "RequestResponse" level. Often nil.
	RequestObject map[string]any `json:"requestObject,omitempty"`

	// ResponseObject mirrors RequestObject for the response side.
	ResponseObject map[string]any `json:"responseObject,omitempty"`

	// RequestReceivedTimestamp is the wall-clock entry time.
	RequestReceivedTimestamp time.Time `json:"requestReceivedTimestamp,omitempty"`

	// StageTimestamp marks the stage transition.
	StageTimestamp time.Time `json:"stageTimestamp,omitempty"`

	// Annotations are policy decisions (authorization/authentication
	// reasons). Sigma rules sometimes match on these.
	Annotations map[string]string `json:"annotations,omitempty"`

	// Raw carries the original JSON line so a SecurityEvent that
	// references this entry can ship the full source. The engine
	// stores it as []byte to avoid a redundant marshal round-trip.
	Raw []byte `json:"-"`
}

// UserInfo mirrors the apiserver authentication.UserInfo subset that
// audit logs carry.
type UserInfo struct {
	Username string              `json:"username,omitempty"`
	UID      string              `json:"uid,omitempty"`
	Groups   []string            `json:"groups,omitempty"`
	Extra    map[string][]string `json:"extra,omitempty"`
}

// ObjectReference identifies the K8s resource the request targeted.
type ObjectReference struct {
	APIGroup    string `json:"apiGroup,omitempty"`
	APIVersion  string `json:"apiVersion,omitempty"`
	Resource    string `json:"resource,omitempty"`
	Subresource string `json:"subresource,omitempty"`
	Name        string `json:"name,omitempty"`
	Namespace   string `json:"namespace,omitempty"`
	UID         string `json:"uid,omitempty"`
}

// ResponseStatus is the trimmed metav1.Status the apiserver returns.
type ResponseStatus struct {
	Code    int32  `json:"code,omitempty"`
	Status  string `json:"status,omitempty"`
	Message string `json:"message,omitempty"`
	Reason  string `json:"reason,omitempty"`
}

// Source produces a stream of AuditEvents to the engine. Two
// implementations exist:
//   - FileSource: tail + inotify on the kubelet/apiserver audit-log
//     file.
//   - WebhookSource: HTTPS endpoint that accepts batched audit events
//     from the apiserver's webhook backend (Phase 2).
//
// Implementations MUST be safe for a single goroutine to call Run on
// — concurrent calls are undefined. Run blocks until ctx is
// cancelled or a fatal source error occurs; the returned channel is
// closed before Run returns so consumers can detect shutdown.
type Source interface {
	// Run drives the source. Events are pushed on the returned
	// channel; closing the channel signals normal shutdown. The
	// channel is buffered (capacity is implementation-defined) and a
	// slow consumer eventually applies backpressure on the source —
	// the FileSource pauses inotify drain, the WebhookSource returns
	// 503 on the next POST.
	Run(ctx context.Context) (<-chan *AuditEvent, error)

	// Name is a stable label for telemetry and logs.
	Name() string
}
