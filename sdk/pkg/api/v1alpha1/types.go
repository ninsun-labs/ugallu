// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

// Class is the top-level classification of a SecurityEvent (design D1, locked enum).
// +kubebuilder:validation:Enum=Detection;Anomaly;PolicyViolation;Forensic;Compliance;Audit
type Class string

// Class constants.
const (
	ClassDetection       Class = "Detection"
	ClassAnomaly         Class = "Anomaly"
	ClassPolicyViolation Class = "PolicyViolation"
	ClassForensic        Class = "Forensic"
	ClassCompliance      Class = "Compliance"
	ClassAudit           Class = "Audit"
)

// Severity is the 5-grade severity scale (design D7).
// +kubebuilder:validation:Enum=critical;high;medium;low;info
type Severity string

// Severity constants.
const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// SecurityEventPhase is the lifecycle phase of a SecurityEvent (design 02 lifecycle).
// Pending is intentionally absent in v1alpha1 (review H3).
// +kubebuilder:validation:Enum=Active;Attested;Archived
type SecurityEventPhase string

// SecurityEventPhase constants.
const (
	SecurityEventPhaseActive   SecurityEventPhase = "Active"
	SecurityEventPhaseAttested SecurityEventPhase = "Attested"
	SecurityEventPhaseArchived SecurityEventPhase = "Archived"
)

// EventResponsePhase is the lifecycle phase of an EventResponse (design 04 Q2).
// +kubebuilder:validation:Enum=Pending;Running;Succeeded;Failed;Cancelled
type EventResponsePhase string

// EventResponsePhase constants.
const (
	EventResponsePhasePending   EventResponsePhase = "Pending"
	EventResponsePhaseRunning   EventResponsePhase = "Running"
	EventResponsePhaseSucceeded EventResponsePhase = "Succeeded"
	EventResponsePhaseFailed    EventResponsePhase = "Failed"
	EventResponsePhaseCancelled EventResponsePhase = "Cancelled"
)

// AttestationBundlePhase is the lifecycle phase of an AttestationBundle (design 05).
// +kubebuilder:validation:Enum=Pending;Signed;Logged;Sealed;Failed
type AttestationBundlePhase string

// AttestationBundlePhase constants.
const (
	AttestationBundlePhasePending AttestationBundlePhase = "Pending"
	AttestationBundlePhaseSigned  AttestationBundlePhase = "Signed"
	AttestationBundlePhaseLogged  AttestationBundlePhase = "Logged"
	AttestationBundlePhaseSealed  AttestationBundlePhase = "Sealed"
	AttestationBundlePhaseFailed  AttestationBundlePhase = "Failed"
)

// ActionType is the kind of action an EventResponse takes (design 04 Q4).
// Adding values requires a CRD bump and an admission policy update.
// +kubebuilder:validation:Enum=PodFreeze;PodUnfreeze;NetworkDeny;FilesystemSnapshot;MemorySnapshot;EvidenceUpload;GitOpsChange;RBACRevoke;NodeIsolate;ImageQuarantine;WebhookDisable;TokenRevoke;NotificationSend
type ActionType string

// ActionType constants.
const (
	ActionPodFreeze          ActionType = "PodFreeze"
	ActionPodUnfreeze        ActionType = "PodUnfreeze"
	ActionNetworkDeny        ActionType = "NetworkDeny"
	ActionFilesystemSnapshot ActionType = "FilesystemSnapshot"
	ActionMemorySnapshot     ActionType = "MemorySnapshot"
	ActionEvidenceUpload     ActionType = "EvidenceUpload"
	ActionGitOpsChange       ActionType = "GitOpsChange"
	ActionRBACRevoke         ActionType = "RBACRevoke"
	ActionNodeIsolate        ActionType = "NodeIsolate"
	ActionImageQuarantine    ActionType = "ImageQuarantine"
	ActionWebhookDisable     ActionType = "WebhookDisable"
	ActionTokenRevoke        ActionType = "TokenRevoke"
	ActionNotificationSend   ActionType = "NotificationSend"
)

// OutcomeType is the typed result of an EventResponse action.
// +kubebuilder:validation:Enum=ActionTaken;NoActionNeeded;Skipped;Errored
type OutcomeType string

// OutcomeType constants.
const (
	OutcomeActionTaken    OutcomeType = "ActionTaken"
	OutcomeNoActionNeeded OutcomeType = "NoActionNeeded"
	OutcomeSkipped        OutcomeType = "Skipped"
	OutcomeErrored        OutcomeType = "Errored"
)

// ErrorCategory classifies an EventResponse error for retry decisioning (design 04 Q11).
// +kubebuilder:validation:Enum=Transient;Permanent;Conflicting;Unauthorized
type ErrorCategory string

// ErrorCategory constants.
const (
	ErrorTransient    ErrorCategory = "Transient"
	ErrorPermanent    ErrorCategory = "Permanent"
	ErrorConflicting  ErrorCategory = "Conflicting"
	ErrorUnauthorized ErrorCategory = "Unauthorized"
)

// BackoffStrategy is the retry backoff strategy.
// +kubebuilder:validation:Enum=Exponential;Fixed;None
type BackoffStrategy string

// BackoffStrategy constants.
const (
	BackoffExponential BackoffStrategy = "Exponential"
	BackoffFixed       BackoffStrategy = "Fixed"
	BackoffNone        BackoffStrategy = "None"
)

// SigningMode is the cryptographic mode used by the attestor (design 06).
// ed25519-dev is an in-process keypair for dev / test only; production
// deployments must use fulcio-keyless or openbao-transit.
// +kubebuilder:validation:Enum=fulcio-keyless;openbao-transit;dual;ed25519-dev
type SigningMode string

// SigningMode constants.
const (
	SigningModeFulcioKeyless  SigningMode = "fulcio-keyless"
	SigningModeOpenBaoTransit SigningMode = "openbao-transit"
	SigningModeDual           SigningMode = "dual"
	SigningModeEd25519Dev     SigningMode = "ed25519-dev"
)

// EncryptionMode is the WORM at-rest encryption mode (design 07 W6).
// +kubebuilder:validation:Enum=sse-kms;sse-s3;none
type EncryptionMode string

// EncryptionMode constants.
const (
	EncryptionSSEKMS EncryptionMode = "sse-kms"
	EncryptionSSES3  EncryptionMode = "sse-s3"
	EncryptionNone   EncryptionMode = "none"
)

// WORMBackend identifies the S3-compatible backend (design 07 W1).
// +kubebuilder:validation:Enum=seaweedfs;aws-s3;rustfs
type WORMBackend string

// WORMBackend constants.
const (
	WORMBackendSeaweedFS WORMBackend = "seaweedfs"
	WORMBackendAWSS3     WORMBackend = "aws-s3"
	WORMBackendRustFS    WORMBackend = "rustfs"
)

// GitProviderType is the kind of git host (design 08 G2).
// +kubebuilder:validation:Enum=github;gitlab;forgejo
type GitProviderType string

// GitProviderType constants.
const (
	GitProviderGitHub  GitProviderType = "github"
	GitProviderGitLab  GitProviderType = "gitlab"
	GitProviderForgejo GitProviderType = "forgejo"
)

// GitAuthMode is the git host auth method.
// +kubebuilder:validation:Enum=github-app;project-access-token;app-token;pat;ssh-deploy-key
type GitAuthMode string

// GitAuthMode constants.
const (
	GitAuthGitHubApp    GitAuthMode = "github-app"
	GitAuthProjectToken GitAuthMode = "project-access-token"
	GitAuthAppToken     GitAuthMode = "app-token"
	GitAuthPAT          GitAuthMode = "pat"
	GitAuthSSHDeployKey GitAuthMode = "ssh-deploy-key"
)

// ConflictBehavior is the GitOps responder conflict policy (design 08 G5).
// +kubebuilder:validation:Enum=abort;force;merge
type ConflictBehavior string

// ConflictBehavior constants.
const (
	ConflictAbort ConflictBehavior = "abort"
	ConflictForce ConflictBehavior = "force"
	ConflictMerge ConflictBehavior = "merge"
)

// SubjectKind enumerates the supported K8s kinds for SecurityEvent.Subject (design 10).
// +kubebuilder:validation:Enum=Pod;Container;Node;ServiceAccount;Secret;ConfigMap;Namespace;Service;EndpointSlice;Deployment;StatefulSet;DaemonSet;Job;CronJob;Role;ClusterRole;RoleBinding;ClusterRoleBinding;NetworkPolicy;CiliumNetworkPolicy;Ingress;Gateway;MutatingWebhookConfiguration;ValidatingWebhookConfiguration;CustomResourceDefinition;APIService;CertificateSigningRequest;Cluster;External
type SubjectKind string

// Type constants — curated catalog per design 11 (Wave 1 + operational anomalies).
// Adding values requires a PR to this file plus the admission policy.
const (
	// Audit (audit-detection raw observations).
	TypeKubernetesAPICall = "KubernetesAPICall"
	TypeWatchSubscription = "WatchSubscription"
	TypeProxyAccess       = "ProxyAccess"

	// Detection (audit-detection Sigma rules).
	TypeWildcardRBACBinding          = "WildcardRBACBinding"
	TypeClusterAdminGranted          = "ClusterAdminGranted"
	TypePrivilegedPodChange          = "PrivilegedPodChange"
	TypeHostPathMount                = "HostPathMount"
	TypeHostNetworkPod               = "HostNetworkPod"
	TypeHostPIDPod                   = "HostPIDPod"
	TypeHostIPCPod                   = "HostIPCPod"
	TypeCapAddDangerous              = "CapAddDangerous"
	TypeRunAsRootContainer           = "RunAsRootContainer"
	TypeServiceAccountTokenAutomount = "ServiceAccountTokenAutomount"
	TypeSecretMountedAsEnv           = "SecretMountedAsEnv"
	TypeImagePullPolicyAlways        = "ImagePullPolicyAlways"
	TypeLatestImageTag               = "LatestImageTag"
	TypeUnsignedImage                = "UnsignedImage"
	TypeExecIntoPod                  = "ExecIntoPod"
	TypePortForwardOpened            = "PortForwardOpened"
	TypeServiceAccountTokenRequest   = "ServiceAccountTokenRequest"
	TypeAnonymousAccess              = "AnonymousAccess"
	TypeImpersonationUsed            = "ImpersonationUsed"
	TypePrivilegeEscalationAttempt   = "PrivilegeEscalationAttempt"
	TypeWebhookSideEffectsUnknown    = "WebhookSideEffectsUnknown"
	TypeFailOpenWebhook              = "FailOpenWebhook"
	TypeCRDOverwrite                 = "CRDOverwrite"
	TypeAPIServiceInsecure           = "APIServiceInsecure"
	TypeLongLivedSecretToken         = "LongLivedSecretToken"
	TypeNamespacePSAWeakened         = "NamespacePSAWeakened"

	// Detection (webhook-auditor — design 21 §W5).
	TypeMutatingWebhookHighRisk    = "MutatingWebhookHighRisk"
	TypeValidatingWebhookHighRisk  = "ValidatingWebhookHighRisk"
	TypeWebhookCAUntrusted         = "WebhookCAUntrusted"
	TypeWebhookFailOpenCriticalAPI = "WebhookFailOpenCriticalAPI"
	TypeWebhookSecretAccess        = "WebhookSecretAccess"
	TypeWebhookConfigDeleted       = "WebhookConfigDeleted"

	// Detection (dns-detect — design 21 §D3).
	TypeDNSExfiltration      = "DNSExfiltration"
	TypeDNSTunneling         = "DNSTunneling"
	TypeDNSToBlocklistedFQDN = "DNSToBlocklistedFQDN"
	TypeDNSToYoungDomain     = "DNSToYoungDomain"
	TypeDNSAnomalousPort     = "DNSAnomalousPort"

	// Detection (tenant-escape — design 21 §T4).
	TypeCrossTenantSecretAccess    = "CrossTenantSecretAccess"
	TypeCrossTenantHostPathOverlap = "CrossTenantHostPathOverlap"
	TypeCrossTenantNetworkPolicy   = "CrossTenantNetworkPolicy"
	TypeCrossTenantExec            = "CrossTenantExec"

	// Detection (honeypot — design 21 §H4).
	TypeHoneypotTriggered = "HoneypotTriggered"
	TypeHoneypotMisplaced = "HoneypotMisplaced"

	// Forensic (forensics workflow).
	TypeIncidentCaptureStarted   = "IncidentCaptureStarted"
	TypeIncidentCaptureCompleted = "IncidentCaptureCompleted"
	TypeIncidentCaptureFailed    = "IncidentCaptureFailed"
	TypeEvidencePreserved        = "EvidencePreserved"
	TypePodFrozen                = "PodFrozen"
	TypePodUnfrozen              = "PodUnfrozen"

	// Anomaly (reasoner + operational meta-events).
	TypeLateralMovementSuspected  = "LateralMovementSuspected"
	TypeRBACEscalationChain       = "RBACEscalationChain"
	TypeIncidentBurst             = "IncidentBurst"
	TypeBehaviorBaselineDeviation = "BehaviorBaselineDeviation"
	TypeWORMQuotaExceeded         = "WORMQuotaExceeded"
	TypeWORMIntegrityViolation    = "WORMIntegrityViolation"
	TypeTTLConfigMissing          = "TTLConfigMissing"
	TypeGitOpsConflict            = "GitOpsConflict"
	TypeSourceRateLimited         = "SourceRateLimited"
	TypeAttestorUnavailable       = "AttestorUnavailable"
	TypeEtcdBackpressureHigh      = "EtcdBackpressureHigh"
	TypeClockSkewDetected         = "ClockSkewDetected"
	TypeAuditLogStreamSilent      = "AuditLogStreamSilent"
	TypeTetragonDataInconsistent  = "TetragonDataInconsistent"
	TypeKeyRotationEmergency      = "KeyRotationEmergency"
	TypeImageRevocation           = "ImageRevocation"
	TypeAttestorRecovered         = "AttestorRecovered"

	// Anomaly (webhook-auditor operational — design 21 §W7).
	TypeWebhookEvalFailed = "WebhookEvalFailed"

	// Anomaly (dns-detect operational — design 21 §D6).
	TypeDNSSourceSilent     = "DNSSourceSilent"
	TypeDNSConfigMissing    = "DNSConfigMissing"
	TypeDNSDetectorDegraded = "DNSDetectorDegraded"

	// Anomaly (tenant-escape operational — design 21 §T5).
	TypeAuditBridgeSilent        = "AuditBridgeSilent"
	TypeTenantBoundaryEmpty      = "TenantBoundaryEmpty"
	TypeTenantBoundaryOverlap    = "TenantBoundaryOverlap"
	TypeTenantEscapeSourceLagged = "TenantEscapeSourceLagged"

	// Anomaly (honeypot operational — design 21 §H5).
	TypeHoneypotConfigInvalid = "HoneypotConfigInvalid"
	TypeHoneypotDecoyMissing  = "HoneypotDecoyMissing"

	// PolicyViolation (seccomp-gen — design 21 §G / Wave 4 §S3).
	TypeSeccompTrainingStarted   = "SeccompTrainingStarted"
	TypeSeccompTrainingCompleted = "SeccompTrainingCompleted"
	TypeSeccompTrainingFailed    = "SeccompTrainingFailed"

	// Compliance + Detection (backup-verify — design 21 §B / Wave 4 §S4).
	TypeBackupVerifyStarted   = "BackupVerifyStarted"
	TypeBackupVerifyCompleted = "BackupVerifyCompleted"
	TypeBackupVerifyMismatch  = "BackupVerifyMismatch"
	TypeBackupVerifyFailed    = "BackupVerifyFailed"

	// Compliance (compliance-scan — design 21 §C / Wave 4 §S5).
	TypeComplianceScanStarted   = "ComplianceScanStarted"
	TypeComplianceScanCompleted = "ComplianceScanCompleted"
	TypeComplianceScanFailed    = "ComplianceScanFailed"
)
