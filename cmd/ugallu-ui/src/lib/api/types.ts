// TypeScript mirror of the BFF OpenAPI schemas. Hand-maintained for
// now; can be regenerated from cmd/ugallu-bff/api/openapi.yaml via
// openapi-typescript when the surface stabilises.

export type Class =
	| 'Detection'
	| 'Audit'
	| 'Forensic'
	| 'Compliance'
	| 'Anomaly'
	| 'PolicyViolation';

export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';

export type Phase = '' | 'Active' | 'Attested' | 'Archived';

export interface Me {
	sub: string;
	email?: string;
	name?: string;
	groups?: string[];
	bffVersion: string;
}

export interface EventSubject {
	kind: string;
	name?: string;
	namespace?: string;
	uid?: string;
}

export interface EventSource {
	kind?: string;
	name?: string;
	instance?: string;
	clusterName?: string;
	clusterID?: string;
}

export interface EventSummary {
	name: string;
	namespace?: string;
	uid: string;
	creationTimestamp: string;
	type: string;
	class: Class;
	severity: Severity;
	subject: EventSubject;
	source: EventSource;
	phase?: Phase;
	correlationID?: string;
	labels?: Record<string, string>;
}

export interface EventListResponse {
	items: EventSummary[];
	generation: string;
	continue?: string;
}

export interface ApiError {
	code: string;
	message: string;
	ts?: string;
	loginURL?: string;
}

export interface EventsListQuery {
	namespace?: string;
	class?: Class;
	type?: string;
	severity?: Severity;
	subjectKind?: string;
	q?: string;
	labelSelector?: string;
	limit?: number;
	continue?: string;
}

// --- Run summaries -------------------------------------------------

export type RunKind =
	| 'BackupVerifyRun'
	| 'ComplianceScanRun'
	| 'ConfidentialAttestationRun'
	| 'SeccompTrainingRun';

export type RunPhase = '' | 'Pending' | 'Running' | 'Succeeded' | 'Failed';

export interface RunSummary {
	kind: RunKind;
	namespace: string;
	name: string;
	uid: string;
	phase?: RunPhase;
	startTime?: string;
	completionTime?: string;
	creationTimestamp: string;
	worstSeverity?: Severity | '';
	resultName?: string;
	details?: Record<string, string>;
}

export interface RunListResponse {
	items: RunSummary[];
}

export interface RunDetailResponse {
	kind: RunKind;
	run: unknown; // raw apiserver object
	result?: unknown; // raw Result/Profile or null
}

// --- Configuration summaries --------------------------------------

export type ConfigKind =
	| 'AuditDetectionConfig'
	| 'DNSDetectConfig'
	| 'ForensicsConfig'
	| 'HoneypotConfig'
	| 'WebhookAuditorConfig'
	| 'TTLConfig'
	| 'WORMConfig'
	| 'AttestorConfig'
	| 'GitOpsResponderConfig';

export interface ConfigSummary {
	kind: ConfigKind;
	namespace?: string;
	name: string;
	uid: string;
	creationTimestamp: string;
	generation?: number;
	lastConfigLoadAt?: string;
	healthy: boolean;
}

export interface ConfigListResponse {
	items: ConfigSummary[];
}

export interface ConfigDetailResponse {
	kind: ConfigKind;
	object: unknown;
}
