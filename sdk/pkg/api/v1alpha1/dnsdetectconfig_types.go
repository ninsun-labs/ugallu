// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// DNSDetectSourceMode picks which DNS observation backend the
// operator subscribes to. CoreDNSPlugin is the primary
// (full-payload, design 21 §D2) — Wave 3 Sprint 3 lockata. Tetragon
// kprobe is a degraded fallback when the plugin is not available
// (only DNSAnomalousPort detector remains functional).
//
// +kubebuilder:validation:Enum=coredns_plugin;tetragon_kprobe
type DNSDetectSourceMode string

// DNSDetectSourceMode enumerates the supported DNS event sources
// the dns-detect operator consumes. coredns_plugin is the primary
// (gRPC stream from the in-tree plugin); tetragon_kprobe is the
// fallback used when the cluster cannot host a CoreDNS plugin.
const (
	// DNSDetectSourceCoreDNSPlugin reads from the coredns-ugallu
	// plugin's UgalluDNSStream gRPC server.
	DNSDetectSourceCoreDNSPlugin DNSDetectSourceMode = "coredns_plugin"
	// DNSDetectSourceTetragonKprobe reads kprobe DNS events from
	// the tetragon-bridge sidecar (Wave 4 §D7).
	DNSDetectSourceTetragonKprobe DNSDetectSourceMode = "tetragon_kprobe"
)

// DNSDetectConfigSpec is the runtime config the ugallu-dns-detect
// operator reads (design 21 §D4).
type DNSDetectConfigSpec struct {
	// Source selects the DNS event source backend.
	Source DNSSourceConfig `json:"source"`

	// Detectors toggles + tunes the 5 anomaly detectors.
	Detectors DNSDetectorsConfig `json:"detectors"`
}

// DNSSourceConfig wraps the source-specific knobs.
type DNSSourceConfig struct {
	// Primary is the default source. coredns_plugin is the Wave 3
	// production default — full payload, mTLS gRPC stream.
	// +kubebuilder:default=coredns_plugin
	Primary DNSDetectSourceMode `json:"primary"`

	// Fallback is engaged when Primary is unreachable for >60s. Set
	// to tetragon_kprobe to degrade gracefully (only DNSAnomalousPort
	// remains functional). Empty = no fallback (operator stays
	// degraded with DNSSourceSilent meta-events).
	// +optional
	Fallback DNSDetectSourceMode `json:"fallback,omitempty"`

	// Plugin is the gRPC endpoint config used when Primary or
	// Fallback resolves to coredns_plugin.
	// +optional
	Plugin *DNSPluginEndpoint `json:"plugin,omitempty"`
}

// DNSPluginEndpoint pins the CoreDNS gRPC stream coordinates.
type DNSPluginEndpoint struct {
	// GRPCEndpoint is the host:port of the coredns-ugallu plugin.
	// Default cluster-DNS endpoint: "coredns.kube-system.svc.cluster.local:8443".
	GRPCEndpoint string `json:"grpcEndpoint"`

	// TokenSecret references the bearer-token Secret used during
	// Wave 3 (mTLS lands in a follow-up).
	// +optional
	TokenSecret *corev1.SecretKeySelector `json:"tokenSecret,omitempty"`
}

// DNSDetectorsConfig holds per-detector knobs. All five default
// enabled to mirror the design. Disabling one lets the operator
// run in a "lighter" profile — useful in air-gapped clusters that
// can't reach RDAP.
type DNSDetectorsConfig struct {
	Exfiltration  ExfiltrationDetectorConfig  `json:"exfiltration"`
	Tunneling     TunnelingDetectorConfig     `json:"tunneling"`
	Blocklist     BlocklistDetectorConfig     `json:"blocklist"`
	YoungDomain   YoungDomainDetectorConfig   `json:"youngDomain"`
	AnomalousPort AnomalousPortDetectorConfig `json:"anomalousPort"`
}

// ExfiltrationDetectorConfig — heuristics for entropy + length
// anomaly on TXT/A queries.
type ExfiltrationDetectorConfig struct {
	// +kubebuilder:default=true
	Enabled bool `json:"enabled"`

	// MinLabelLen is the minimum length of label[0] (the leftmost
	// dot-separated component) below which the detector skips.
	// +kubebuilder:default=60
	MinLabelLen int32 `json:"minLabelLen,omitempty"`

	// MinEntropy is the Shannon-entropy threshold on label[0].
	// Above it, the query qualifies as "high entropy".
	// +kubebuilder:default="4.0"
	MinEntropy string `json:"minEntropy,omitempty"`

	// WindowSize is the per-Pod ring buffer length for entropy
	// history.
	// +kubebuilder:default=64
	WindowSize int32 `json:"windowSize,omitempty"`

	// ConsecutiveTriggers is the number of recent high-entropy
	// queries that fire the SE.
	// +kubebuilder:default=3
	ConsecutiveTriggers int32 `json:"consecutiveTriggers,omitempty"`
}

// TunnelingDetectorConfig — base64-in-subdomain heuristic.
type TunnelingDetectorConfig struct {
	// +kubebuilder:default=true
	Enabled bool `json:"enabled"`

	// RatelimitPerPod limits SE emission to one per period per Pod.
	// +kubebuilder:default="1m"
	RatelimitPerPod metav1.Duration `json:"ratelimitPerPod,omitempty"`
}

// BlocklistDetectorConfig — match against admin-curated FQDN list(s).
type BlocklistDetectorConfig struct {
	// +kubebuilder:default=true
	Enabled bool `json:"enabled"`

	// ConfigMaps lists ConfigMaps to load. Each must contain a
	// `blocklist` data key with one FQDN per line. Supports
	// suffix wildcards (`*.example.com`).
	ConfigMaps []DNSBlocklistRef `json:"configMaps,omitempty"`
}

// DNSBlocklistRef points at a ConfigMap holding blocklist entries.
type DNSBlocklistRef struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

// YoungDomainDetectorConfig — RDAP / WHOIS lookup gated by domain age.
type YoungDomainDetectorConfig struct {
	// +kubebuilder:default=true
	Enabled bool `json:"enabled"`

	// ThresholdDays is the cutoff. Domains registered within the
	// past N days are flagged on lookup.
	// +kubebuilder:default=30
	ThresholdDays int32 `json:"thresholdDays,omitempty"`

	// RDAPEndpoint is the lookup endpoint base URL.
	// +kubebuilder:default="https://rdap.org/"
	RDAPEndpoint string `json:"rdapEndpoint,omitempty"`

	// RateLimit caps lookups to RDAP infrastructure. Format:
	// "<count>/<unit>" (e.g. "100/h").
	// +kubebuilder:default="100/h"
	RateLimit string `json:"rateLimit,omitempty"`
}

// AnomalousPortDetectorConfig — flag DNS queries to a non-53 port.
type AnomalousPortDetectorConfig struct {
	// +kubebuilder:default=true
	Enabled bool `json:"enabled"`
}

// DNSDetectConfigStatus surfaces operator-side runtime state.
type DNSDetectConfigStatus struct {
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// Source reports the active source backend (may differ from
	// Spec.Source.Primary when the operator has fallen back).
	Source DNSDetectSourceMode `json:"source,omitempty"`

	// LastConfigLoadAt marks the most recent successful spec read.
	LastConfigLoadAt *metav1.Time `json:"lastConfigLoadAt,omitempty"`

	// InflightLookups reports the live count of pending RDAP
	// lookups (YoungDomain detector).
	InflightLookups int32 `json:"inflightLookups,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster,shortName=dnsdetectcfg
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Source",type=string,JSONPath=`.status.source`
// +kubebuilder:printcolumn:name="LookupsInFlight",type=integer,JSONPath=`.status.inflightLookups`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// DNSDetectConfig is the cluster-scoped singleton (name="default")
// that governs the ugallu-dns-detect operator.
type DNSDetectConfig struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   DNSDetectConfigSpec   `json:"spec,omitempty"`
	Status DNSDetectConfigStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// DNSDetectConfigList is the list type for DNSDetectConfig.
type DNSDetectConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []DNSDetectConfig `json:"items"`
}

func init() {
	SchemeBuilder.Register(&DNSDetectConfig{}, &DNSDetectConfigList{})
}
