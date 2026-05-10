// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// SubjectTier1 is the snapshot of the K8s subject of a SecurityEvent or
// EventResponse, captured at emit time. It carries common identity fields
// plus exactly one populated kind-specific discriminator pointer.
//
// The discriminator is enforced by an admission policy.
type SubjectTier1 struct {
	APIVersion      string                  `json:"apiVersion,omitempty"`
	Kind            SubjectKind             `json:"kind"`
	Name            string                  `json:"name"`
	Namespace       string                  `json:"namespace,omitempty"`
	UID             types.UID               `json:"uid,omitempty"`
	ResourceVersion string                  `json:"resourceVersion,omitempty"`
	Labels          map[string]string       `json:"labels,omitempty"`
	OwnerReferences []metav1.OwnerReference `json:"ownerReferences,omitempty"`

	// Discriminator: only one populated, matched against Kind by admission policy.
	Pod            *PodSubject            `json:"pod,omitempty"`
	Container      *ContainerSubject      `json:"container,omitempty"`
	Node           *NodeSubject           `json:"node,omitempty"`
	ServiceAccount *ServiceAccountSubject `json:"serviceAccount,omitempty"`
	Secret         *SecretSubject         `json:"secret,omitempty"`
	ConfigMap      *ConfigMapSubject      `json:"configMap,omitempty"`
	NamespaceData  *NamespaceSubject      `json:"namespaceData,omitempty"`
	Service        *ServiceSubject        `json:"service,omitempty"`
	EndpointSlice  *EndpointSliceSubject  `json:"endpointSlice,omitempty"`
	Workload       *WorkloadSubject       `json:"workload,omitempty"`
	Job            *JobSubject            `json:"job,omitempty"`
	Role           *RoleSubject           `json:"role,omitempty"`
	RoleBinding    *RoleBindingSubject    `json:"roleBinding,omitempty"`
	NetworkPolicy  *NetworkPolicySubject  `json:"networkPolicy,omitempty"`
	Ingress        *IngressSubject        `json:"ingress,omitempty"`
	WebhookConfig  *WebhookConfigSubject  `json:"webhookConfig,omitempty"`
	CRD            *CRDSubject            `json:"crd,omitempty"`
	APIService     *APIServiceSubject     `json:"apiService,omitempty"`
	CSR            *CSRSubject            `json:"csr,omitempty"`
	Cluster        *ClusterSubject        `json:"cluster,omitempty"`
	External       *ExternalSubject       `json:"external,omitempty"`

	// Failure markers (resolver fallback path).
	Partial    bool `json:"partial,omitempty"`
	Tombstone  bool `json:"tombstone,omitempty"`
	Unresolved bool `json:"unresolved,omitempty"`
}

// PodRef is a stable reference to a Pod, used as parent in ContainerSubject.
type PodRef struct {
	Namespace       string    `json:"namespace"`
	Name            string    `json:"name"`
	UID             types.UID `json:"uid,omitempty"`
	ResourceVersion string    `json:"resourceVersion,omitempty"`
}

// ServiceRef references a backing Service (used by APIService).
type ServiceRef struct {
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name"`
	Port      *int32 `json:"port,omitempty"`
}

// PodSubject is the Tier-1 snapshot for a Pod.
type PodSubject struct {
	NodeName            string          `json:"nodeName,omitempty"`
	ServiceAccountName  string          `json:"serviceAccountName,omitempty"`
	HostNetwork         bool            `json:"hostNetwork,omitempty"`
	HostPID             bool            `json:"hostPID,omitempty"`
	HostIPC             bool            `json:"hostIPC,omitempty"`
	Containers          []ContainerInfo `json:"containers,omitempty"`
	InitContainers      []ContainerInfo `json:"initContainers,omitempty"`
	EphemeralContainers []ContainerInfo `json:"ephemeralContainers,omitempty"`
	Volumes             []VolumeInfo    `json:"volumes,omitempty"`

	PodSecurityContext *PodSecCtx `json:"podSecurityContext,omitempty"`

	NodeSelector      map[string]string `json:"nodeSelector,omitempty"`
	Tolerations       []TolerationInfo  `json:"tolerations,omitempty"`
	Affinity          *AffinityInfo     `json:"affinity,omitempty"`
	PriorityClassName string            `json:"priorityClassName,omitempty"`
	Priority          *int32            `json:"priority,omitempty"`

	RuntimeClassName string              `json:"runtimeClassName,omitempty"`
	Overhead         corev1.ResourceList `json:"overhead,omitempty"`

	DNSPolicy   string         `json:"dnsPolicy,omitempty"`
	DNSConfig   *DNSConfigInfo `json:"dnsConfig,omitempty"`
	Subdomain   string         `json:"subdomain,omitempty"`
	Hostname    string         `json:"hostname,omitempty"`
	HostAliases []HostAlias    `json:"hostAliases,omitempty"`

	AutomountServiceAccountToken *bool `json:"automountServiceAccountToken,omitempty"`
	EnableServiceLinks           *bool `json:"enableServiceLinks,omitempty"`

	TerminationGracePeriodSeconds *int64 `json:"terminationGracePeriodSeconds,omitempty"`

	Phase    string `json:"phase,omitempty"`
	QOSClass string `json:"qosClass,omitempty"`
}

// PodSecCtx is the pod-level security context.
type PodSecCtx struct {
	RunAsUser           *int64           `json:"runAsUser,omitempty"`
	RunAsGroup          *int64           `json:"runAsGroup,omitempty"`
	RunAsNonRoot        *bool            `json:"runAsNonRoot,omitempty"`
	SupplementalGroups  []int64          `json:"supplementalGroups,omitempty"`
	FSGroup             *int64           `json:"fsGroup,omitempty"`
	FSGroupChangePolicy string           `json:"fsGroupChangePolicy,omitempty"`
	Sysctls             []SysctlInfo     `json:"sysctls,omitempty"`
	SeccompProfile      *SeccompProfile  `json:"seccompProfile,omitempty"`
	SELinuxOptions      *SELinuxOptions  `json:"seLinuxOptions,omitempty"`
	AppArmorProfile     *AppArmorProfile `json:"appArmorProfile,omitempty"`
}

// ContainerInfo is the slim per-container snapshot.
type ContainerInfo struct {
	Name            string                       `json:"name"`
	Image           string                       `json:"image,omitempty"`
	ImageDigest     string                       `json:"imageDigest,omitempty"`
	ImagePullPolicy string                       `json:"imagePullPolicy,omitempty"`
	VolumeMounts    []VolumeMount                `json:"volumeMounts,omitempty"`
	EnvNames        []string                     `json:"envNames,omitempty"`
	EnvFrom         []EnvFromRef                 `json:"envFrom,omitempty"`
	Ports           []ContainerPort              `json:"ports,omitempty"`
	Resources       *corev1.ResourceRequirements `json:"resources,omitempty"`
	SecurityContext *ContainerSecCtx             `json:"securityContext,omitempty"`
	Lifecycle       *LifecycleInfo               `json:"lifecycle,omitempty"`
	LivenessProbe   *ProbeInfo                   `json:"livenessProbe,omitempty"`
	ReadinessProbe  *ProbeInfo                   `json:"readinessProbe,omitempty"`
	StartupProbe    *ProbeInfo                   `json:"startupProbe,omitempty"`
	WorkingDir      string                       `json:"workingDir,omitempty"`
	Stdin           bool                         `json:"stdin,omitempty"`
	TTY             bool                         `json:"tty,omitempty"`
}

// ContainerSecCtx is the per-container security context (LSM completeness).
type ContainerSecCtx struct {
	Privileged               bool                 `json:"privileged,omitempty"`
	RunAsUser                *int64               `json:"runAsUser,omitempty"`
	RunAsGroup               *int64               `json:"runAsGroup,omitempty"`
	RunAsNonRoot             *bool                `json:"runAsNonRoot,omitempty"`
	ReadOnlyRootFilesystem   *bool                `json:"readOnlyRootFilesystem,omitempty"`
	AllowPrivilegeEscalation *bool                `json:"allowPrivilegeEscalation,omitempty"`
	Capabilities             *corev1.Capabilities `json:"capabilities,omitempty"`
	SeccompProfile           *SeccompProfile      `json:"seccompProfile,omitempty"`
	AppArmorProfile          *AppArmorProfile     `json:"appArmorProfile,omitempty"`
	SELinuxOptions           *SELinuxOptions      `json:"seLinuxOptions,omitempty"`
	ProcMount                string               `json:"procMount,omitempty"`
}

// VolumeMount is the slim mount info.
type VolumeMount struct {
	Name             string `json:"name"`
	MountPath        string `json:"mountPath"`
	ReadOnly         bool   `json:"readOnly,omitempty"`
	SubPath          string `json:"subPath,omitempty"`
	MountPropagation string `json:"mountPropagation,omitempty"`
}

// EnvFromRef is the slim envFrom ref (only names, never values).
type EnvFromRef struct {
	ConfigMapRefName string `json:"configMapRefName,omitempty"`
	SecretRefName    string `json:"secretRefName,omitempty"`
	Optional         *bool  `json:"optional,omitempty"`
	Prefix           string `json:"prefix,omitempty"`
}

// ContainerPort exposes minimal port info.
type ContainerPort struct {
	Name          string `json:"name,omitempty"`
	HostPort      int32  `json:"hostPort,omitempty"`
	ContainerPort int32  `json:"containerPort"`
	Protocol      string `json:"protocol,omitempty"`
	HostIP        string `json:"hostIP,omitempty"`
}

// VolumeInfo captures the actual hostPath for security audit.
type VolumeInfo struct {
	Name         string `json:"name"`
	Type         string `json:"type"`
	Source       string `json:"source,omitempty"`
	HostPath     string `json:"hostPath,omitempty"`
	HostPathType string `json:"hostPathType,omitempty"`
}

// LifecycleInfo captures lifecycle hooks (postStart / preStop).
type LifecycleInfo struct {
	PostStart *HookInfo `json:"postStart,omitempty"`
	PreStop   *HookInfo `json:"preStop,omitempty"`
}

// HookInfo is a slim hook descriptor (exec command captured for security audit).
type HookInfo struct {
	Type    string   `json:"type"`
	Command []string `json:"command,omitempty"`
	Path    string   `json:"path,omitempty"`
	Port    int32    `json:"port,omitempty"`
}

// ProbeInfo is a slim probe descriptor.
type ProbeInfo struct {
	Type    string   `json:"type"`
	Command []string `json:"command,omitempty"`
	Path    string   `json:"path,omitempty"`
	Port    int32    `json:"port,omitempty"`
}

// SysctlInfo is a kernel parameter override.
type SysctlInfo struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// SeccompProfile descriptor.
type SeccompProfile struct {
	Type             string `json:"type"`
	LocalhostProfile string `json:"localhostProfile,omitempty"`
}

// AppArmorProfile descriptor.
type AppArmorProfile struct {
	Type             string `json:"type"`
	LocalhostProfile string `json:"localhostProfile,omitempty"`
}

// SELinuxOptions descriptor.
type SELinuxOptions struct {
	User  string `json:"user,omitempty"`
	Role  string `json:"role,omitempty"`
	Type  string `json:"type,omitempty"`
	Level string `json:"level,omitempty"`
}

// TolerationInfo is a slim toleration.
type TolerationInfo struct {
	Key      string `json:"key,omitempty"`
	Operator string `json:"operator,omitempty"`
	Value    string `json:"value,omitempty"`
	Effect   string `json:"effect,omitempty"`
}

// AffinityInfo carries node/pod affinity for tenant-escape detection.
type AffinityInfo struct {
	NodeAffinity    *corev1.NodeAffinity    `json:"nodeAffinity,omitempty"`
	PodAffinity     *corev1.PodAffinity     `json:"podAffinity,omitempty"`
	PodAntiAffinity *corev1.PodAntiAffinity `json:"podAntiAffinity,omitempty"`
}

// DNSConfigInfo captures pod DNS configuration.
type DNSConfigInfo struct {
	Nameservers []string `json:"nameservers,omitempty"`
	Searches    []string `json:"searches,omitempty"`
	Options     []string `json:"options,omitempty"`
}

// HostAlias is a static host file entry.
type HostAlias struct {
	IP        string   `json:"ip"`
	Hostnames []string `json:"hostnames"`
}

// ContainerSubject identifies a single container as the subject of an event.
type ContainerSubject struct {
	PodRef        PodRef         `json:"podRef"`
	ContainerName string         `json:"containerName"`
	ContainerID   string         `json:"containerID,omitempty"`
	Image         string         `json:"image,omitempty"`
	ImageDigest   string         `json:"imageDigest,omitempty"`
	PID           *int32         `json:"pid,omitempty"`
	CgroupID      uint64         `json:"cgroupID,omitempty"`
	StartedAt     *metav1.Time   `json:"startedAt,omitempty"`
	Embedded      *ContainerInfo `json:"embedded,omitempty"`
}

// NodeSubject is the Tier-1 snapshot for a Node.
type NodeSubject struct {
	Roles            []string            `json:"roles,omitempty"`
	KernelVersion    string              `json:"kernelVersion,omitempty"`
	OSImage          string              `json:"osImage,omitempty"`
	KubeletVersion   string              `json:"kubeletVersion,omitempty"`
	ContainerRuntime string              `json:"containerRuntime,omitempty"`
	Architecture     string              `json:"architecture,omitempty"`
	OperatingSystem  string              `json:"operatingSystem,omitempty"`
	Taints           []string            `json:"taints,omitempty"`
	Conditions       []string            `json:"conditions,omitempty"`
	Capacity         corev1.ResourceList `json:"capacity,omitempty"`
	Allocatable      corev1.ResourceList `json:"allocatable,omitempty"`
	InternalIP       string              `json:"internalIP,omitempty"`
	Hostname         string              `json:"hostname,omitempty"`
}

// ServiceAccountSubject is the Tier-1 snapshot for a ServiceAccount.
type ServiceAccountSubject struct {
	AutomountToken   *bool    `json:"automountToken,omitempty"`
	ImagePullSecrets []string `json:"imagePullSecrets,omitempty"`
	Secrets          []string `json:"secrets,omitempty"`
}

// SecretSubject — never carries data (S10.2).
type SecretSubject struct {
	Type      string   `json:"type,omitempty"`
	DataKeys  []string `json:"dataKeys,omitempty"`
	Immutable *bool    `json:"immutable,omitempty"`
	SizeBytes int      `json:"sizeBytes,omitempty"`
}

// ConfigMapSubject — never carries data (S10.2).
type ConfigMapSubject struct {
	DataKeys       []string `json:"dataKeys,omitempty"`
	BinaryDataKeys []string `json:"binaryDataKeys,omitempty"`
	Immutable      *bool    `json:"immutable,omitempty"`
	SizeBytes      int      `json:"sizeBytes,omitempty"`
}

// NamespaceSubject is the Tier-1 snapshot for a Namespace.
type NamespaceSubject struct {
	Labels      map[string]string `json:"labels,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
	Phase       string            `json:"phase,omitempty"`
	PSALevel    *PSAInfo          `json:"psaLevel,omitempty"`
}

// PSAInfo describes Pod Security Admission settings on a Namespace.
type PSAInfo struct {
	Enforce        string `json:"enforce,omitempty"`
	EnforceVersion string `json:"enforceVersion,omitempty"`
	Audit          string `json:"audit,omitempty"`
	Warn           string `json:"warn,omitempty"`
}

// ServiceSubject is the Tier-1 snapshot for a Service.
type ServiceSubject struct {
	Type                     string            `json:"type,omitempty"`
	ClusterIP                string            `json:"clusterIP,omitempty"`
	ClusterIPs               []string          `json:"clusterIPs,omitempty"`
	ExternalIPs              []string          `json:"externalIPs,omitempty"`
	LoadBalancerIP           string            `json:"loadBalancerIP,omitempty"`
	LoadBalancerSourceRanges []string          `json:"loadBalancerSourceRanges,omitempty"`
	ExternalName             string            `json:"externalName,omitempty"`
	Ports                    []ServicePort     `json:"ports,omitempty"`
	Selector                 map[string]string `json:"selector,omitempty"`
	SessionAffinity          string            `json:"sessionAffinity,omitempty"`
	InternalTrafficPolicy    string            `json:"internalTrafficPolicy,omitempty"`
	ExternalTrafficPolicy    string            `json:"externalTrafficPolicy,omitempty"`
	PublishNotReadyAddresses bool              `json:"publishNotReadyAddresses,omitempty"`
}

// ServicePort describes a port a Service exposes.
type ServicePort struct {
	Name       string `json:"name,omitempty"`
	Port       int32  `json:"port"`
	TargetPort string `json:"targetPort,omitempty"`
	Protocol   string `json:"protocol,omitempty"`
	NodePort   int32  `json:"nodePort,omitempty"`
}

// EndpointSliceSubject is the Tier-1 snapshot for an EndpointSlice.
type EndpointSliceSubject struct {
	AddressType  string         `json:"addressType,omitempty"`
	Endpoints    []EndpointInfo `json:"endpoints,omitempty"`
	Ports        []EndpointPort `json:"ports,omitempty"`
	OwnerService string         `json:"ownerService,omitempty"`
}

// EndpointInfo summarizes a single endpoint within an EndpointSlice.
type EndpointInfo struct {
	Addresses  []string `json:"addresses,omitempty"`
	Conditions []string `json:"conditions,omitempty"`
	Hostname   string   `json:"hostname,omitempty"`
	NodeName   string   `json:"nodeName,omitempty"`
}

// EndpointPort describes a port for an EndpointSlice.
type EndpointPort struct {
	Name        string `json:"name,omitempty"`
	Port        int32  `json:"port,omitempty"`
	Protocol    string `json:"protocol,omitempty"`
	AppProtocol string `json:"appProtocol,omitempty"`
}

// WorkloadSubject covers Deployment / StatefulSet / DaemonSet.
type WorkloadSubject struct {
	Kind            string                  `json:"kind"`
	Replicas        *int32                  `json:"replicas,omitempty"`
	Strategy        string                  `json:"strategy,omitempty"`
	PodTemplate     *PodSubject             `json:"podTemplate,omitempty"`
	Selector        map[string]string       `json:"selector,omitempty"`
	OwnerReferences []metav1.OwnerReference `json:"ownerReferences,omitempty"`
}

// JobSubject covers Job / CronJob.
type JobSubject struct {
	Kind             string       `json:"kind"`
	Schedule         string       `json:"schedule,omitempty"`
	BackoffLimit     *int32       `json:"backoffLimit,omitempty"`
	Completions      *int32       `json:"completions,omitempty"`
	Parallelism      *int32       `json:"parallelism,omitempty"`
	PodTemplate      *PodSubject  `json:"podTemplate,omitempty"`
	Suspend          *bool        `json:"suspend,omitempty"`
	LastScheduleTime *metav1.Time `json:"lastScheduleTime,omitempty"`
}

// RoleSubject covers Role / ClusterRole.
type RoleSubject struct {
	Kind             string                `json:"kind"`
	Rules            []PolicyRule          `json:"rules,omitempty"`
	AggregationLabel *metav1.LabelSelector `json:"aggregationLabel,omitempty"`
}

// PolicyRule is a slim PolicyRule (the serialized sub-set of
// rbacv1.PolicyRule).
type PolicyRule struct {
	Verbs           []string `json:"verbs"`
	APIGroups       []string `json:"apiGroups,omitempty"`
	Resources       []string `json:"resources,omitempty"`
	ResourceNames   []string `json:"resourceNames,omitempty"`
	NonResourceURLs []string `json:"nonResourceURLs,omitempty"`
}

// RoleBindingSubject covers RoleBinding / ClusterRoleBinding.
type RoleBindingSubject struct {
	Kind     string           `json:"kind"`
	RoleRef  RoleRef          `json:"roleRef"`
	Subjects []BindingSubject `json:"subjects,omitempty"`
}

// RoleRef is the role reference of a binding.
type RoleRef struct {
	APIGroup string `json:"apiGroup,omitempty"`
	Kind     string `json:"kind"`
	Name     string `json:"name"`
}

// BindingSubject is a subject of a RoleBinding / ClusterRoleBinding.
type BindingSubject struct {
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
	APIGroup  string `json:"apiGroup,omitempty"`
}

// NetworkPolicySubject covers NetworkPolicy / CiliumNetworkPolicy.
type NetworkPolicySubject struct {
	Kind         string            `json:"kind"`
	PolicyTypes  []string          `json:"policyTypes,omitempty"`
	PodSelector  map[string]string `json:"podSelector,omitempty"`
	Endpoint     string            `json:"endpoint,omitempty"`
	IngressRules int               `json:"ingressRules,omitempty"`
	EgressRules  int               `json:"egressRules,omitempty"`
}

// IngressSubject covers Ingress / Gateway.
type IngressSubject struct {
	Kind             string  `json:"kind"`
	IngressClassName *string `json:"ingressClassName,omitempty"`
	HostsCount       int     `json:"hostsCount,omitempty"`
	TLSCount         int     `json:"tlsCount,omitempty"`
	BackendsCount    int     `json:"backendsCount,omitempty"`
}

// WebhookConfigSubject covers MutatingWebhookConfiguration / ValidatingWebhookConfiguration.
type WebhookConfigSubject struct {
	Kind     string        `json:"kind"`
	Webhooks []WebhookInfo `json:"webhooks,omitempty"`
}

// WebhookInfo carries webhook descriptor without ca bundle body (S10.2).
type WebhookInfo struct {
	Name                    string                `json:"name"`
	ClientConfig            WebhookClientConfig   `json:"clientConfig"`
	Rules                   []RuleInfo            `json:"rules,omitempty"`
	FailurePolicy           string                `json:"failurePolicy,omitempty"`
	MatchPolicy             string                `json:"matchPolicy,omitempty"`
	SideEffects             string                `json:"sideEffects,omitempty"`
	TimeoutSeconds          *int32                `json:"timeoutSeconds,omitempty"`
	ReinvocationPolicy      string                `json:"reinvocationPolicy,omitempty"`
	AdmissionReviewVersions []string              `json:"admissionReviewVersions,omitempty"`
	NamespaceSelector       *metav1.LabelSelector `json:"namespaceSelector,omitempty"`
	ObjectSelector          *metav1.LabelSelector `json:"objectSelector,omitempty"`
}

// WebhookClientConfig is the slim client config (no ca bundle body).
type WebhookClientConfig struct {
	Service        *ServiceRef `json:"service,omitempty"`
	URL            string      `json:"url,omitempty"`
	CABundleSHA256 string      `json:"caBundleSHA256,omitempty"`
}

// RuleInfo is the slim webhook rule descriptor.
type RuleInfo struct {
	Operations  []string `json:"operations,omitempty"`
	APIGroups   []string `json:"apiGroups,omitempty"`
	APIVersions []string `json:"apiVersions,omitempty"`
	Resources   []string `json:"resources,omitempty"`
	Scope       string   `json:"scope,omitempty"`
}

// CRDSubject is the Tier-1 snapshot for a CustomResourceDefinition.
type CRDSubject struct {
	Group      string   `json:"group"`
	Versions   []string `json:"versions,omitempty"`
	Scope      string   `json:"scope,omitempty"`
	Names      CRDNames `json:"names"`
	Categories []string `json:"categories,omitempty"`
	Conversion string   `json:"conversion,omitempty"`
}

// CRDNames is the slim CRD names tuple.
type CRDNames struct {
	Plural     string   `json:"plural"`
	Singular   string   `json:"singular,omitempty"`
	Kind       string   `json:"kind"`
	ListKind   string   `json:"listKind,omitempty"`
	ShortNames []string `json:"shortNames,omitempty"`
}

// APIServiceSubject is the Tier-1 snapshot for an APIService.
type APIServiceSubject struct {
	Group                 string      `json:"group"`
	Version               string      `json:"version"`
	Service               *ServiceRef `json:"service,omitempty"`
	InsecureSkipTLSVerify bool        `json:"insecureSkipTLSVerify,omitempty"`
	GroupPriorityMinimum  int32       `json:"groupPriorityMinimum,omitempty"`
	VersionPriority       int32       `json:"versionPriority,omitempty"`
	Available             bool        `json:"available,omitempty"`
}

// CSRSubject is the Tier-1 snapshot for a CertificateSigningRequest.
type CSRSubject struct {
	SignerName        string   `json:"signerName"`
	Username          string   `json:"username,omitempty"`
	Groups            []string `json:"groups,omitempty"`
	UIDs              []string `json:"uids,omitempty"`
	Conditions        []string `json:"conditions,omitempty"`
	ExpirationSeconds *int32   `json:"expirationSeconds,omitempty"`
}

// ClusterSubject is a synthetic subject for cluster-scoped facts.
type ClusterSubject struct {
	ClusterID         string `json:"clusterID,omitempty"`
	ClusterName       string `json:"clusterName,omitempty"`
	KubernetesVersion string `json:"kubernetesVersion,omitempty"`
	DistroProvider    string `json:"distroProvider,omitempty"`
}

// ExternalSubject represents a subject outside the cluster.
// ExternalSubject.Kind values: ExternalUser | ExternalIP | ExternalEndpoint | Group.
type ExternalSubject struct {
	Kind     string `json:"kind"`
	Identity string `json:"identity"`
	Source   string `json:"source,omitempty"`
}
