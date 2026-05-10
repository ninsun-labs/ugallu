// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package serverv1

import (
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
)

// SAUsernamePrefixes recognised by ResolveBySAUsername.
const (
	saUsernameSAPrefix   = "system:serviceaccount:"
	saUsernameNodePrefix = "system:node:"
	saUsernameSystem     = "system:"
)

// BuildPodSubject converts a corev1.Pod into a Tier-1 SubjectTier1
// snapshot. Phase 1 populates the high-value fields the Tier-1
// taxonomy mandates plus the slim container/volume info; the
// fine-grained PodSecurityContext, affinity, scheduling tunables, and
// per-probe details land in follow-up iterations as the operators
// start consuming them.
func BuildPodSubject(p *corev1.Pod) *securityv1alpha1.SubjectTier1 {
	if p == nil {
		return nil
	}
	return &securityv1alpha1.SubjectTier1{
		APIVersion:      "v1",
		Kind:            "Pod",
		Name:            p.Name,
		Namespace:       p.Namespace,
		UID:             p.UID,
		ResourceVersion: p.ResourceVersion,
		Labels:          copyStringMap(p.Labels),
		OwnerReferences: append([]metav1OwnerCopy{}, copyOwnerRefs(p.OwnerReferences)...),
		Pod: &securityv1alpha1.PodSubject{
			NodeName:                      p.Spec.NodeName,
			ServiceAccountName:            p.Spec.ServiceAccountName,
			HostNetwork:                   p.Spec.HostNetwork,
			HostPID:                       p.Spec.HostPID,
			HostIPC:                       p.Spec.HostIPC,
			AutomountServiceAccountToken:  p.Spec.AutomountServiceAccountToken,
			Containers:                    buildContainerInfos(p.Spec.Containers, p.Status.ContainerStatuses),
			InitContainers:                buildContainerInfos(p.Spec.InitContainers, p.Status.InitContainerStatuses),
			Volumes:                       buildVolumeInfos(p.Spec.Volumes),
			Phase:                         string(p.Status.Phase),
			QOSClass:                      string(p.Status.QOSClass),
			PriorityClassName:             p.Spec.PriorityClassName,
			Priority:                      p.Spec.Priority,
			RuntimeClassName:              ptrToString(p.Spec.RuntimeClassName),
			DNSPolicy:                     string(p.Spec.DNSPolicy),
			Hostname:                      p.Spec.Hostname,
			Subdomain:                     p.Spec.Subdomain,
			TerminationGracePeriodSeconds: p.Spec.TerminationGracePeriodSeconds,
		},
	}
}

// BuildSASubject converts a corev1.ServiceAccount into a Tier-1
// SubjectTier1 with the ServiceAccount discriminator populated.
func BuildSASubject(sa *corev1.ServiceAccount) *securityv1alpha1.SubjectTier1 {
	if sa == nil {
		return nil
	}
	pulls := make([]string, 0, len(sa.ImagePullSecrets))
	for _, ref := range sa.ImagePullSecrets {
		pulls = append(pulls, ref.Name)
	}
	secrets := make([]string, 0, len(sa.Secrets))
	for _, ref := range sa.Secrets {
		secrets = append(secrets, ref.Name)
	}
	return &securityv1alpha1.SubjectTier1{
		APIVersion:      "v1",
		Kind:            "ServiceAccount",
		Name:            sa.Name,
		Namespace:       sa.Namespace,
		UID:             sa.UID,
		ResourceVersion: sa.ResourceVersion,
		Labels:          copyStringMap(sa.Labels),
		ServiceAccount: &securityv1alpha1.ServiceAccountSubject{
			AutomountToken:   sa.AutomountServiceAccountToken,
			ImagePullSecrets: pulls,
			Secrets:          secrets,
		},
	}
}

// BuildNodeSubject converts a corev1.Node into a Tier-1 SubjectTier1.
func BuildNodeSubject(n *corev1.Node) *securityv1alpha1.SubjectTier1 {
	if n == nil {
		return nil
	}
	roles := make([]string, 0, 2)
	for k := range n.Labels {
		const rolePrefix = "node-role.kubernetes.io/"
		if strings.HasPrefix(k, rolePrefix) {
			roles = append(roles, strings.TrimPrefix(k, rolePrefix))
		}
	}
	taints := make([]string, 0, len(n.Spec.Taints))
	for _, t := range n.Spec.Taints {
		taints = append(taints, t.Key+"="+t.Value+":"+string(t.Effect))
	}
	conds := make([]string, 0, len(n.Status.Conditions))
	for _, c := range n.Status.Conditions {
		if c.Status == corev1.ConditionTrue {
			conds = append(conds, string(c.Type))
		}
	}
	internalIP := ""
	hostname := ""
	for _, addr := range n.Status.Addresses {
		switch addr.Type {
		case corev1.NodeInternalIP:
			internalIP = addr.Address
		case corev1.NodeHostName:
			hostname = addr.Address
		}
	}
	return &securityv1alpha1.SubjectTier1{
		APIVersion:      "v1",
		Kind:            "Node",
		Name:            n.Name,
		UID:             n.UID,
		ResourceVersion: n.ResourceVersion,
		Labels:          copyStringMap(n.Labels),
		Node: &securityv1alpha1.NodeSubject{
			Roles:            roles,
			KernelVersion:    n.Status.NodeInfo.KernelVersion,
			OSImage:          n.Status.NodeInfo.OSImage,
			KubeletVersion:   n.Status.NodeInfo.KubeletVersion,
			ContainerRuntime: n.Status.NodeInfo.ContainerRuntimeVersion,
			Architecture:     n.Status.NodeInfo.Architecture,
			OperatingSystem:  n.Status.NodeInfo.OperatingSystem,
			Taints:           taints,
			Conditions:       conds,
			Capacity:         n.Status.Capacity,
			Allocatable:      n.Status.Allocatable,
			InternalIP:       internalIP,
			Hostname:         hostname,
		},
	}
}

// BuildExternalSubject is the catch-all for non-K8s identities
// (system:* outside the SA/Node families, OIDC users, cert-based
// users, anonymous, etc.). source describes how the identity was
// observed so callers can correlate against the original event.
func BuildExternalSubject(kind, identity, source string) *securityv1alpha1.SubjectTier1 {
	return &securityv1alpha1.SubjectTier1{
		APIVersion: "v1",
		Kind:       "External",
		Name:       identity,
		External: &securityv1alpha1.ExternalSubject{
			Kind:     kind,
			Identity: identity,
			Source:   source,
		},
	}
}

// SAUsernameLookup is what ResolveBySAUsername returns.
type SAUsernameLookup struct {
	// Subject is the resolved Tier-1 subject. nil only when the
	// underlying lister returned an unrecoverable error.
	Subject *securityv1alpha1.SubjectTier1

	// Partial is true when intelligent parsing succeeded but the
	// underlying object was not findable in the cache (e.g. the SA
	// was already deleted). The Subject still carries the parsed
	// identity so consumers can emit a degraded SE.
	Partial bool
}

// ResolveSAUsername parses a Kubernetes auth username and returns
// the matching subject.
//
//   - "system:serviceaccount:<ns>:<name>" -> SA lookup via lister
//   - "system:node:<name>"                -> Node lookup via lister
//   - other "system:*"                    -> ExternalSubject{kind=SystemUser}
//   - everything else                     -> ExternalSubject{kind=ExternalUser}
//
// Lookup failures still produce a Subject (Partial=true) so the
// caller can emit a degraded SE rather than block.
func ResolveSAUsername(c *Cache, username string) SAUsernameLookup {
	switch {
	case strings.HasPrefix(username, saUsernameSAPrefix):
		rest := strings.TrimPrefix(username, saUsernameSAPrefix)
		ns, name, ok := strings.Cut(rest, ":")
		if !ok || ns == "" || name == "" {
			return SAUsernameLookup{
				Subject: BuildExternalSubject("SystemUser", username, "audit"),
				Partial: true,
			}
		}
		if c == nil || c.SaLister == nil {
			return SAUsernameLookup{
				Subject: makePartialSASubject(ns, name),
				Partial: true,
			}
		}
		sa, err := c.SaLister.ServiceAccounts(ns).Get(name)
		if err != nil {
			if apierrors.IsNotFound(err) {
				return SAUsernameLookup{
					Subject: makePartialSASubject(ns, name),
					Partial: true,
				}
			}
			return SAUsernameLookup{Subject: nil, Partial: true}
		}
		return SAUsernameLookup{Subject: BuildSASubject(sa)}

	case strings.HasPrefix(username, saUsernameNodePrefix):
		name := strings.TrimPrefix(username, saUsernameNodePrefix)
		if c == nil || c.NodeLister == nil || name == "" {
			return SAUsernameLookup{
				Subject: makePartialNodeSubject(name),
				Partial: true,
			}
		}
		n, err := c.NodeLister.Get(name)
		if err != nil {
			if apierrors.IsNotFound(err) {
				return SAUsernameLookup{
					Subject: makePartialNodeSubject(name),
					Partial: true,
				}
			}
			return SAUsernameLookup{Subject: nil, Partial: true}
		}
		return SAUsernameLookup{Subject: BuildNodeSubject(n)}

	case strings.HasPrefix(username, saUsernameSystem):
		return SAUsernameLookup{
			Subject: BuildExternalSubject("SystemUser", username, "audit"),
		}

	default:
		return SAUsernameLookup{
			Subject: BuildExternalSubject("ExternalUser", username, "audit"),
		}
	}
}

// makePartialSASubject builds a minimal SA subject when the lister
// has no entry (e.g. the SA was already deleted before the event was
// observed). Identity fields are populated from the parsed username.
func makePartialSASubject(ns, name string) *securityv1alpha1.SubjectTier1 {
	return &securityv1alpha1.SubjectTier1{
		APIVersion:     "v1",
		Kind:           "ServiceAccount",
		Name:           name,
		Namespace:      ns,
		ServiceAccount: &securityv1alpha1.ServiceAccountSubject{},
		Partial:        true,
	}
}

// makePartialNodeSubject builds a minimal Node subject when the
// lister has no entry.
func makePartialNodeSubject(name string) *securityv1alpha1.SubjectTier1 {
	return &securityv1alpha1.SubjectTier1{
		APIVersion: "v1",
		Kind:       "Node",
		Name:       name,
		Node:       &securityv1alpha1.NodeSubject{},
		Partial:    true,
	}
}

// --- helpers --------------------------------------------------------

// metav1OwnerCopy aliases metav1.OwnerReference to keep the import
// surface small (subjects.go already pulls in apimachinery/v1).
type metav1OwnerCopy = metav1OwnerReference
