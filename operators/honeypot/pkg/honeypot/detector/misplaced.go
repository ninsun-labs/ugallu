// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package detector

import (
	"encoding/json"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"

	"github.com/ninsun-labs/ugallu/operators/honeypot/pkg/honeypot/index"
)

// HoneypotMisplacedDetector flags Pod create requests whose spec
// references a decoy resource via volumes, envFrom, or
// serviceAccountName. A legitimate workload never mounts a decoy —
// firing here means someone authored a Pod template that thinks
// the decoy is real (intent reconnaissance) or is actively trying
// to exfiltrate decoy data into a process they control.
type HoneypotMisplacedDetector struct {
	idx *index.Index
}

// NewHoneypotMisplacedDetector returns a ready detector.
func NewHoneypotMisplacedDetector(idx *index.Index) *HoneypotMisplacedDetector {
	return &HoneypotMisplacedDetector{idx: idx}
}

// Name returns the detector name.
func (d *HoneypotMisplacedDetector) Name() string { return "honeypot_misplaced" }

// Evaluate parses the Pod RequestObject for references to decoy
// resources in the Pod's namespace.
func (d *HoneypotMisplacedDetector) Evaluate(in *AuditInput) *Finding {
	if in == nil || d.idx == nil {
		return nil
	}
	if in.ObjectResource != "pods" || in.Verb != "create" {
		return nil
	}
	if in.ObjectNamespace == "" || len(in.RequestObject) == 0 {
		return nil
	}

	refs := extractDecoyRefs(in.RequestObject, in.ObjectNamespace, d.idx)
	if len(refs) == 0 {
		return nil
	}

	first := refs[0]
	return &Finding{
		Type:     securityv1alpha1.TypeHoneypotMisplaced,
		Severity: Severity(securityv1alpha1.TypeHoneypotMisplaced),
		Subject: Subject{
			Kind:      "Pod",
			Name:      in.ObjectName,
			Namespace: in.ObjectNamespace,
			UID:       in.ObjectUID,
		},
		Signals: map[string]string{
			"actor.username":  in.UserUsername,
			"pod.namespace":   in.ObjectNamespace,
			"pod.name":        in.ObjectName,
			"decoy.resource":  first.Resource,
			"decoy.name":      first.Name,
			"reference.path":  first.Path,
			"honeypot.config": first.HoneypotConfig,
		},
	}
}

type decoyRef struct {
	Resource       string
	Name           string
	Path           string
	HoneypotConfig string
}

// extractDecoyRefs walks the Pod spec for references to decoy
// resources in the Pod's namespace. Three reference kinds covered
// in v1alpha1: volumes[*].secret.secretName, container[*].envFrom
// (secretRef + configMapRef), serviceAccountName.
func extractDecoyRefs(body []byte, podNS string, idx *index.Index) []decoyRef {
	var pod struct {
		Spec struct {
			ServiceAccountName string `json:"serviceAccountName,omitempty"`
			Volumes            []struct {
				Name   string `json:"name"`
				Secret *struct {
					SecretName string `json:"secretName"`
				} `json:"secret,omitempty"`
			} `json:"volumes,omitempty"`
			Containers []struct {
				EnvFrom []struct {
					SecretRef *struct {
						Name string `json:"name"`
					} `json:"secretRef,omitempty"`
				} `json:"envFrom,omitempty"`
			} `json:"containers,omitempty"`
		} `json:"spec"`
	}
	if err := json.Unmarshal(body, &pod); err != nil {
		return nil
	}
	out := []decoyRef{}

	if sa := pod.Spec.ServiceAccountName; sa != "" {
		if e := idx.Lookup("serviceaccounts", podNS, sa); e != nil {
			out = append(out, decoyRef{Resource: "serviceaccounts", Name: sa, Path: "spec.serviceAccountName", HoneypotConfig: e.HoneypotConfig})
		}
	}
	for _, v := range pod.Spec.Volumes {
		if v.Secret == nil || v.Secret.SecretName == "" {
			continue
		}
		if e := idx.Lookup("secrets", podNS, v.Secret.SecretName); e != nil {
			out = append(out, decoyRef{Resource: "secrets", Name: v.Secret.SecretName, Path: "spec.volumes[" + v.Name + "].secret.secretName", HoneypotConfig: e.HoneypotConfig})
		}
	}
	for _, c := range pod.Spec.Containers {
		for _, ef := range c.EnvFrom {
			if ef.SecretRef == nil || ef.SecretRef.Name == "" {
				continue
			}
			if e := idx.Lookup("secrets", podNS, ef.SecretRef.Name); e != nil {
				out = append(out, decoyRef{Resource: "secrets", Name: ef.SecretRef.Name, Path: "spec.containers[*].envFrom.secretRef.name", HoneypotConfig: e.HoneypotConfig})
			}
		}
	}
	return out
}
