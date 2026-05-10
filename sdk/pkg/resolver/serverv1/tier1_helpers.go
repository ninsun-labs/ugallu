// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package serverv1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
)

// metav1OwnerReference is a local alias so tier1.go's signatures
// don't need to import metav1 (kept for readability).
type metav1OwnerReference = metav1.OwnerReference

func copyOwnerRefs(in []metav1.OwnerReference) []metav1.OwnerReference {
	if len(in) == 0 {
		return nil
	}
	out := make([]metav1.OwnerReference, len(in))
	copy(out, in)
	return out
}

func copyStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func buildContainerInfos(specs []corev1.Container, statuses []corev1.ContainerStatus) []securityv1alpha1.ContainerInfo {
	if len(specs) == 0 {
		return nil
	}
	statusByName := make(map[string]string, len(statuses))
	for i := range statuses {
		statusByName[statuses[i].Name] = statuses[i].ImageID
	}
	out := make([]securityv1alpha1.ContainerInfo, 0, len(specs))
	for i := range specs {
		c := &specs[i]
		info := securityv1alpha1.ContainerInfo{
			Name:            c.Name,
			Image:           c.Image,
			ImagePullPolicy: string(c.ImagePullPolicy),
			VolumeMounts:    buildVolumeMounts(c.VolumeMounts),
			EnvNames:        envNames(c.Env),
			EnvFrom:         envFromRefs(c.EnvFrom),
			Ports:           containerPorts(c.Ports),
			WorkingDir:      c.WorkingDir,
			Stdin:           c.Stdin,
			TTY:             c.TTY,
		}
		if id, ok := statusByName[c.Name]; ok {
			info.ImageDigest = id
		}
		if c.Resources.Limits != nil || c.Resources.Requests != nil {
			info.Resources = c.Resources.DeepCopy()
		}
		if c.SecurityContext != nil {
			info.SecurityContext = buildContainerSecCtx(c.SecurityContext)
		}
		out = append(out, info)
	}
	return out
}

func buildVolumeMounts(in []corev1.VolumeMount) []securityv1alpha1.VolumeMount {
	if len(in) == 0 {
		return nil
	}
	out := make([]securityv1alpha1.VolumeMount, 0, len(in))
	for _, m := range in {
		mp := ""
		if m.MountPropagation != nil {
			mp = string(*m.MountPropagation)
		}
		out = append(out, securityv1alpha1.VolumeMount{
			Name:             m.Name,
			MountPath:        m.MountPath,
			ReadOnly:         m.ReadOnly,
			SubPath:          m.SubPath,
			MountPropagation: mp,
		})
	}
	return out
}

func envNames(in []corev1.EnvVar) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	for _, e := range in {
		out = append(out, e.Name)
	}
	return out
}

func envFromRefs(in []corev1.EnvFromSource) []securityv1alpha1.EnvFromRef {
	if len(in) == 0 {
		return nil
	}
	out := make([]securityv1alpha1.EnvFromRef, 0, len(in))
	for _, e := range in {
		ref := securityv1alpha1.EnvFromRef{Prefix: e.Prefix}
		if e.ConfigMapRef != nil {
			ref.ConfigMapRefName = e.ConfigMapRef.Name
			if e.ConfigMapRef.Optional != nil {
				v := *e.ConfigMapRef.Optional
				ref.Optional = &v
			}
		}
		if e.SecretRef != nil {
			ref.SecretRefName = e.SecretRef.Name
			if e.SecretRef.Optional != nil {
				v := *e.SecretRef.Optional
				ref.Optional = &v
			}
		}
		out = append(out, ref)
	}
	return out
}

func containerPorts(in []corev1.ContainerPort) []securityv1alpha1.ContainerPort {
	if len(in) == 0 {
		return nil
	}
	out := make([]securityv1alpha1.ContainerPort, 0, len(in))
	for _, p := range in {
		out = append(out, securityv1alpha1.ContainerPort{
			Name:          p.Name,
			HostPort:      p.HostPort,
			ContainerPort: p.ContainerPort,
			Protocol:      string(p.Protocol),
			HostIP:        p.HostIP,
		})
	}
	return out
}

func buildContainerSecCtx(s *corev1.SecurityContext) *securityv1alpha1.ContainerSecCtx {
	if s == nil {
		return nil
	}
	out := &securityv1alpha1.ContainerSecCtx{
		RunAsUser:                s.RunAsUser,
		RunAsGroup:               s.RunAsGroup,
		RunAsNonRoot:             s.RunAsNonRoot,
		ReadOnlyRootFilesystem:   s.ReadOnlyRootFilesystem,
		AllowPrivilegeEscalation: s.AllowPrivilegeEscalation,
	}
	if s.Privileged != nil {
		out.Privileged = *s.Privileged
	}
	if s.Capabilities != nil {
		caps := *s.Capabilities
		out.Capabilities = &caps
	}
	if s.SeccompProfile != nil {
		out.SeccompProfile = &securityv1alpha1.SeccompProfile{
			Type:             string(s.SeccompProfile.Type),
			LocalhostProfile: ptrToString(s.SeccompProfile.LocalhostProfile),
		}
	}
	if s.AppArmorProfile != nil {
		out.AppArmorProfile = &securityv1alpha1.AppArmorProfile{
			Type:             string(s.AppArmorProfile.Type),
			LocalhostProfile: ptrToString(s.AppArmorProfile.LocalhostProfile),
		}
	}
	if s.SELinuxOptions != nil {
		out.SELinuxOptions = &securityv1alpha1.SELinuxOptions{
			User:  s.SELinuxOptions.User,
			Role:  s.SELinuxOptions.Role,
			Type:  s.SELinuxOptions.Type,
			Level: s.SELinuxOptions.Level,
		}
	}
	if s.ProcMount != nil {
		out.ProcMount = string(*s.ProcMount)
	}
	return out
}

func buildVolumeInfos(in []corev1.Volume) []securityv1alpha1.VolumeInfo {
	if len(in) == 0 {
		return nil
	}
	out := make([]securityv1alpha1.VolumeInfo, 0, len(in))
	for i := range in {
		v := &in[i]
		info := securityv1alpha1.VolumeInfo{Name: v.Name, Type: volumeKind(v)}
		if v.HostPath != nil {
			info.HostPath = v.HostPath.Path
			if v.HostPath.Type != nil {
				info.HostPathType = string(*v.HostPath.Type)
			}
		}
		out = append(out, info)
	}
	return out
}

// volumeKind identifies the volume source family. Order follows the
// security-audit priority: hostPath / projected / secret / configMap
// first, then PVC, then in-tree types.
func volumeKind(v *corev1.Volume) string {
	switch {
	case v.HostPath != nil:
		return "HostPath"
	case v.PersistentVolumeClaim != nil:
		return "PersistentVolumeClaim"
	case v.Secret != nil:
		return "Secret"
	case v.ConfigMap != nil:
		return "ConfigMap"
	case v.Projected != nil:
		return "Projected"
	case v.EmptyDir != nil:
		return "EmptyDir"
	case v.DownwardAPI != nil:
		return "DownwardAPI"
	case v.NFS != nil:
		return "NFS"
	case v.CSI != nil:
		return "CSI"
	}
	return "Other"
}

func ptrToString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
