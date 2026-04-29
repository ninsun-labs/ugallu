// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package compliancescan

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/controller-runtime/pkg/client"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
)

// realKubeBenchScanner templates an upstream kube-bench Job per scan,
// waits for it to complete, and parses the JSON report. The Job runs
// privileged + hostPath-mounts the kubelet config bundle so it can
// fingerprint the actual cluster control plane.
//
// The image + Job namespace + RBAC are picked at construction time
// from the operator config. The result of one scan is the JSON
// report that kube-bench writes on stdout (--json flag).
type realKubeBenchScanner struct {
	client       client.Client
	jobNamespace string
	image        string
	timeout      time.Duration
}

// newRealKubeBenchScanner is the production builder.
func newRealKubeBenchScanner(c client.Client, ns, image string, timeout time.Duration) *realKubeBenchScanner {
	if image == "" {
		image = "docker.io/aquasec/kube-bench:v0.10.7"
	}
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	if ns == "" {
		ns = "ugallu-system-privileged"
	}
	return &realKubeBenchScanner{client: c, jobNamespace: ns, image: image, timeout: timeout}
}

func (s *realKubeBenchScanner) Scan(ctx context.Context, _ client.Client, spec *securityv1alpha1.ComplianceScanRunSpec) (*ScanOutcome, error) {
	jobName := fmt.Sprintf("ugallu-cs-kubebench-%d", time.Now().UnixNano())
	job := s.buildJob(jobName, spec.Profile)
	if err := s.client.Create(ctx, job); err != nil {
		return nil, fmt.Errorf("create kube-bench Job: %w", err)
	}
	defer func() { _ = s.client.Delete(context.Background(), job) }()

	// Wait for Job completion (success or failure).
	deadline := time.Now().Add(s.timeout)
	pollCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	if err := wait.PollUntilContextCancel(pollCtx, 5*time.Second, true, func(c context.Context) (bool, error) {
		var fresh batchv1.Job
		if err := s.client.Get(c, client.ObjectKey{Namespace: s.jobNamespace, Name: jobName}, &fresh); err != nil {
			return false, err
		}
		return fresh.Status.Succeeded > 0 || fresh.Status.Failed >= 1, nil
	}); err != nil {
		return nil, fmt.Errorf("wait kube-bench Job: %w", err)
	}

	// Pull the Pod log via the apiserver. The result is one JSON
	// document per checked control. Errors are surfaced as a single
	// non-fatal finding so ops sees that the run completed but the
	// report parser couldn't read it.
	report, err := s.fetchReport(ctx, jobName)
	if err != nil {
		return &ScanOutcome{
			Summary: map[string]int{"warn": 1},
			Checks: []securityv1alpha1.ComplianceCheckResult{{
				CheckID:  "ugallu.kube-bench.report-fetch-failed",
				Title:    "Could not fetch kube-bench JSON report",
				Outcome:  "warn",
				Severity: securityv1alpha1.SeverityMedium,
				Detail:   err.Error(),
			}},
		}, nil
	}
	return parseKubeBenchReport(report), nil
}

// buildJob renders the Job spec. Mounts are the standard kube-bench
// host-path set; pinned to runAsUser=0 because the upstream image
// reads files owned by root on the node (kubeconfig, etc.).
func (s *realKubeBenchScanner) buildJob(name, profile string) *batchv1.Job {
	hostPathDir := corev1.HostPathDirectory
	hostPathFile := corev1.HostPathFile
	args := []string{"--json"}
	if profile != "" {
		args = append(args, "--benchmark", profile)
	}
	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: s.jobNamespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":       "ugallu-kube-bench",
				"app.kubernetes.io/managed-by": "ugallu-compliance-scan",
			},
		},
		Spec: batchv1.JobSpec{
			BackoffLimit: ptrInt32(0),
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					RestartPolicy:      corev1.RestartPolicyNever,
					HostPID:            true,
					ServiceAccountName: "ugallu-compliance-scan",
					Containers: []corev1.Container{{
						Name:    "kube-bench",
						Image:   s.image,
						Command: []string{"kube-bench"},
						Args:    args,
						SecurityContext: &corev1.SecurityContext{
							RunAsUser: ptrInt64(0),
						},
						VolumeMounts: []corev1.VolumeMount{
							{Name: "var-lib-etcd", MountPath: "/var/lib/etcd", ReadOnly: true},
							{Name: "var-lib-kubelet", MountPath: "/var/lib/kubelet", ReadOnly: true},
							{Name: "etc-systemd", MountPath: "/etc/systemd", ReadOnly: true},
							{Name: "etc-kubernetes", MountPath: "/etc/kubernetes", ReadOnly: true},
							{Name: "usr-bin", MountPath: "/usr/local/mount-from-host/bin", ReadOnly: true},
						},
					}},
					Volumes: []corev1.Volume{
						{Name: "var-lib-etcd", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/lib/etcd", Type: &hostPathDir}}},
						{Name: "var-lib-kubelet", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/lib/kubelet", Type: &hostPathDir}}},
						{Name: "etc-systemd", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/etc/systemd", Type: &hostPathDir}}},
						{Name: "etc-kubernetes", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/etc/kubernetes", Type: &hostPathDir}}},
						{Name: "usr-bin", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/usr/bin/kubelet", Type: &hostPathFile}}},
					},
				},
			},
		},
	}
}

// fetchReport pulls the Pod log line-by-line. The controller-runtime
// client doesn't expose Pod log streaming, so the scanner looks up
// the Pod by job-name label and loads the latest log directly via
// a typed list. The kubectl-logs-equivalent over the apiserver REST
// log subresource is out of scope here — instead the scanner parses
// the Pod's terminated container exit message, which carries the
// last 80 KiB of the container's output.
func (s *realKubeBenchScanner) fetchReport(ctx context.Context, jobName string) (string, error) {
	var pods corev1.PodList
	if err := s.client.List(ctx, &pods,
		client.InNamespace(s.jobNamespace),
		client.MatchingLabels{"job-name": jobName},
	); err != nil {
		return "", err
	}
	if len(pods.Items) == 0 {
		return "", fmt.Errorf("no pods for job %s", jobName)
	}
	for i := range pods.Items {
		statuses := pods.Items[i].Status.ContainerStatuses
		for j := range statuses {
			cs := &statuses[j]
			if cs.LastTerminationState.Terminated != nil &&
				cs.LastTerminationState.Terminated.Message != "" {
				return cs.LastTerminationState.Terminated.Message, nil
			}
			if cs.State.Terminated != nil && cs.State.Terminated.Message != "" {
				return cs.State.Terminated.Message, nil
			}
		}
	}
	return "", fmt.Errorf("kube-bench pod did not surface a terminated.message; needs kubelet --pod-termination-message-policy=FallbackToLogsOnError on the node")
}

// kubeBenchReport mirrors the JSON shape kube-bench emits on stdout.
type kubeBenchReport struct {
	Controls []struct {
		Tests []struct {
			Results []struct {
				TestNumber string `json:"test_number"`
				TestDesc   string `json:"test_desc"`
				Status     string `json:"status"`
			} `json:"results"`
		} `json:"tests"`
		TotalPass int `json:"total_pass"`
		TotalFail int `json:"total_fail"`
		TotalWarn int `json:"total_warn"`
		TotalInfo int `json:"total_info"`
	} `json:"Controls"`
}

func parseKubeBenchReport(raw string) *ScanOutcome {
	var r kubeBenchReport
	if err := json.Unmarshal([]byte(raw), &r); err != nil {
		return &ScanOutcome{
			Summary: map[string]int{"warn": 1},
			Checks: []securityv1alpha1.ComplianceCheckResult{{
				CheckID:  "ugallu.kube-bench.report-parse-failed",
				Title:    "kube-bench JSON parse failed",
				Outcome:  "warn",
				Severity: securityv1alpha1.SeverityMedium,
				Detail:   fmt.Sprintf("decode: %v; raw head: %s", err, head(raw, 200)),
			}},
		}
	}
	out := &ScanOutcome{Summary: map[string]int{"pass": 0, "fail": 0, "warn": 0, "skip": 0}}
	for ci := range r.Controls {
		c := &r.Controls[ci]
		out.Summary["pass"] += c.TotalPass
		out.Summary["fail"] += c.TotalFail
		out.Summary["warn"] += c.TotalWarn
		out.Summary["skip"] += c.TotalInfo
		for ti := range c.Tests {
			for ri := range c.Tests[ti].Results {
				res := c.Tests[ti].Results[ri]
				outcome := strings.ToLower(res.Status)
				if outcome == "info" {
					outcome = "skip"
				}
				severity := securityv1alpha1.SeverityInfo
				switch outcome {
				case "fail":
					severity = securityv1alpha1.SeverityHigh
				case "warn":
					severity = securityv1alpha1.SeverityMedium
				}
				out.Checks = append(out.Checks, securityv1alpha1.ComplianceCheckResult{
					CheckID:  "cis." + res.TestNumber,
					Title:    res.TestDesc,
					Outcome:  outcome,
					Severity: severity,
				})
			}
		}
	}
	return out
}

func head(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func ptrInt32(v int32) *int32 { return &v }
func ptrInt64(v int64) *int64 { return &v }

// veroIsNotFound checks an apierrors helper without dragging the
// import locally; used by the close-out path.
//
//nolint:unused // reserved for the close-out path
func veroIsNotFound(err error) bool { return apierrors.IsNotFound(err) }
