// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package forensics

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"

	"github.com/ninsun-labs/ugallu/operators/forensics/pkg/snapshot"
)

// SnapshotResult mirrors the JSON the in-pod forensics-snapshot
// binary writes to stdout. The orchestrator unmarshals the
// container's logs into this shape before stamping the final SE
// evidence list. Re-exporting snapshot.Result keeps the operator
// API stable even if the binary's internals shift.
type SnapshotResult = snapshot.Result

// SnapshotterOptions configures a Snapshotter.
type SnapshotterOptions struct {
	// Client is the controller-runtime client for Pod reads.
	Client client.Client

	// Clientset is the typed clientset; needed for the
	// `/ephemeralcontainers` subresource (controller-runtime does
	// not expose it) and for streaming pod logs.
	Clientset kubernetes.Interface

	// Image is the multi-binary runtime image carrying
	// /bin/ugallu-forensics-snapshot.
	Image string

	// ImagePullPolicy follows the suspect Pod's policy by default;
	// the operator can override it (e.g. Never on the lab).
	ImagePullPolicy corev1.PullPolicy

	// WORMEndpoint is the S3 URL the snapshot binary streams to.
	WORMEndpoint string

	// WORMBucket is the destination bucket.
	WORMBucket string

	// WORMRegion is sent in the SDK headers; ignored by self-hosted
	// backends but required by aws-sdk-go-v2.
	WORMRegion string

	// WORMUsePathStyle forces path-style addressing (SeaweedFS / MinIO).
	WORMUsePathStyle bool

	// WORMSecretName is the Secret in the suspect Pod's namespace
	// that carries access-key + secret-key. The orchestrator copies
	// the master Secret over before injecting the ephemeral
	// container; see EnsureCredentials in pipeline.go.
	WORMSecretName string

	// LockMode + LockUntil set Object Lock retention. Defaults to
	// COMPLIANCE / 168h.
	LockMode  string
	LockUntil time.Duration

	// PollInterval is the cadence at which the operator polls the
	// suspect Pod for ephemeral-container status. Default 1s.
	PollInterval time.Duration
}

// Snapshotter drives the FilesystemSnapshot pipeline step. It
// patches the suspect Pod with an ephemeral container running the
// forensics-snapshot binary, polls until the container terminates,
// reads its logs, and parses the JSON Result.
type Snapshotter struct {
	opts SnapshotterOptions
}

// NewSnapshotter validates opts and returns a Snapshotter.
func NewSnapshotter(opts *SnapshotterOptions) (*Snapshotter, error) {
	if opts == nil || opts.Client == nil || opts.Clientset == nil {
		return nil, errors.New("snapshotter: Client + Clientset are required")
	}
	if opts.Image == "" {
		return nil, errors.New("snapshotter: Image is required")
	}
	if opts.WORMBucket == "" {
		return nil, errors.New("snapshotter: WORMBucket is required")
	}
	if opts.WORMSecretName == "" {
		opts.WORMSecretName = DefaultWORMSecretName
	}
	if opts.LockMode == "" {
		opts.LockMode = "COMPLIANCE"
	}
	if opts.LockUntil <= 0 {
		opts.LockUntil = 168 * time.Hour
	}
	if opts.PollInterval <= 0 {
		opts.PollInterval = time.Second
	}
	if opts.ImagePullPolicy == "" {
		opts.ImagePullPolicy = corev1.PullIfNotPresent
	}
	return &Snapshotter{opts: *opts}, nil
}

// Capture runs the full snapshot step against pod and returns the
// parsed Result (or an error). The function blocks until the
// ephemeral container terminates or ctx is cancelled.
func (s *Snapshotter) Capture(ctx context.Context, pod *corev1.Pod, incident *Incident, cfg *securityv1alpha1.SnapshotConfig) (*SnapshotResult, error) {
	if pod == nil || incident == nil || cfg == nil {
		return nil, errors.New("snapshotter: pod, incident and cfg are required")
	}
	containerName := snapshotContainerName(incident.UID)
	targetContainer := primaryContainerName(pod)
	if targetContainer == "" {
		return nil, errors.New("snapshotter: pod has no containers to target")
	}

	args := s.buildArgs(incident, pod, cfg)
	if err := s.injectEphemeralContainer(ctx, pod, containerName, targetContainer, args); err != nil {
		return nil, fmt.Errorf("inject ephemeral container: %w", err)
	}
	if err := s.waitForTermination(ctx, pod, containerName, time.Duration(cfg.TimeoutSeconds)*time.Second); err != nil {
		return nil, fmt.Errorf("wait for snapshot: %w", err)
	}
	logs, err := s.readContainerLogs(ctx, pod, containerName)
	if err != nil {
		return nil, fmt.Errorf("read snapshot logs: %w", err)
	}
	return parseSnapshotResult(logs)
}

// snapshotContainerName makes the ephemeral container name
// deterministic so a re-attempt produces the same target (the
// kubelet rejects duplicates with 409, which the orchestrator
// treats as success on idempotent retry).
func snapshotContainerName(incidentUID string) string {
	return "forensics-snapshot-" + sanitizeForK8sName(incidentUID)
}

// primaryContainerName picks the suspect container the snapshot
// targets. Default: the Pod's first container.
func primaryContainerName(pod *corev1.Pod) string {
	if len(pod.Spec.Containers) == 0 {
		return ""
	}
	return pod.Spec.Containers[0].Name
}

// buildArgs assembles the forensics-snapshot CLI flags from the
// active SnapshotConfig + Incident metadata.
func (s *Snapshotter) buildArgs(incident *Incident, pod *corev1.Pod, cfg *securityv1alpha1.SnapshotConfig) []string {
	args := []string{
		"--target-pid=1",
		"--worm-bucket=" + s.opts.WORMBucket,
		"--worm-key=" + buildSnapshotKey(incident, pod),
		"--lock-mode=" + s.opts.LockMode,
		"--lock-until=" + s.opts.LockUntil.String(),
	}
	if s.opts.WORMEndpoint != "" {
		args = append(args, "--worm-endpoint="+s.opts.WORMEndpoint)
	}
	if s.opts.WORMRegion != "" {
		args = append(args, "--worm-region="+s.opts.WORMRegion)
	}
	if s.opts.WORMUsePathStyle {
		args = append(args, "--worm-path-style=true")
	}
	for _, p := range cfg.FilesystemPaths {
		args = append(args, "--paths="+p)
	}
	for _, g := range cfg.ExcludePaths {
		args = append(args, "--exclude-glob="+g)
	}
	if cfg.TimeoutSeconds > 0 {
		args = append(args, fmt.Sprintf("--timeout=%ds", cfg.TimeoutSeconds))
	}
	if !cfg.MaxBytes.IsZero() {
		args = append(args, fmt.Sprintf("--max-bytes=%d", maxBytesValue(cfg.MaxBytes)))
	}
	return args
}

// injectEphemeralContainer patches the suspect Pod's
// `/ephemeralcontainers` subresource. The kubelet picks up the
// addition and starts the container in the Pod's network + PID
// namespace.
func (s *Snapshotter) injectEphemeralContainer(ctx context.Context, pod *corev1.Pod, name, targetContainer string, args []string) error {
	updated := pod.DeepCopy()
	updated.Spec.EphemeralContainers = append(updated.Spec.EphemeralContainers, corev1.EphemeralContainer{
		EphemeralContainerCommon: corev1.EphemeralContainerCommon{
			// Kubelet rejects Resources on ephemeral containers
			// (spec.ephemeralContainers[].resources: Forbidden) — the
			// kubelet allocates them off the Pod's existing budget.
			// Memory ceiling is enforced inside the snapshot binary
			// via the multipart-uploader part-size budget instead.
			Name:                     name,
			Image:                    s.opts.Image,
			ImagePullPolicy:          s.opts.ImagePullPolicy,
			Command:                  []string{"/bin/ugallu-forensics-snapshot"},
			Args:                     args,
			Env:                      s.envFromSecret(),
			SecurityContext:          snapshotSecurityContext(),
			TerminationMessagePolicy: corev1.TerminationMessageReadFile,
		},
		TargetContainerName: targetContainer,
	})

	if _, err := s.opts.Clientset.CoreV1().
		Pods(pod.Namespace).
		UpdateEphemeralContainers(ctx, pod.Name, updated, metav1.UpdateOptions{}); err != nil {
		if apierrors.IsAlreadyExists(err) || apierrors.IsConflict(err) {
			// Idempotent retry: the kubelet (or a concurrent
			// recovery pass) already injected this name.
			return nil
		}
		return err
	}
	return nil
}

// waitForTermination polls the Pod until the named ephemeral
// container reaches Terminated state or timeout fires. Returns the
// terminated state's exit code via err when non-zero.
func (s *Snapshotter) waitForTermination(ctx context.Context, pod *corev1.Pod, name string, timeout time.Duration) error {
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	pollCtx, cancel := context.WithTimeout(ctx, timeout+30*time.Second)
	defer cancel()

	return wait.PollUntilContextCancel(pollCtx, s.opts.PollInterval, true, func(ctx context.Context) (bool, error) {
		got := &corev1.Pod{}
		if err := s.opts.Client.Get(ctx, client.ObjectKeyFromObject(pod), got); err != nil {
			return false, nil
		}
		for i := range got.Status.EphemeralContainerStatuses {
			st := &got.Status.EphemeralContainerStatuses[i]
			if st.Name != name {
				continue
			}
			if st.State.Terminated != nil {
				if st.State.Terminated.ExitCode != 0 {
					return true, fmt.Errorf("snapshot exit %d: %s", st.State.Terminated.ExitCode, st.State.Terminated.Reason)
				}
				return true, nil
			}
		}
		return false, nil
	})
}

// readContainerLogs streams the ephemeral container's stdout into
// a single string; the JSON result is on the last non-empty line.
func (s *Snapshotter) readContainerLogs(ctx context.Context, pod *corev1.Pod, name string) (string, error) {
	req := s.opts.Clientset.CoreV1().Pods(pod.Namespace).GetLogs(pod.Name, &corev1.PodLogOptions{
		Container: name,
	})
	r, err := req.Stream(ctx)
	if err != nil {
		return "", err
	}
	defer func() { _ = r.Close() }()
	buf, err := io.ReadAll(r)
	if err != nil {
		return "", err
	}
	return string(buf), nil
}

// envFromSecret wires the WORM creds Secret as env into the
// ephemeral container.
func (s *Snapshotter) envFromSecret() []corev1.EnvVar {
	return []corev1.EnvVar{
		{
			Name: "WORM_ACCESS_KEY",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{Name: s.opts.WORMSecretName},
					Key:                  "access-key",
				},
			},
		},
		{
			Name: "WORM_SECRET_KEY",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{Name: s.opts.WORMSecretName},
					Key:                  "secret-key",
				},
			},
		},
	}
}

// snapshotSecurityContext drops every capability the binary doesn't
// need. The /proc/<pid>/root walk requires DAC_READ_SEARCH so the
// snapshot can read files owned by other UIDs without becoming
// fully root-equivalent.
func snapshotSecurityContext() *corev1.SecurityContext {
	allowEsc := false
	readOnlyRoot := true
	runAsNonRoot := false // /proc/<pid>/root reads must run as root inside the target's namespaces
	runAsUser := int64(0)
	return &corev1.SecurityContext{
		AllowPrivilegeEscalation: &allowEsc,
		ReadOnlyRootFilesystem:   &readOnlyRoot,
		RunAsNonRoot:             &runAsNonRoot,
		RunAsUser:                &runAsUser,
		Capabilities: &corev1.Capabilities{
			Add:  []corev1.Capability{"DAC_READ_SEARCH"},
			Drop: []corev1.Capability{"ALL"},
		},
		SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
	}
}

// parseSnapshotResult finds the JSON object in logs (last non-empty
// line) and decodes it into Result. When the binary aborted with
// EncodeFailure (the wrapper key `failure`), parseSnapshotResult
// returns a SnapshotFailureError that carries the (step, error,
// detail) tuple so the orchestrator can copy it into the
// IncidentCaptureFailed SE signals.
func parseSnapshotResult(logs string) (*SnapshotResult, error) {
	last := ""
	for _, line := range strings.Split(logs, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			last = line
		}
	}
	if last == "" {
		return nil, errors.New("snapshotter: empty container logs")
	}

	// Failure path first — discriminator is the `failure` top-level
	// key; the success path's Result has `url` etc.
	var fw struct {
		Failure *snapshot.Failure `json:"failure,omitempty"`
	}
	if err := json.Unmarshal([]byte(last), &fw); err == nil && fw.Failure != nil {
		return nil, &SnapshotFailureError{Failure: *fw.Failure}
	}

	var res SnapshotResult
	if err := json.Unmarshal([]byte(last), &res); err != nil {
		return nil, fmt.Errorf("decode result %q: %w", last, err)
	}
	return &res, nil
}

// SnapshotFailureError wraps a snapshot.Failure so the orchestrator
// can surface (step, error, detail) on the IncidentCaptureFailed
// SE. Use errors.As to extract.
type SnapshotFailureError struct {
	Failure snapshot.Failure
}

func (e *SnapshotFailureError) Error() string {
	if e.Failure.Detail != "" {
		return fmt.Sprintf("snapshot exit 1 (step=%s): %s", e.Failure.Step, e.Failure.Detail)
	}
	return fmt.Sprintf("snapshot exit 1 (step=%s): %s", e.Failure.Step, e.Failure.Error)
}

// buildSnapshotKey assembles the S3 object key. Layout
// `forensics/<incident-uid>/<pod-namespace>-<pod-name>.tar.gz`
// keeps cluster-wide listings sortable and human-readable.
func buildSnapshotKey(incident *Incident, pod *corev1.Pod) string {
	return fmt.Sprintf("forensics/%s/%s-%s.tar.gz",
		sanitizeForK8sName(incident.UID), pod.Namespace, pod.Name)
}

// sanitizeForK8sName trims to k8s name length + lowercases. Good
// enough for incident UIDs and Pod UIDs.
func sanitizeForK8sName(in string) string {
	out := strings.ToLower(in)
	if len(out) > 63 {
		out = out[:63]
	}
	return out
}

// maxBytesValue extracts the int64 byte count from a resource.Quantity
// without dragging in the pkg/api/resource alias.
func maxBytesValue(q resource.Quantity) int64 {
	v, _ := q.AsInt64()
	return v
}
