# forensics

Forensics capture operator. Watches `SecurityEvent` CRs, evaluates the
[ForensicsConfig](../../sdk/pkg/api/v1alpha1/forensicsconfig_types.go)
trigger predicate, and runs an IR-as-code capture pipeline against
the suspect Pod when the predicate fires.

The operator is designed around a single invariant: every side
effect is an [EventResponse](../../sdk/pkg/api/v1alpha1/eventresponse_types.go)
CR that the attestor seals into an in-toto bundle. The pipeline
itself is the audit chain — there is no separate event log.

## Trigger predicate

`ForensicsConfig.spec.trigger` gates pipeline entry on:

- `classes` (default `[Detection, Anomaly]`)
- `minSeverities` (default `[high, critical]`)
- `whitelistedTypes` — explicit opt-in (e.g. `PrivilegedPodChange`,
  `ClusterAdminGranted`, `HostPathMount`, `ExecIntoPod`, …). An
  empty whitelist matches nothing.
- `requireAttested` — when true the SE must have
  `Status.Phase=Attested` (set by the attestor after
  `AttestationBundle` Sealed). Defends against unauthenticated SE
  forges that would otherwise drive a freeze.
- `namespaceAllowlist` — empty = match-all
- implicit: `Subject.Kind=Pod` (anything else is a `non_pod_subject` skip)

Misses bump `ugallu_forensics_skipped_total{reason}` so dashboards
show why an SE didn't trigger.

## Pipeline

Three steps, run sequentially per incident, each emitting its own
EventResponse for attestation:

1. **PodFreezeStep** — labels the suspect Pod with
   `ugallu.io/frozen=<incident-uid>` and applies a deny-all
   `CiliumNetworkPolicy` (Cilium clusters) or `NetworkPolicy`
   (vanilla CNI). Egress is widened to DNS (CoreDNS/RKE2-CoreDNS),
   the configured WORM endpoint, and the forensics workload
   namespace — without these the snapshot ephemeral container
   cannot resolve or upload.
2. **FilesystemSnapshotStep** — injects an ephemeral container
   (`ugallu-forensics-snapshot`) into the suspect Pod and tees the
   process's `/proc/<pid>/root` to S3 as a `tar+gzip+sha256`
   stream. Capability scope: `CAP_DAC_READ_SEARCH` only — enough
   to read arbitrary inode trees without root and small enough that
   `pod-security.kubernetes.io/enforce=baseline` accepts the
   ephemeral container only when the suspect's namespace is
   labelled `privileged` (this is intentional; baseline-only
   namespaces fall back to a pod-level memory-only capture in a
   later sprint).
3. **EvidenceUploadStep** — builds a content-addressed
   [Manifest](pkg/forensics/manifest.go) (sha256 over the canonical
   JSON), uploads it under
   `s3://<bucket>/forensics/<incident>/manifest-<sha>.json` with
   COMPLIANCE Object Lock, and references it from the
   `IncidentCaptureCompleted` SE as the sole evidence URL. Re-uploads
   of identical content are no-ops; divergent rewrites are rejected
   by Object Lock — that's the audit guarantee.

The freeze backend is detected once at startup (Cilium CRD probe);
the choice surfaces on `ForensicsConfig.status.freezeBackend`. The
detector refreshes every 10m so a CNI swap is reflected without a
restart.

Each step EventResponse carries:

- `app.kubernetes.io/managed-by=ugallu-forensics`
- `ugallu.io/incident-uid=<sha256(triggerSE.uid)[0:16]>`
- `ugallu.io/parent-er=<previous-step-er-name>` (chain back-link)
- `ugallu.io/step=<podfreeze|filesystem-snapshot|evidence-upload|podunfreeze>`

## Lifecycle

- **Manual ack**: an authorized SA stamps
  `ugallu.io/incident-acknowledged=true` on the
  `IncidentCaptureCompleted` SE. Admission policy 8
  (`forensicsAckAuthorizedSAs`) gates this annotation by SA. The
  controller observes the annotation flip and runs
  `PodUnfreezeStep`.
- **Auto-unfreeze** (optional): when `cleanup.autoUnfreezeAfter` is
  positive, the controller computes the deadline as
  `triggerSE.metadata.creationTimestamp + grace` and unfreezes
  when the wall clock crosses it. Durable by construction — the
  deadline lives on the SE, not in process memory, so a controller
  restart honours the grace.
- **Crash recovery**: at startup the operator lists ERs created by
  itself, reconstructs the incident state machine, and resumes per
  Action.Type:
  - `PodFreeze` / `PodUnfreeze`: idempotent re-apply (label + CNP
    are convergent)
  - `FilesystemSnapshot`: non-idempotent. If the ephemeral
    container is `Terminated`+success, salvage the logs and proceed.
    Otherwise mark the ER `Permanent` so it doesn't re-run a
    half-completed capture.
  - `EvidenceUpload`: rebuild the manifest deterministically, retry
    the upload (Object Lock makes the second write a no-op when
    content matches).

## Concurrency

`Pipeline` holds a semaphore (`MaxConcurrent`, default 5) and an
in-flight set keyed on incident UID. Re-emits of the same incident
return immediately as a no-op; a busy queue surfaces on
`ugallu_forensics_queue_size` so the SE reconciler can back off
with a `RequeueAfter` instead of looping.

## Telemetry

- `ugallu_forensics_incidents_total{outcome}`
- `ugallu_forensics_steps_total{step,outcome}`
- `ugallu_forensics_skipped_total{reason}`
- `ugallu_forensics_queue_size`
- `ugallu_forensics_cni_detect_failures_total`
- `ugallu_forensics_recovery_total{outcome}`
- `ugallu_forensics_auto_unfreeze_total{outcome}`

Surfaced as alerts + a Grafana dashboard by
[charts/ugallu/charts/monitoring](../../charts/ugallu/charts/monitoring).

## Snapshot binary

The [ugallu-forensics-snapshot](cmd/ugallu-forensics-snapshot)
binary ships in the same multi-binary image as the controller. It
is invoked only as the ephemeral container's argv — never reconciled
— so it has no client-go dependencies and the binary stays small.

## Deployment

Helm subchart at [charts/ugallu/charts/forensics](../../charts/ugallu/charts/forensics).
ApplicationSet wave `2`. Runs in `ugallu-system-privileged` because
the snapshot ephemeral container needs `CAP_DAC_READ_SEARCH` (and
optionally `CAP_SYS_PTRACE` once memory snapshots are turned on).

The umbrella's `worm.secret` Secret carries the WORM access-key /
secret-key — the operator reads them through env vars
(`WORM_ACCESS_KEY` / `WORM_SECRET_KEY`) so we don't grant a cluster-wide
Secret list/watch (controller-runtime's cache pre-loads everything
the manager has permission to see; we explicitly disable the cache
for `corev1.Secret` and resolve the master credentials with a one-shot
client at startup).

## Lab smokes

- [hack/forensics-smoke.sh](../../hack/forensics-smoke.sh) — ten
  scenarios covering predicate skip, freeze, per-step ER chain
  with `parent-er` labels, manifest content-addressing, manual
  ack, auto-unfreeze, and admission-policy 8 deny path.
- [hack/wave2-smoke.sh](../../hack/wave2-smoke.sh) end-to-end
  real-chain smoke that drives this operator from a real
  `audit-detection` emit through a real attestor seal into the
  pipeline, with no manual `Status.Phase=Attested` patch.
