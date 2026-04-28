# Wave 2 retrospective

This document captures what shipped in Wave 2, what was deliberately
deferred, and the known issues an operator should be aware of when
running the platform from the `wave2-final` tag.

## What shipped

### Detection — `audit-detection`

- Two interchangeable audit-event sources: file (DaemonSet, kubelet
  hostPath) and webhook (Deployment, apiserver audit-webhook
  backend). Webhook supports bearer-token auth, optional mTLS, and
  an mTLS-only mode.
- `SigmaRule` CRD with `SigmaMatch` / `SigmaMatchLeaf` split — a
  deliberate two-level structure that sidesteps the OpenAPI
  recursive-schema rejection while preserving the
  `anyOf` / `not` compositional semantics.
- Sigma engine subset: `objectRef`, `verb` / `stage`, `userGlob`,
  `nameGlob`, `requestObjectGlob` (JSONPath + glob list,
  array-wildcard supported), `anyOf` / `not`. No event aggregation
  and no time windows — that domain belongs to a future
  correlator.
- Per-rule `golang.org/x/time/rate` limiter, hot-swappable
  `RuleSet` (counters survive a recompile, limiter is rebuilt with
  the new budget), `Status.ParseError` on bad-JSONPath.
- SE emit via the SDK emitter with deterministic naming
  (`auditID + type + subjectUID`) so apiserver replays converge to
  the same SE.
- envtest integration suite + 7-scenario lab smoke
  ([hack/audit-detection-smoke.sh](../hack/audit-detection-smoke.sh)).

### Response — `forensics`

- `ForensicsConfig` CRD (singleton `default`, content-addressed
  trigger predicate). `Status` surfaces `FreezeBackend`,
  `LastConfigLoadAt`, `InFlightIncidents`.
- IR-as-code pipeline with three step types — `PodFreezeStep`,
  `FilesystemSnapshotStep`, `EvidenceUploadStep` — each emitting
  its own `EventResponse`. The audit chain is the EventResponse
  chain itself (`ugallu.io/parent-er` labels), not a parallel log.
- Cilium-vs-CoreV1 freeze backend, detected at startup with a
  10m-refreshed `CNIDetector`. Egress in the freeze policy is
  widened to DNS, the WORM endpoint and the forensics workload
  namespace — the snapshot ephemeral container needs all three.
- Filesystem snapshot via ephemeral container with
  `CAP_DAC_READ_SEARCH`. The `ugallu-forensics-snapshot` binary
  streams `tar+gzip+sha256` over a single S3 multipart upload.
- Content-addressed [`Manifest`](../operators/forensics/pkg/forensics/manifest.go)
  (sha256 over canonical JSON, sorted keys, no HTML escaping). The
  `IncidentCaptureCompleted` SE references the manifest as the sole
  evidence URL; per-chunk URLs live inside the manifest body
  itself, so re-uploads of identical content are no-ops and
  divergent rewrites are rejected by Object Lock.
- Crash recovery one-shot at startup: per-Action.Type idempotency
  classification, capped retry attempts (3), `Permanent` state for
  irrecoverable steps. Surfaces on
  `ugallu_forensics_recovery_total{outcome}`.
- Auto-unfreeze with a durable wall-clock deadline
  (`triggerSE.creationTimestamp + grace`); a controller restart
  honours the grace window.
- Manual unfreeze via `ugallu.io/incident-acknowledged=true`
  annotation, gated by admission policy 8 against the
  `forensicsAckAuthorizedSAs` allowlist.
- 10-scenario lab smoke
  ([hack/forensics-smoke.sh](../hack/forensics-smoke.sh)).

### Admission policies

- Policy 7 — `frozen-label-restricted`: only the forensics SA may
  remove the `ugallu.io/frozen` label from a Pod. CEL expression
  uses optional-index `?key.orValue('')` to stay legal when
  `metadata.labels` is unset on either side of the request.
- Policy 8 — `forensic-ack-restricted`: only allowlisted SAs may
  flip `ugallu.io/incident-acknowledged` to `true` on a Forensic SE.
  Allowlist is plumbed through chart values
  (`forensicsAckAuthorizedSAs`).

### Build, release, telemetry

- Per-binary OCI images on `wave*-final` / `v*` tags (and
  `workflow_dispatch`): build matrix → push to
  `ghcr.io/ninsun-labs/ugallu/<binary>:<tag>` → `cosign sign --keyless`
  via GitHub OIDC + Fulcio + Rekor → SBOM attestation → signature
  verify roundtrip. See
  [.github/workflows/release.yml](../.github/workflows/release.yml).
- OpenBao bootstrap helper for the production cosign signing key
  (separate from the attestor's transit key — different blast
  radius, rotation cadence, audit attribution). See
  [hack/openbao/cosign-key.sh](../hack/openbao/cosign-key.sh).
- Multi-binary lab image (`localhost/ugallu-runtime:dev`) for the
  ssh+ctr dev loop.
- `monitoring` subchart with a `PrometheusRule` carrying 12 alerts
  (5 audit-detection + 5 forensics + 2 emitter) and two Grafana
  dashboards loaded into ConfigMaps with `grafana_dashboard=1` for
  grafana-operator-style auto-discovery.

### Real-chain smoke

[hack/wave2-smoke.sh](../hack/wave2-smoke.sh) drives the full chain
end-to-end with no manual `Status.Phase=Attested` patch. Stages,
in order: audit event POST → SE create → AttestationBundle Sealed →
SE Phase=Attested → freeze → 3 ER chain Succeeded →
IncidentCaptureCompleted → authorized-SA ack → unfreeze. 180s
budget; rke2-lab runs land at ~45s.

## Deferred to Wave 3+

- **Memory snapshots.** Design supports `MemorySnapshot` as an
  Action.Type but the implementation is gated on a CRIU-compatible
  runtime + the right capabilities (`CAP_SYS_PTRACE`). Filesystem
  snapshots ship in Wave 2; the memory path lights up when the
  runtime story is settled.
- **Sigma rule aggregation / time windows.** The Wave 2 engine
  evaluates one event at a time. Multi-event detection
  (e.g. "5 failed auths from the same SA in 60s") is a Wave 3
  correlator that consumes Wave 2 SEs, not an extension to
  audit-detection.
- **Prometheus auto-bind.** The monitoring subchart applies
  unconditionally — when no kube-prometheus-stack is present the
  PrometheusRule is inert (no consumer) and the dashboard
  ConfigMaps just sit there. A future ServiceMonitor /
  PodMonitor pass adds the scrape side.
- **Webhook → SE backpressure.** The webhook source counts
  backpressure events on `ugallu_audit_webhook_backpressure_total`
  but currently still buffers. A bounded-queue + 429 path is a
  Wave 3 hardening.
- **EventResponse signing back-pressure.** Every step ER triggers
  an `AttestationBundle`. Under sustained incident load the
  attestor queue grows linearly with the number of steps. Wave 3
  considers either bundling step ERs into one envelope or
  back-pressuring the pipeline on `AttestationBundle` queue depth.

## Known issues

### SeaweedFS list-objects path doubling

The lab dev-stack runs SeaweedFS in S3-compatible mode. Some
versions of the gateway double a leading-slash prefix when
serving `ListObjectsV2` (`Prefix=foo/` returns keys reported as
`foo//bar`). It is purely a list-side artifact — `GetObject`,
`PutObject`, and `HeadObject` all use the original key — but
external auditor code that paginates listings should normalize
the result with `path.Clean`. AWS S3 and RustFS do not
exhibit it.

### Trillian tree loss on MySQL restart

The dev-stack's Trillian-MySQL has no persistent volume (it is a
dev stack — see [hack/dev-stack/README.md](../hack/dev-stack/README.md)).
A MySQL pod restart wipes the tree, but `rekor-config.treeID`
still references the old tree, and Rekor returns
`HTTP 500: unexpected result from transparency log` on every
Bundle seal. [hack/dev-stack/up.sh](../hack/dev-stack/up.sh)
detects this state by reading `trillian-log-signer`'s
"Acting as master for 0 / 0 active logs" line and re-runs
`createtree`. Production stacks should run Trillian against
durable MySQL.

### golangci-lint cache vs CI

`golangci-lint`'s cache survives across runs. When a local lint
config or linter version drifts from CI, an issue present on the
file the day you wrote it never resurfaces locally even after the
linter version bumps (see golangci/golangci-lint#5414). The
[hack/ci-local.sh](../hack/ci-local.sh) script burns the cache
once before the lint pass — costs ~30s of cold lint locally; CI
never sees it.

### Forensics ack annotation race window

Admission policy 8 only gates the annotation flip on UPDATE. If
two operators race to ack the same SE with different SAs, both
the controller-runtime cache and the apiserver may flap before
the policy converges on the allowed write. In practice the SA
allowlist is small (1–3 in production) and the window is sub-second;
the design accepts it because the unfreeze is idempotent — a
duplicate `PodUnfreeze` ER is a no-op.

### Snapshot ephemeral container transient `exit 1`

Observed once during Wave 2 final lab validation: the
`ugallu-forensics-snapshot` ephemeral container exited with status 1
(Reason `Error`) on a fresh suspect Pod, triggering an
`IncidentCaptureFailed` SE. A second incident in the same namespace
(same Pod spec, same image) on the same lab run completed in ~22s.
The snapshot binary's hard-fail paths are bucket / key / credential
validation and the upload itself, so the most likely cause is a
brief S3 PutObject hiccup during a re-frozen pod's egress
allowlist take-effect. The pipeline correctly classified it as
`Permanent` and emitted `IncidentCaptureFailed`.

Two follow-ups for Wave 3: (a) the snapshot binary should write a
`failure.detail` JSON line to stdout before exit so
`ugallu-forensics` can surface a richer reason in the SE
`signals.failure.message` (the current opaque "Error" leaks no
diagnosis); (b) `UnfreezeReconciler` watches `IncidentCaptureCompleted`
only — on `IncidentCaptureFailed` the pod stays frozen until
manual ack. Auto-unfreeze should also fire on `Failed` so a
failed capture does not strand the suspect.

### Subject mapping fallback to `External`

`audit-detection` maps `objectRef.resource` to `SubjectKind` via a
hand-curated allowlist. A resource not in the allowlist falls
back to `External` so the SE still validates. Forensics rejects
`External` subjects (`non_pod_subject` skip), so a forensics rule
silently won't fire against an unmapped subject kind. Adding a
new SubjectKind in the SDK requires a corresponding entry in
`engine.resourceToKind`.

## Versioning + tag

This Wave 2 close ships under the annotated tag `wave2-final`.
The CRD spine (`security.ugallu.io/v1alpha1`) remains pre-alpha;
breaking schema changes are expected before `v1alpha2`.
