# audit-detection

Audit-stream detection operator. Consumes the Kubernetes apiserver audit log,
evaluates user-supplied [SigmaRule](../../sdk/pkg/api/v1alpha1/sigmarule_types.go)
CRs against each event, and emits [SecurityEvent](../../sdk/pkg/api/v1alpha1/securityevent_types.go)
CRs of class `Detection` (or `Audit` for low-severity matches) via
the emitter SDK.

## Sources

Two interchangeable backends. Pick one at startup with `--source=`:

| Source    | Workload   | Audit-log path                                          |
|-----------|------------|---------------------------------------------------------|
| `file`    | DaemonSet  | `/host/var/log/audit/audit.log` (kubelet hostPath mount) |
| `webhook` | Deployment | apiserver `--audit-webhook-config-file` HTTPS POST       |

The webhook source authenticates the apiserver with a bearer token
(`AUDIT_WEBHOOK_TOKEN` env, or any name passed via `--webhook-secret-env`)
and optionally enforces mTLS (`--webhook-client-ca`). Both sources
emit `*auditdetection.AuditEvent` onto the same engine channel, so
the rule surface is source-agnostic.

## Sigma engine

`pkg/auditdetection/sigma` implements a deliberately small subset of
the Sigma matching language — the parts that matter against K8s
audit events:

- `objectRef` filters: `apiGroup`, `apiVersion`, `resource`,
  `subresource`, `namespace`, `name`
- `verb` / `stage` set membership
- `userGlob`, `nameGlob`, `namespaceGlob` glob lists
- `requestObjectGlob`: JSONPath into `request.requestObject` plus a
  glob list (supports `$.x.y[*].z`-style wildcard array steps)
- compositional `anyOf` / `not`

No event aggregation, no time windows. Per-rule rate limiting is
enforced by `golang.org/x/time/rate` (configurable `burst` +
`sustainedPerSec`). Matches that exceed the budget are dropped and
counted in `Status.DroppedRateLimit`.

The `SigmaRule` reconciler hot-swaps the in-memory `RuleSet` on
every CR write — counters (`MatchCount`, `DroppedRateLimit`,
`LastMatchedAt`) survive a re-compile so an edit does not erase
history; only the limiter is rebuilt with the new budget. Compile
errors land on `Status.ParseError` and disable the rule.

## SecurityEvent emission

The engine maps `objectRef.resource` onto `SecurityEvent.Subject.Kind`
via a small allowlist (`pods`, `nodes`, `secrets`, `clusterrolebindings`, …).
Unknown resources fall back to `External` so the SE remains valid
against the SubjectKind enum. The SE name is derived deterministically
from `(auditID, type, subjectUID)` so an apiserver replay re-emits
the same SE (idempotent Create returns AlreadyExists).

Every emit stamps the configured cluster identity
(`--cluster-id` / chart `clusterIdentity.clusterID`) so downstream
consumers (attestor, forensics) can partition WORM keys by cluster.

## Telemetry

Source-level:

- `ugallu_audit_file_lines_total`
- `ugallu_audit_file_parse_errors_total`
- `ugallu_audit_webhook_events_total`
- `ugallu_audit_webhook_parse_errors_total`
- `ugallu_audit_webhook_auth_failures_total`
- `ugallu_audit_webhook_backpressure_total`

Engine-level (per-rule):

- `ugallu_audit_rule_matches_total{rule}`
- `ugallu_audit_rule_dropped_total{rule}`
- `ugallu_audit_rule_emit_errors_total{rule}`
- `ugallu_audit_rule_compile_errors_total{rule}`

Surfaced as alerts + a Grafana dashboard by
[charts/ugallu/charts/monitoring](../../charts/ugallu/charts/monitoring).

## Deployment

Helm subchart at [charts/ugallu/charts/audit-detection](../../charts/ugallu/charts/audit-detection).
ApplicationSet wave `2`. The chart provisions:

- the apiserver audit-webhook bearer-token Secret + TLS Secret
- a `Service` (webhook source) or `DaemonSet`+hostPath (file source)
- an mTLS-only mode toggled by setting `webhook.sharedSecretRef` to empty

## Lab smoke

[hack/audit-detection-smoke.sh](../../hack/audit-detection-smoke.sh) —
seven end-to-end scenarios covering rule compile + bad-JSONPath
ParseError + matching emit + non-match negative + per-rule rate
limit + disable + delete. Posts payloads via an in-cluster
`alpine/curl` Job (the `--resolve` trick avoids round-tripping
through the host's WARP TLS-inspection proxy).

The end-to-end smoke at [hack/wave2-smoke.sh](../../hack/wave2-smoke.sh)
exercises this operator as the head of the
audit-detection → attestor → forensics chain.
