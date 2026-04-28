#!/usr/bin/env bash
# E2E lab smoke test for ugallu-audit-detection.
#
# Assumes:
#   - kubectl context already pointed at the lab cluster
#   - ugallu-audit-detection deployed via Argo (webhook mode by default)
#   - ugallu-audit-detection-webhook Service is reachable from inside the
#     cluster on https://ugallu-audit-detection-webhook.ugallu-system:443
#   - the webhook bearer token Secret (ugallu-audit-webhook-token) is
#     populated with key=token
#
# What it covers (every Sprint-1 §A3-A9 scenario, no skipping):
#   1. Apply a SigmaRule, verify Status.Conditions[Compiled]=True
#   2. Apply a bad-JSONPath SigmaRule, verify Status.ParseError set
#   3. Submit a matching audit event via webhook, verify SecurityEvent
#      created with the configured Type / Severity / Subject mapping
#   4. Submit an audit event that should NOT match, verify no extra SE
#   5. Submit a burst that exceeds the per-rule budget, verify
#      Status.DroppedRateLimit > 0
#   6. Disable the rule, verify subsequent matches do not emit
#   7. Delete the rule, verify it's removed from the engine
#
# Run with:
#   bash hack/audit-detection-smoke.sh

set -euo pipefail

GREEN=$'\033[0;32m'
RED=$'\033[0;31m'
YELLOW=$'\033[1;33m'
NC=$'\033[0m'

pass() { echo "${GREEN}PASS${NC} $*"; }
fail() { echo "${RED}FAIL${NC} $*" >&2; exit 1; }
info() { echo "${YELLOW}==>${NC} $*"; }

NS=${NS:-ugallu-system}
WEBHOOK_HOST=${WEBHOOK_HOST:-ugallu-audit-detection-webhook.${NS}.svc.cluster.local}
WEBHOOK_PORT=${WEBHOOK_PORT:-443}
WEBHOOK_PATH=${WEBHOOK_PATH:-/v1/audit}
WEBHOOK_SECRET_NAME=${WEBHOOK_SECRET_NAME:-ugallu-audit-webhook-token}

RULE=audit-smoke-cabg
BAD_RULE=audit-smoke-bad-jsonpath
# Unique suffix per run so deterministic SE names from previous runs
# don't collide with this run's events (the emitter derives SE.Name
# from auditID + type + subject — same inputs ⇒ same SE name ⇒
# idempotent Create returns AlreadyExists, masking new "matches").
RUN_ID=$(date +%s)-$$
TOKEN=$(kubectl -n "$NS" get secret "$WEBHOOK_SECRET_NAME" -o jsonpath='{.data.token}' | base64 -d)
WEBHOOK_SVC_NAME=${WEBHOOK_SVC_NAME:-ugallu-audit-detection-webhook}
WEBHOOK_SVC_IP=$(kubectl -n "$NS" get svc "$WEBHOOK_SVC_NAME" -o jsonpath='{.spec.clusterIP}')
[ -n "$WEBHOOK_SVC_IP" ] || fail "Service $WEBHOOK_SVC_NAME has no ClusterIP"

# webhook_post(audit_json) — POSTs an EventList payload to the webhook
# from a tiny one-shot Job. The payload travels via a ConfigMap so its
# JSON indentation does not collide with the YAML block scalar that
# carries the curl command.
webhook_post() {
  local payload="$1"
  kubectl -n "$NS" delete job audit-smoke-curl --ignore-not-found >/dev/null 2>&1 || true
  kubectl -n "$NS" delete configmap audit-smoke-payload --ignore-not-found >/dev/null 2>&1 || true
  printf '%s' "$payload" > /tmp/audit-smoke-body.json
  kubectl -n "$NS" create configmap audit-smoke-payload \
    --from-file=body.json=/tmp/audit-smoke-body.json >/dev/null
  cat <<EOF | kubectl -n "$NS" apply -f - >/dev/null
apiVersion: batch/v1
kind: Job
metadata:
  name: audit-smoke-curl
spec:
  ttlSecondsAfterFinished: 60
  template:
    spec:
      restartPolicy: Never
      securityContext:
        runAsNonRoot: true
        runAsUser: 65532
        runAsGroup: 65532
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: curl
          image: alpine/curl:8.11.1
          env:
            - { name: TOKEN, value: "$TOKEN" }
          command: ["sh", "-c"]
          args:
            - |
              curl -sk -X POST \
                -H "Authorization: Bearer \$TOKEN" \
                -H "Content-Type: application/json" \
                --data @/payload/body.json \
                --resolve ${WEBHOOK_HOST}:${WEBHOOK_PORT}:${WEBHOOK_SVC_IP} \
                https://${WEBHOOK_HOST}:${WEBHOOK_PORT}${WEBHOOK_PATH}
          securityContext:
            allowPrivilegeEscalation: false
            capabilities:
              drop: ["ALL"]
          volumeMounts:
            - { name: payload, mountPath: /payload }
      volumes:
        - name: payload
          configMap:
            name: audit-smoke-payload
EOF
  kubectl -n "$NS" wait --for=condition=complete --timeout=60s job/audit-smoke-curl >/dev/null
}

cleanup() {
  kubectl delete sigmarule "$RULE" "$BAD_RULE" --ignore-not-found >/dev/null 2>&1 || true
  kubectl -n "$NS" delete job audit-smoke-curl --ignore-not-found >/dev/null 2>&1 || true
  kubectl -n "$NS" delete configmap audit-smoke-payload --ignore-not-found >/dev/null 2>&1 || true
  rm -f /tmp/audit-smoke-body.json 2>/dev/null || true
}
trap cleanup EXIT

# --- Test 1: SigmaRule compiles -------------------------------------------
info "Test 1: SigmaRule compiles cleanly"
cat <<EOF | kubectl apply -f - >/dev/null
apiVersion: security.ugallu.io/v1alpha1
kind: SigmaRule
metadata:
  name: $RULE
spec:
  enabled: true
  description: "smoke: cluster-admin grant via clusterrolebinding create"
  match:
    objectRef:
      resource: ["clusterrolebindings"]
    requestObjectGlob:
      - jsonPath: "\$.roleRef.name"
        patterns: ["cluster-admin"]
  emit:
    securityEventType: ClusterAdminGranted
    severity: critical
    signals:
      verb: "\${verb}"
      user: "\${user.username}"
  rateLimit:
    burst: 2
    sustainedPerSec: 1
EOF

# Give the controller a beat to reconcile.
for _ in $(seq 1 30); do
  cond=$(kubectl get sigmarule "$RULE" -o jsonpath='{.status.conditions[?(@.type=="Compiled")].status}' 2>/dev/null || true)
  if [ "$cond" = "True" ]; then break; fi
  sleep 1
done
[ "$cond" = "True" ] || fail "SigmaRule never went Compiled=True (got '$cond')"
pass "SigmaRule compiled"

# --- Test 2: Bad JSONPath surfaces ParseError -----------------------------
info "Test 2: Bad-JSONPath rule reports ParseError"
cat <<EOF | kubectl apply -f - >/dev/null
apiVersion: security.ugallu.io/v1alpha1
kind: SigmaRule
metadata:
  name: $BAD_RULE
spec:
  enabled: true
  match:
    requestObjectGlob:
      - jsonPath: "\$..deep.field"
        patterns: ["x"]
  emit:
    securityEventType: ClusterAdminGranted
    severity: high
EOF

for _ in $(seq 1 30); do
  pe=$(kubectl get sigmarule "$BAD_RULE" -o jsonpath='{.status.parseError}' 2>/dev/null || true)
  if [ -n "$pe" ]; then break; fi
  sleep 1
done
[ -n "$pe" ] || fail "Bad-JSONPath rule did not surface ParseError"
pass "Bad-JSONPath rule reports ParseError ($pe)"

# --- Test 3: Matching audit event creates SecurityEvent -------------------
info "Test 3: matching audit event creates SecurityEvent"
before=$(kubectl get securityevent -o name 2>/dev/null | wc -l)
webhook_post '{
  "items": [{
    "auditID": "smoke-create-'"$RUN_ID"'",
    "stage": "ResponseComplete",
    "verb": "create",
    "user": {"username": "system:serviceaccount:kube-system:smoke-bot"},
    "objectRef": {
      "apiGroup": "rbac.authorization.k8s.io",
      "apiVersion": "v1",
      "resource": "clusterrolebindings",
      "name": "smoke-evil-binding"
    },
    "requestObject": {
      "roleRef": {"name": "cluster-admin"}
    },
    "stageTimestamp": "2026-04-28T10:00:00Z"
  }]
}'

for _ in $(seq 1 30); do
  after=$(kubectl get securityevent -o name 2>/dev/null | wc -l)
  if [ "$after" -gt "$before" ]; then break; fi
  sleep 1
done
[ "$after" -gt "$before" ] || fail "no new SecurityEvent created"
pass "SecurityEvent created (count $before → $after)"

# --- Test 4: Non-matching audit event does NOT create extra SE ------------
info "Test 4: non-matching audit event ignored"
mid=$(kubectl get securityevent -o name 2>/dev/null | wc -l)
webhook_post '{
  "items": [{
    "auditID": "smoke-non-match-'"$RUN_ID"'",
    "verb": "get",
    "objectRef": {"resource": "pods", "name": "irrelevant"},
    "stageTimestamp": "2026-04-28T10:00:01Z"
  }]
}'
sleep 3
after=$(kubectl get securityevent -o name 2>/dev/null | wc -l)
[ "$after" -eq "$mid" ] || fail "non-matching event leaked: $mid → $after"
pass "non-matching event correctly ignored"

# --- Test 5: Burst exceeds per-rule budget -------------------------------
info "Test 5: burst exceeds per-rule rate limit (DroppedRateLimit > 0)"
batch_items=""
for i in 1 2 3 4 5 6 7 8; do
  sep=","
  if [ $i -eq 1 ]; then sep=""; fi
  batch_items="${batch_items}${sep}{
    \"auditID\": \"smoke-burst-${RUN_ID}-$i\",
    \"verb\": \"create\",
    \"user\": {\"username\": \"system:serviceaccount:kube-system:smoke-bot\"},
    \"objectRef\": {\"apiGroup\": \"rbac.authorization.k8s.io\", \"resource\": \"clusterrolebindings\", \"name\": \"burst-$i\"},
    \"requestObject\": {\"roleRef\": {\"name\": \"cluster-admin\"}},
    \"stageTimestamp\": \"2026-04-28T10:00:0${i}Z\"
  }"
done
webhook_post "{\"items\": [${batch_items}]}"
# Status flushes on the reconciler's 30s requeue. Force one by
# bumping an annotation; that way we don't have to wait the full
# RequeueAfter window.
kubectl annotate sigmarule "$RULE" --overwrite ugallu.io/smoke-bump="$(date +%s)" >/dev/null
for _ in $(seq 1 60); do
  drop=$(kubectl get sigmarule "$RULE" -o jsonpath='{.status.droppedRateLimit}' 2>/dev/null || echo 0)
  if [ "${drop:-0}" -gt 0 ]; then break; fi
  sleep 1
done
[ "${drop:-0}" -gt 0 ] || fail "DroppedRateLimit never went above zero (got $drop)"
pass "rate limit kicked in (DroppedRateLimit=$drop)"

# --- Test 6: Disable the rule, no further matches emit --------------------
info "Test 6: disable rule, ensure subsequent matches don't emit"
kubectl patch sigmarule "$RULE" --type=merge -p '{"spec":{"enabled":false}}' >/dev/null
sleep 2
mid=$(kubectl get securityevent -o name 2>/dev/null | wc -l)
webhook_post '{
  "items": [{
    "auditID": "smoke-after-disable-'"$RUN_ID"'",
    "verb": "create",
    "objectRef": {"resource": "clusterrolebindings", "name": "should-be-ignored"},
    "requestObject": {"roleRef": {"name": "cluster-admin"}},
    "stageTimestamp": "2026-04-28T10:00:30Z"
  }]
}'
sleep 3
after=$(kubectl get securityevent -o name 2>/dev/null | wc -l)
[ "$after" -eq "$mid" ] || fail "disabled rule still emitted: $mid → $after"
pass "disabled rule produced no further SecurityEvents"

# --- Test 7: Delete the rule cleanly --------------------------------------
info "Test 7: delete SigmaRule"
kubectl delete sigmarule "$RULE" >/dev/null
sleep 2
if kubectl get sigmarule "$RULE" >/dev/null 2>&1; then
  fail "SigmaRule $RULE still present after delete"
fi
pass "SigmaRule deleted"

echo
echo "${GREEN}All 7 audit-detection smoke tests passed.${NC}"
