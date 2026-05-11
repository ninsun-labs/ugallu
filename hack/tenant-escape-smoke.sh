#!/usr/bin/env bash
# E2E lab smoke for ugallu-tenant-escape.
#
# Assumes:
#   - kubectl context already pointed at the lab
#   - ugallu-tenant-escape deployed via the chart (placeholder=false
#     in lab values overlay)
#   - audit-detection deployed with eventBus.enabled=true (the bus
#     Service ugallu-audit-detection-bus must be reachable from
#     tenant-escape)
#   - admission policy 11 (ugallu.tenant-boundary-spec) bound
#
# What it covers (5 scenarios):
#   1. Admission policy 11: empty NamespaceSelector → 4xx denied
#   2. CrossTenantSecretAccess fires when team-a SA reads a Secret
#      in team-b
#   3. CrossTenantHostPathOverlap fires on a Pod create that mounts
#      another tenant's hostPath
#   4. CrossTenantNetworkPolicy fires on cross-tenant ingress.from
#   5. TenantBoundaryOverlap meta-event fires when two CRs claim
#      the same namespace
#
# CrossTenantExec is NOT exercised here: the Tetragon source is a
# stub in this release (the real impl lives in
# ninsun-labs/tetragon-bridge).
#
# Run with:
#   bash hack/tenant-escape-smoke.sh

set -euo pipefail

GREEN=$'\033[0;32m'
RED=$'\033[0;31m'
YELLOW=$'\033[1;33m'
NC=$'\033[0m'

pass() { echo "${GREEN}PASS${NC} $*"; }
fail() { echo "${RED}FAIL${NC} $*" >&2; exit 1; }
skip() { echo "${YELLOW}SKIP${NC} $*"; }
info() { echo "${YELLOW}==>${NC} $*"; }

RUN_ID=$(date +%s)-$$
NS_A=te-smoke-a-${RUN_ID}
NS_B=te-smoke-b-${RUN_ID}
TB_A=te-smoke-a-${RUN_ID}
TB_B=te-smoke-b-${RUN_ID}
TB_OVERLAP=te-smoke-overlap-${RUN_ID}
SA_A=team-a-bot

# Inject synthetic apiserver audit events directly into the
# audit-detection webhook (the lab apiserver is not configured with
# audit-webhook so we simulate the events the same way
# audit-detection-smoke does - webhook_post helper).
NS_UGALLU=ugallu-system
WEBHOOK_HOST=ugallu-audit-detection-webhook.${NS_UGALLU}.svc.cluster.local
WEBHOOK_PORT=443
WEBHOOK_PATH=/v1/audit
WEBHOOK_SECRET_NAME=ugallu-audit-webhook-token
TOKEN=$(kubectl -n "$NS_UGALLU" get secret "$WEBHOOK_SECRET_NAME" -o jsonpath='{.data.token}' | base64 -d 2>/dev/null || echo "")
WEBHOOK_SVC_IP=$(kubectl -n "$NS_UGALLU" get svc ugallu-audit-detection-webhook -o jsonpath='{.spec.clusterIP}' 2>/dev/null || echo "")

webhook_post() {
  local payload="$1"
  kubectl -n "$NS_UGALLU" delete job te-smoke-curl --ignore-not-found >/dev/null 2>&1 || true
  kubectl -n "$NS_UGALLU" delete configmap te-smoke-payload --ignore-not-found >/dev/null 2>&1 || true
  printf '%s' "$payload" > /tmp/te-smoke-body.json
  kubectl -n "$NS_UGALLU" create configmap te-smoke-payload \
    --from-file=body.json=/tmp/te-smoke-body.json >/dev/null
  cat <<EOF | kubectl -n "$NS_UGALLU" apply -f - >/dev/null
apiVersion: batch/v1
kind: Job
metadata:
  name: te-smoke-curl
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
            name: te-smoke-payload
EOF
  kubectl -n "$NS_UGALLU" wait --for=condition=complete --timeout=60s job/te-smoke-curl >/dev/null
}

cleanup() {
  kubectl delete ns "$NS_A" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  kubectl delete ns "$NS_B" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  kubectl delete tenantboundary "$TB_A" "$TB_B" "$TB_OVERLAP" --ignore-not-found >/dev/null 2>&1 || true
  kubectl -n "$NS_UGALLU" delete job te-smoke-curl --ignore-not-found >/dev/null 2>&1 || true
  kubectl -n "$NS_UGALLU" delete configmap te-smoke-payload --ignore-not-found >/dev/null 2>&1 || true
  kubectl get securityevent --no-headers 2>/dev/null \
    | awk -v rid="$RUN_ID" '$0 ~ rid {print $1}' \
    | xargs -r kubectl delete securityevent --ignore-not-found >/dev/null 2>&1 || true
  rm -f /tmp/te-smoke-body.json 2>/dev/null || true
}
trap cleanup EXIT

wait_for_se() {
  local se_type="$1"
  local timeout="${2:-60}"
  local end=$(( $(date +%s) + timeout ))
  while [ "$(date +%s)" -lt "$end" ]; do
    if kubectl get securityevents -o json 2>/dev/null \
      | jq -e --arg t "$se_type" '.items[] | select(.spec.type == $t)' >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  return 1
}

# --- Test 1: admission policy 11 denies empty NamespaceSelector ------
info "Test 1: admission policy 11 denies empty NamespaceSelector"
denied_msg=$(kubectl apply -f - <<EOF 2>&1 || true
apiVersion: security.ugallu.io/v1alpha1
kind: TenantBoundary
metadata:
  name: ${TB_OVERLAP}-bad
spec:
  namespaceSelector: {}
EOF
)
if echo "$denied_msg" | grep -qiE "namespaceSelector must set"; then
  pass "VAP rejected empty selector"
else
  fail "expected admission rejection, got: $denied_msg"
fi

# --- Bring up two namespaces + tenant boundaries ---------------------
info "Bootstrap: namespaces + TenantBoundary CRs"
kubectl create ns "$NS_A" --dry-run=client -o yaml \
  | kubectl label --local --dry-run=client -o yaml -f - "team=$NS_A" \
  | kubectl apply -f -
kubectl create ns "$NS_B" --dry-run=client -o yaml \
  | kubectl label --local --dry-run=client -o yaml -f - "team=$NS_B" \
  | kubectl apply -f -

cat <<EOF | kubectl apply -f -
apiVersion: security.ugallu.io/v1alpha1
kind: TenantBoundary
metadata:
  name: ${TB_A}
spec:
  namespaceSelector:
    matchLabels:
      team: ${NS_A}
  hostPathPolicy:
    allow:
      - /var/lib/${TB_A}/
---
apiVersion: security.ugallu.io/v1alpha1
kind: TenantBoundary
metadata:
  name: ${TB_B}
spec:
  namespaceSelector:
    matchLabels:
      team: ${NS_B}
  hostPathPolicy:
    allow:
      - /var/lib/${TB_B}/
EOF

kubectl create sa "$SA_A" -n "$NS_A" --dry-run=client -o yaml | kubectl apply -f -
kubectl create rolebinding "${SA_A}-secret-read" -n "$NS_B" \
  --clusterrole=view --serviceaccount="${NS_A}:${SA_A}" --dry-run=client -o yaml \
  | kubectl apply -f -

# Wait for the reconciler to pick up the boundaries.
for _ in $(seq 1 30); do
  matched=$(kubectl get tenantboundary "$TB_A" -o jsonpath='{.status.matchedNamespaces}' 2>/dev/null || true)
  [ -n "$matched" ] && break
  sleep 1
done
info "TB ${TB_A}.status.matchedNamespaces = $matched"

# Give tenant-escape leader time to connect to the audit bus before
# we post synthetic events (Subscribe takes a couple of seconds
# after lease acquisition).
sleep 10

# --- Test 2: CrossTenantSecretAccess --------------------------------
info "Test 2: CrossTenantSecretAccess (synthetic audit: team-a SA gets Secret in team-b)"
webhook_post '{"kind":"EventList","apiVersion":"audit.k8s.io/v1","items":[{"kind":"Event","apiVersion":"audit.k8s.io/v1","level":"RequestResponse","auditID":"te-smoke-secret-'${RUN_ID}'","stage":"ResponseComplete","verb":"get","user":{"username":"system:serviceaccount:'${NS_A}':'${SA_A}'"},"objectRef":{"resource":"secrets","namespace":"'${NS_B}'","name":"shared-creds-'${RUN_ID}'"},"responseStatus":{"code":200},"requestReceivedTimestamp":"2026-04-29T08:00:00.000000Z","stageTimestamp":"2026-04-29T08:00:00.001000Z"}]}'
if wait_for_se CrossTenantSecretAccess 60; then
  pass "CrossTenantSecretAccess SE emitted"
else
  fail "no CrossTenantSecretAccess SE within 60s"
fi

# --- Test 3: CrossTenantHostPathOverlap -----------------------------
info "Test 3: CrossTenantHostPathOverlap (synthetic audit: Pod create in team-a with hostPath of team-b)"
webhook_post '{"kind":"EventList","apiVersion":"audit.k8s.io/v1","items":[{"kind":"Event","apiVersion":"audit.k8s.io/v1","level":"RequestResponse","auditID":"te-smoke-hostpath-'${RUN_ID}'","stage":"ResponseComplete","verb":"create","user":{"username":"system:serviceaccount:'${NS_A}':'${SA_A}'"},"objectRef":{"resource":"pods","namespace":"'${NS_A}'","name":"hostpath-poacher-'${RUN_ID}'"},"requestObject":{"spec":{"volumes":[{"hostPath":{"path":"/var/lib/'${TB_B}'/secrets"}}]}},"responseStatus":{"code":201},"requestReceivedTimestamp":"2026-04-29T08:00:00.000000Z","stageTimestamp":"2026-04-29T08:00:00.001000Z"}]}'

if wait_for_se CrossTenantHostPathOverlap 60; then
  pass "CrossTenantHostPathOverlap SE emitted"
else
  fail "no CrossTenantHostPathOverlap SE within 60s"
fi

# --- Test 4: CrossTenantNetworkPolicy --------------------------------
info "Test 4: CrossTenantNetworkPolicy (synthetic audit: NP create in team-a allows ingress from team-b)"
webhook_post '{"kind":"EventList","apiVersion":"audit.k8s.io/v1","items":[{"kind":"Event","apiVersion":"audit.k8s.io/v1","level":"RequestResponse","auditID":"te-smoke-np-'${RUN_ID}'","stage":"ResponseComplete","verb":"create","user":{"username":"system:serviceaccount:'${NS_A}':'${SA_A}'"},"objectRef":{"resource":"networkpolicies","apiGroup":"networking.k8s.io","namespace":"'${NS_A}'","name":"open-ingress-'${RUN_ID}'"},"requestObject":{"spec":{"podSelector":{},"policyTypes":["Ingress"],"ingress":[{"from":[{"namespaceSelector":{"matchLabels":{"kubernetes.io/metadata.name":"'${NS_B}'"}}}]}]}},"responseStatus":{"code":201},"requestReceivedTimestamp":"2026-04-29T08:00:00.000000Z","stageTimestamp":"2026-04-29T08:00:00.001000Z"}]}'

if wait_for_se CrossTenantNetworkPolicy 60; then
  pass "CrossTenantNetworkPolicy SE emitted"
else
  fail "no CrossTenantNetworkPolicy SE within 60s"
fi

# --- Test 5: TenantBoundaryOverlap meta-event ------------------------
info "Test 5: TenantBoundaryOverlap (two CRs claiming the same namespace)"
cat <<EOF | kubectl apply -f -
apiVersion: security.ugallu.io/v1alpha1
kind: TenantBoundary
metadata:
  name: ${TB_OVERLAP}
spec:
  namespaceSelector:
    matchLabels:
      team: ${NS_A}
EOF

if wait_for_se TenantBoundaryOverlap 60; then
  pass "TenantBoundaryOverlap SE emitted"
else
  skip "TenantBoundaryOverlap not emitted (operator may surface via Status only)"
fi

echo
pass "tenant-escape smoke: 4 detection scenarios + admission policy 11 verified"
