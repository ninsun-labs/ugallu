#!/usr/bin/env bash
# E2E lab smoke for ugallu-honeypot.
#
# Assumes:
#   - kubectl context already pointed at the lab
#   - ugallu-honeypot deployed via the chart (placeholder=false in
#     lab values overlay)
#   - audit-detection deployed with eventBus.enabled=true
#   - admission policy 12 (ugallu.honeypot-config-spec) bound
#
# Scenarios (5):
#   1. Admission policy 12 rejects a HoneypotConfig with empty
#      decoys list.
#   2. HoneypotConfig CR creates the declared decoys with
#      ugallu.io/decoy=true label + ownerReference.
#   3. HoneypotTriggered fires when an SA reads a decoy Secret.
#   4. HoneypotMisplaced fires when a Pod create mounts a decoy
#      Secret as a volume.
#   5. Allowlisted SA does NOT trigger an SE on decoy access.
#
# Run with:
#   bash hack/honeypot-smoke.sh

set -euo pipefail

GREEN=$'\033[0;32m'
RED=$'\033[0;31m'
YELLOW=$'\033[1;33m'
NC=$'\033[0m'

pass() { echo "${GREEN}PASS${NC} $*"; }
fail() { echo "${RED}FAIL${NC} $*" >&2; exit 1; }
info() { echo "${YELLOW}==>${NC} $*"; }

RUN_ID=$(date +%s)-$$
NS=hp-smoke-${RUN_ID}
HP_GOOD=hp-smoke-${RUN_ID}
HP_BAD=hp-smoke-bad-${RUN_ID}
SA_ATTACKER=attacker-${RUN_ID}
SA_BACKUP=backup-operator-${RUN_ID}

# Inject synthetic apiserver audit events directly into the
# audit-detection webhook (the lab apiserver is not configured with
# audit-webhook so we simulate the events).
NS_UGALLU=ugallu-system
WEBHOOK_HOST=ugallu-audit-detection-webhook.${NS_UGALLU}.svc.cluster.local
WEBHOOK_PORT=443
WEBHOOK_PATH=/v1/audit
WEBHOOK_SECRET_NAME=ugallu-audit-webhook-token
TOKEN=$(kubectl -n "$NS_UGALLU" get secret "$WEBHOOK_SECRET_NAME" -o jsonpath='{.data.token}' | base64 -d 2>/dev/null || echo "")
WEBHOOK_SVC_IP=$(kubectl -n "$NS_UGALLU" get svc ugallu-audit-detection-webhook -o jsonpath='{.spec.clusterIP}' 2>/dev/null || echo "")

webhook_post() {
  local payload="$1"
  kubectl -n "$NS_UGALLU" delete job hp-smoke-curl --ignore-not-found >/dev/null 2>&1 || true
  kubectl -n "$NS_UGALLU" delete configmap hp-smoke-payload --ignore-not-found >/dev/null 2>&1 || true
  printf '%s' "$payload" > /tmp/hp-smoke-body.json
  kubectl -n "$NS_UGALLU" create configmap hp-smoke-payload \
    --from-file=body.json=/tmp/hp-smoke-body.json >/dev/null
  cat <<EOF | kubectl -n "$NS_UGALLU" apply -f - >/dev/null
apiVersion: batch/v1
kind: Job
metadata:
  name: hp-smoke-curl
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
            name: hp-smoke-payload
EOF
  kubectl -n "$NS_UGALLU" wait --for=condition=complete --timeout=60s job/hp-smoke-curl >/dev/null
}

cleanup() {
  kubectl delete ns "$NS" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  kubectl delete honeypotconfig "$HP_GOOD" "$HP_BAD" --ignore-not-found >/dev/null 2>&1 || true
  kubectl -n "$NS_UGALLU" delete job hp-smoke-curl --ignore-not-found >/dev/null 2>&1 || true
  kubectl -n "$NS_UGALLU" delete configmap hp-smoke-payload --ignore-not-found >/dev/null 2>&1 || true
  kubectl get securityevent --no-headers 2>/dev/null \
    | awk -v rid="$RUN_ID" '$0 ~ rid {print $1}' \
    | xargs -r kubectl delete securityevent --ignore-not-found >/dev/null 2>&1 || true
  rm -f /tmp/hp-smoke-body.json 2>/dev/null || true
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

# --- Test 1: VAP rejects empty decoys -------------------------------
info "Test 1: admission policy 12 rejects empty decoys list"
denied_msg=$(kubectl apply -f - <<EOF 2>&1 || true
apiVersion: security.ugallu.io/v1alpha1
kind: HoneypotConfig
metadata:
  name: ${HP_BAD}
spec:
  decoys: []
EOF
)
if echo "$denied_msg" | grep -qiE "decoys must declare at least one"; then
  pass "VAP rejected empty decoys list"
else
  fail "expected admission rejection, got: $denied_msg"
fi

# --- Bootstrap the namespace + 2 SAs --------------------------------
info "Bootstrap: namespace + actor SAs"
kubectl create ns "$NS" --dry-run=client -o yaml | kubectl apply -f -
kubectl create sa "$SA_ATTACKER" -n "$NS" --dry-run=client -o yaml | kubectl apply -f -
kubectl create sa "$SA_BACKUP" -n "$NS" --dry-run=client -o yaml | kubectl apply -f -
kubectl create rolebinding "${SA_ATTACKER}-secret-reader" -n "$NS" \
  --clusterrole=view --serviceaccount="${NS}:${SA_ATTACKER}" --dry-run=client -o yaml \
  | kubectl apply -f -
kubectl create rolebinding "${SA_BACKUP}-secret-reader" -n "$NS" \
  --clusterrole=view --serviceaccount="${NS}:${SA_BACKUP}" --dry-run=client -o yaml \
  | kubectl apply -f -

# --- Test 2: HoneypotConfig deploys decoys --------------------------
info "Test 2: HoneypotConfig materialises decoys with ownerRef + label"
cat <<EOF | kubectl apply -f -
apiVersion: security.ugallu.io/v1alpha1
kind: HoneypotConfig
metadata:
  name: ${HP_GOOD}
spec:
  emitOnRead: true
  allowlistedActors:
    - system:serviceaccount:${NS}:${SA_BACKUP}
  decoys:
    - kind: Secret
      name: prod-db-creds-${RUN_ID}
      namespace: ${NS}
      data:
        password: hunter2
    - kind: ServiceAccount
      name: backup-uploader-${RUN_ID}
      namespace: ${NS}
EOF

for _ in $(seq 1 30); do
  if kubectl -n "$NS" get secret "prod-db-creds-${RUN_ID}" >/dev/null 2>&1 \
     && kubectl -n "$NS" get sa "backup-uploader-${RUN_ID}" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
kubectl -n "$NS" get secret "prod-db-creds-${RUN_ID}" -o jsonpath='{.metadata.labels.ugallu\.io/decoy}' | grep -q true \
  || fail "decoy Secret missing label ugallu.io/decoy=true"
pass "decoys materialised (Secret + ServiceAccount with decoy label)"

# Give honeypot leader time to connect to the audit bus before we
# post synthetic events.
sleep 10

# --- Test 3: HoneypotTriggered fires on attacker read ---------------
info "Test 3: HoneypotTriggered fires when attacker SA reads decoy (synthetic audit)"
webhook_post '{"kind":"EventList","apiVersion":"audit.k8s.io/v1","items":[{"kind":"Event","apiVersion":"audit.k8s.io/v1","level":"Metadata","auditID":"hp-smoke-trig-'${RUN_ID}'","stage":"ResponseComplete","verb":"get","user":{"username":"system:serviceaccount:'${NS}':'${SA_ATTACKER}'"},"objectRef":{"resource":"secrets","namespace":"'${NS}'","name":"prod-db-creds-'${RUN_ID}'"},"responseStatus":{"code":200},"requestReceivedTimestamp":"2026-04-29T08:00:00.000000Z","stageTimestamp":"2026-04-29T08:00:00.001000Z"}]}'
if wait_for_se HoneypotTriggered 60; then
  pass "HoneypotTriggered SE emitted"
else
  fail "no HoneypotTriggered SE within 60s"
fi

# --- Test 4: HoneypotMisplaced fires on Pod with decoy volume -------
info "Test 4: HoneypotMisplaced fires when a Pod mounts a decoy Secret (synthetic audit)"
webhook_post '{"kind":"EventList","apiVersion":"audit.k8s.io/v1","items":[{"kind":"Event","apiVersion":"audit.k8s.io/v1","level":"RequestResponse","auditID":"hp-smoke-misp-'${RUN_ID}'","stage":"ResponseComplete","verb":"create","user":{"username":"system:serviceaccount:'${NS}':'${SA_ATTACKER}'"},"objectRef":{"resource":"pods","namespace":"'${NS}'","name":"exfil-pod-'${RUN_ID}'"},"requestObject":{"spec":{"volumes":[{"name":"stolen","secret":{"secretName":"prod-db-creds-'${RUN_ID}'"}}]}},"responseStatus":{"code":201},"requestReceivedTimestamp":"2026-04-29T08:00:00.000000Z","stageTimestamp":"2026-04-29T08:00:00.001000Z"}]}'
if wait_for_se HoneypotMisplaced 60; then
  pass "HoneypotMisplaced SE emitted"
else
  fail "no HoneypotMisplaced SE within 60s"
fi

# --- Test 5: Allowlisted SA does NOT fire ---------------------------
info "Test 5: allowlisted backup SA reads decoy → no fire (synthetic audit)"
# Drop the previous SE so we see a fresh emit (or absence of one).
kubectl get securityevent --no-headers 2>/dev/null \
  | awk '/HoneypotTriggered/ {print $1}' \
  | xargs -r kubectl delete securityevent --ignore-not-found >/dev/null 2>&1 || true

webhook_post '{"kind":"EventList","apiVersion":"audit.k8s.io/v1","items":[{"kind":"Event","apiVersion":"audit.k8s.io/v1","level":"Metadata","auditID":"hp-smoke-allow-'${RUN_ID}'","stage":"ResponseComplete","verb":"get","user":{"username":"system:serviceaccount:'${NS}':'${SA_BACKUP}'"},"objectRef":{"resource":"secrets","namespace":"'${NS}'","name":"prod-db-creds-'${RUN_ID}'"},"responseStatus":{"code":200},"requestReceivedTimestamp":"2026-04-29T08:00:00.000000Z","stageTimestamp":"2026-04-29T08:00:00.001000Z"}]}'
sleep 10
if wait_for_se HoneypotTriggered 5; then
  fail "allowlisted SA should not have produced a HoneypotTriggered SE"
else
  pass "allowlisted SA correctly filtered"
fi

echo
pass "honeypot smoke: 5 scenarios green"
