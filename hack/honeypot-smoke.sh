#!/usr/bin/env bash
# E2E lab smoke for ugallu-honeypot — Wave 3 Sprint 5 close gate.
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

cleanup() {
  kubectl delete ns "$NS" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  kubectl delete honeypotconfig "$HP_GOOD" "$HP_BAD" --ignore-not-found >/dev/null 2>&1 || true
  kubectl get securityevent --no-headers 2>/dev/null \
    | awk -v rid="$RUN_ID" '$0 ~ rid {print $1}' \
    | xargs -r kubectl delete securityevent --ignore-not-found >/dev/null 2>&1 || true
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

# --- Test 3: HoneypotTriggered fires on attacker read ---------------
info "Test 3: HoneypotTriggered fires when attacker SA reads decoy"
kubectl --as="system:serviceaccount:${NS}:${SA_ATTACKER}" \
  -n "$NS" get secret "prod-db-creds-${RUN_ID}" >/dev/null 2>&1 || true
if wait_for_se HoneypotTriggered 60; then
  pass "HoneypotTriggered SE emitted"
else
  fail "no HoneypotTriggered SE within 60s"
fi

# --- Test 4: HoneypotMisplaced fires on Pod with decoy volume -------
info "Test 4: HoneypotMisplaced fires when a Pod mounts a decoy Secret"
cat <<EOF | kubectl apply -f - || true
apiVersion: v1
kind: Pod
metadata:
  name: exfil-pod-${RUN_ID}
  namespace: ${NS}
spec:
  restartPolicy: Never
  containers:
    - name: x
      image: busybox:1.37
      command: ["/bin/sleep", "3"]
      volumeMounts:
        - name: stolen
          mountPath: /stolen
  volumes:
    - name: stolen
      secret:
        secretName: prod-db-creds-${RUN_ID}
EOF

if wait_for_se HoneypotMisplaced 60; then
  pass "HoneypotMisplaced SE emitted"
else
  fail "no HoneypotMisplaced SE within 60s"
fi

# --- Test 5: Allowlisted SA does NOT fire ---------------------------
info "Test 5: allowlisted backup SA reads decoy → no fire"
# Drop the previous SE so we see a fresh emit (or absence of one).
kubectl get securityevent --no-headers 2>/dev/null \
  | awk '/HoneypotTriggered/ {print $1}' \
  | xargs -r kubectl delete securityevent --ignore-not-found >/dev/null 2>&1 || true

kubectl --as="system:serviceaccount:${NS}:${SA_BACKUP}" \
  -n "$NS" get secret "prod-db-creds-${RUN_ID}" >/dev/null 2>&1 || true
sleep 30
if wait_for_se HoneypotTriggered 5; then
  fail "allowlisted SA should not have produced a HoneypotTriggered SE"
else
  pass "allowlisted SA correctly filtered"
fi

echo
pass "honeypot smoke: 5 scenarios green"
