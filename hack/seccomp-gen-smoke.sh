#!/usr/bin/env bash
# E2E lab smoke for ugallu-seccomp-gen.
#
# Scenarios (4):
#   1. Admission policy 13 rejects ratio=0 / ratio>100.
#   2. Admission policy 13 rejects timeout > 24h.
#   3. SeccompTrainingRun whose selector matches no pods → Failed +
#      SeccompTrainingFailed SE.
#   4. SeccompTrainingRun targeting a real Pod → Succeeded +
#      SeccompTrainingProfile + SeccompTrainingCompleted SE.
#
# Run with:
#   bash hack/seccomp-gen-smoke.sh

set -euo pipefail

GREEN=$'\033[0;32m'
RED=$'\033[0;31m'
YELLOW=$'\033[1;33m'
NC=$'\033[0m'

pass() { echo "${GREEN}PASS${NC} $*"; }
fail() { echo "${RED}FAIL${NC} $*" >&2; exit 1; }
info() { echo "${YELLOW}==>${NC} $*"; }

RUN_ID=$(date +%s)-$$
NS=sg-smoke-${RUN_ID}

cleanup() {
  info "cleanup"
  kubectl delete ns "$NS" --ignore-not-found --wait=false >/dev/null 2>&1 || true
}
trap cleanup EXIT

info "create test namespace $NS"
kubectl create namespace "$NS" >/dev/null

# --- Scenario 1: admission rejects ratio=0 -------------------------
info "S1: admission policy 13 rejects ratio=0"
if cat <<EOF | kubectl apply -f - >/dev/null 2>&1
apiVersion: security.ugallu.io/v1alpha1
kind: SeccompTrainingRun
metadata:
  name: bad-ratio
  namespace: $NS
spec:
  targetSelector: { matchLabels: { app: x } }
  targetNamespace: $NS
  duration: 5s
  replicaRatio: 0
  defaultAction: SCMP_ACT_ERRNO
EOF
then fail "admission accepted ratio=0"; fi
pass "S1: ratio=0 rejected"

# --- Scenario 2: admission rejects timeout > 24h -------------------
info "S2: admission policy 13 rejects duration > 24h"
if cat <<EOF | kubectl apply -f - >/dev/null 2>&1
apiVersion: security.ugallu.io/v1alpha1
kind: SeccompTrainingRun
metadata:
  name: bad-duration
  namespace: $NS
spec:
  targetSelector: { matchLabels: { app: x } }
  targetNamespace: $NS
  duration: 25h
  replicaRatio: 50
  defaultAction: SCMP_ACT_ERRNO
EOF
then fail "admission accepted duration=25h"; fi
pass "S2: duration > 24h rejected"

# --- Scenario 3: selector matches no pods → Failed ------------------
info "S3: training run with empty selector → Failed"
cat <<EOF | kubectl apply -f - >/dev/null
apiVersion: security.ugallu.io/v1alpha1
kind: SeccompTrainingRun
metadata:
  name: no-match-run
  namespace: $NS
spec:
  targetSelector: { matchLabels: { does-not-exist: "true" } }
  targetNamespace: $NS
  duration: 5s
  replicaRatio: 50
  defaultAction: SCMP_ACT_ERRNO
EOF
deadline=$(( $(date +%s) + 30 ))
phase=""
while [ "$(date +%s)" -lt "$deadline" ]; do
  phase=$(kubectl -n "$NS" get seccomptrainingrun no-match-run -o jsonpath='{.status.phase}' 2>/dev/null || echo "")
  [ "$phase" = "Failed" ] && break
  sleep 1
done
[ "$phase" = "Failed" ] || fail "S3: phase=$phase, want Failed"
pass "S3: empty-selector run reached Failed"

# Look for the SeccompTrainingFailed SE.
deadline=$(( $(date +%s) + 30 ))
se_found=""
while [ "$(date +%s)" -lt "$deadline" ]; do
  se_found=$(kubectl -n "$NS" get securityevents -o jsonpath='{.items[?(@.spec.type=="SeccompTrainingFailed")].metadata.name}' 2>/dev/null || echo "")
  [ -n "$se_found" ] && break
  sleep 1
done
[ -n "$se_found" ] || fail "S3: SeccompTrainingFailed SE never appeared"
pass "S3: SeccompTrainingFailed SE emitted ($se_found)"

# --- Scenario 4: real Pod target → Succeeded -----------------------
info "S4: training run with matching Pod → Succeeded"
kubectl -n "$NS" run target --image=registry.k8s.io/pause:3.10 --labels=app=demo >/dev/null
kubectl -n "$NS" wait pod/target --for=condition=Ready --timeout=30s >/dev/null

cat <<EOF | kubectl apply -f - >/dev/null
apiVersion: security.ugallu.io/v1alpha1
kind: SeccompTrainingRun
metadata:
  name: real-run
  namespace: $NS
spec:
  targetSelector: { matchLabels: { app: demo } }
  targetNamespace: $NS
  duration: 5s
  replicaRatio: 100
  defaultAction: SCMP_ACT_ERRNO
EOF

deadline=$(( $(date +%s) + 60 ))
phase=""
while [ "$(date +%s)" -lt "$deadline" ]; do
  phase=$(kubectl -n "$NS" get seccomptrainingrun real-run -o jsonpath='{.status.phase}' 2>/dev/null || echo "")
  [ "$phase" = "Succeeded" ] && break
  [ "$phase" = "Failed" ] && fail "S4: run reached Failed early; conditions=$(kubectl -n $NS get seccomptrainingrun real-run -o jsonpath='{.status.conditions}')"
  sleep 2
done
[ "$phase" = "Succeeded" ] || fail "S4: phase=$phase, want Succeeded"
pass "S4: real-Pod run reached Succeeded"

# SeccompTrainingProfile must be present.
profiles=$(kubectl -n "$NS" get seccomptrainingprofiles -o name 2>/dev/null || true)
profile="${profiles%%$'\n'*}"
[ -n "$profile" ] || fail "S4: no SeccompTrainingProfile created"
syscalls_raw=$(kubectl -n "$NS" get "$profile" -o jsonpath='{.spec.profileJSON}' 2>/dev/null || true)
[ -n "$syscalls_raw" ] || fail "S4: profile.spec.profileJSON empty"
echo "$syscalls_raw" | base64 -d 2>/dev/null | grep -q '"names"' || fail "S4: decoded profile missing syscalls"
pass "S4: SeccompTrainingProfile created ($profile)"

# SeccompTrainingCompleted SE emitted.
deadline=$(( $(date +%s) + 30 ))
se_found=""
while [ "$(date +%s)" -lt "$deadline" ]; do
  se_found=$(kubectl -n "$NS" get securityevents -o jsonpath='{.items[?(@.spec.type=="SeccompTrainingCompleted")].metadata.name}' 2>/dev/null || echo "")
  [ -n "$se_found" ] && break
  sleep 1
done
[ -n "$se_found" ] || fail "S4: SeccompTrainingCompleted SE never appeared"
pass "S4: SeccompTrainingCompleted SE emitted"

echo
pass "seccomp-gen smoke: 4/4 scenarios green"
