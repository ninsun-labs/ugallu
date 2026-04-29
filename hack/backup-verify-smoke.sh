#!/usr/bin/env bash
# E2E lab smoke for ugallu-backup-verify — Wave 4 Sprint 7 close gate.
#
# Scenarios (4):
#   1. Admission policy 14 rejects backend not in [velero, etcd-snapshot].
#   2. Admission policy 14 rejects mode=full-restore without sandboxNamespace.
#   3. BackupVerifyRun (etcd-snapshot, checksum-only) on a missing
#      file → Failed + BackupVerifyFailed SE.
#   4. BackupVerifyRun (velero, checksum-only) → Succeeded +
#      BackupVerifyResult + BackupVerifyCompleted SE.
#
# Run with:
#   bash hack/backup-verify-smoke.sh

set -euo pipefail

GREEN=$'\033[0;32m'
RED=$'\033[0;31m'
YELLOW=$'\033[1;33m'
NC=$'\033[0m'

pass() { echo "${GREEN}PASS${NC} $*"; }
fail() { echo "${RED}FAIL${NC} $*" >&2; exit 1; }
info() { echo "${YELLOW}==>${NC} $*"; }

RUN_ID=$(date +%s)-$$
NS=bv-smoke-${RUN_ID}

cleanup() { kubectl delete ns "$NS" --ignore-not-found --wait=false >/dev/null 2>&1 || true; }
trap cleanup EXIT

info "create test namespace $NS"
kubectl create namespace "$NS" >/dev/null

# --- Scenario 1: bad backend ---------------------------------------
info "S1: admission rejects backend=restic"
if cat <<EOF | kubectl apply -f - >/dev/null 2>&1
apiVersion: security.ugallu.io/v1alpha1
kind: BackupVerifyRun
metadata: { name: bad-backend, namespace: $NS }
spec: { backend: restic, backupRef: { name: x }, mode: checksum-only, timeout: 5m }
EOF
then fail "admission accepted backend=restic"; fi
pass "S1: backend=restic rejected"

# --- Scenario 2: full-restore without sandbox ----------------------
info "S2: admission rejects mode=full-restore without sandbox"
if cat <<EOF | kubectl apply -f - >/dev/null 2>&1
apiVersion: security.ugallu.io/v1alpha1
kind: BackupVerifyRun
metadata: { name: bad-restore, namespace: $NS }
spec: { backend: velero, backupRef: { name: x, namespace: velero }, mode: full-restore, timeout: 5m }
EOF
then fail "admission accepted full-restore without sandbox"; fi
pass "S2: full-restore without sandbox rejected"

# --- Scenario 3: missing file → Failed -----------------------------
info "S3: etcd-snapshot run for non-existent file → Failed"
cat <<EOF | kubectl apply -f - >/dev/null
apiVersion: security.ugallu.io/v1alpha1
kind: BackupVerifyRun
metadata: { name: missing-file, namespace: $NS }
spec:
  backend: etcd-snapshot
  backupRef: { name: does-not-exist }
  mode: checksum-only
  timeout: 30s
EOF
deadline=$(( $(date +%s) + 60 ))
phase=""
while [ "$(date +%s)" -lt "$deadline" ]; do
  phase=$(kubectl -n "$NS" get backupverifyrun missing-file -o jsonpath='{.status.phase}' 2>/dev/null || echo "")
  [ "$phase" = "Failed" ] && break
  sleep 1
done
[ "$phase" = "Failed" ] || fail "S3: phase=$phase, want Failed"
pass "S3: missing-file run reached Failed"

deadline=$(( $(date +%s) + 30 ))
se_found=""
while [ "$(date +%s)" -lt "$deadline" ]; do
  se_found=$(kubectl -n "$NS" get securityevents -o jsonpath='{.items[?(@.spec.type=="BackupVerifyFailed")].metadata.name}' 2>/dev/null || echo "")
  [ -n "$se_found" ] && break
  sleep 1
done
[ -n "$se_found" ] || fail "S3: BackupVerifyFailed SE never appeared"
pass "S3: BackupVerifyFailed SE emitted"

# --- Scenario 4: velero stub → Succeeded ---------------------------
info "S4: velero checksum-only → Succeeded"
cat <<EOF | kubectl apply -f - >/dev/null
apiVersion: security.ugallu.io/v1alpha1
kind: BackupVerifyRun
metadata: { name: velero-good, namespace: $NS }
spec:
  backend: velero
  backupRef: { name: dummy, namespace: velero }
  mode: checksum-only
  timeout: 30s
EOF
deadline=$(( $(date +%s) + 60 ))
phase=""
while [ "$(date +%s)" -lt "$deadline" ]; do
  phase=$(kubectl -n "$NS" get backupverifyrun velero-good -o jsonpath='{.status.phase}' 2>/dev/null || echo "")
  [ "$phase" = "Succeeded" ] && break
  [ "$phase" = "Failed" ] && fail "S4: ran Failed; conditions=$(kubectl -n $NS get backupverifyrun velero-good -o jsonpath='{.status.conditions}')"
  sleep 1
done
[ "$phase" = "Succeeded" ] || fail "S4: phase=$phase, want Succeeded"
pass "S4: velero run reached Succeeded"

results=$(kubectl -n "$NS" get backupverifyresults -o name 2>/dev/null || true)
result="${results%%$'\n'*}"
[ -n "$result" ] || fail "S4: no BackupVerifyResult created"
pass "S4: BackupVerifyResult created ($result)"

deadline=$(( $(date +%s) + 30 ))
se_found=""
while [ "$(date +%s)" -lt "$deadline" ]; do
  se_found=$(kubectl -n "$NS" get securityevents -o jsonpath='{.items[?(@.spec.type=="BackupVerifyCompleted")].metadata.name}' 2>/dev/null || echo "")
  [ -n "$se_found" ] && break
  sleep 1
done
[ -n "$se_found" ] || fail "S4: BackupVerifyCompleted SE never appeared"
pass "S4: BackupVerifyCompleted SE emitted"

echo
pass "backup-verify smoke: 4/4 scenarios green"
