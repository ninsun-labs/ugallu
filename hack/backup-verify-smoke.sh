#!/usr/bin/env bash
# E2E lab smoke for ugallu-backup-verify.
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

# --- Scenario 4: velero checksum-only → Succeeded ------------------
info "S4: velero checksum-only → Succeeded (backup-not-found finding is acceptable)"
cat <<EOF | kubectl apply -f - >/dev/null
apiVersion: security.ugallu.io/v1alpha1
kind: BackupVerifyRun
metadata: { name: velero-good, namespace: $NS }
spec:
  backend: velero
  backupRef: { name: smoke-not-real, namespace: velero }
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
  # The verifier surfaces a velero-backup-not-found finding
  # (severity=high) → SE class flips from Compliance to Detection
  # (BackupVerifyMismatch). Either is a valid "verifier closed the
  # run" signal for the smoke.
  for t in BackupVerifyCompleted BackupVerifyMismatch; do
    n=$(kubectl -n "$NS" get securityevents -o jsonpath="{.items[?(@.spec.type==\"$t\")].metadata.name}" 2>/dev/null || echo "")
    if [ -n "$n" ]; then se_found="$t/$n"; break; fi
  done
  [ -n "$se_found" ] && break
  sleep 1
done
[ -n "$se_found" ] || fail "S4: no BackupVerify Completed/Mismatch SE appeared"
pass "S4: SE emitted ($se_found)"

# --- Scenario 5: velero full-restore → Succeeded with diff findings -
info "S5: velero full-restore E2E (skip if Velero is not installed)"
if ! kubectl get crd backups.velero.io >/dev/null 2>&1; then
  echo "${YELLOW}SKIP${NC} S5: Velero CRDs not installed in this cluster"
else
  SANDBOX_NS="bv-${RUN_ID}-bvsandbox"
  cat <<EOF | kubectl apply -f - >/dev/null
apiVersion: security.ugallu.io/v1alpha1
kind: BackupVerifyRun
metadata: { name: velero-fullrestore, namespace: $NS }
spec:
  backend: velero
  backupRef: { name: smoke-not-real, namespace: velero }
  mode: full-restore
  sandboxNamespace: $SANDBOX_NS
  timeout: 3m
EOF
  # Watch the async pipeline up to 3m. The Restore CR will fail with
  # backup-not-found (the smoke doesn't seed a real Velero Backup -
  # that's S6 territory). We assert the pipeline completes + the
  # cleanup tears the sandbox + Restore CR down.
  deadline=$(( $(date +%s) + 180 ))
  phase=""
  while [ "$(date +%s)" -lt "$deadline" ]; do
    phase=$(kubectl -n "$NS" get backupverifyrun velero-fullrestore -o jsonpath='{.status.phase}' 2>/dev/null || echo "")
    [ "$phase" = "Succeeded" ] && break
    [ "$phase" = "Failed" ] && fail "S5: phase=Failed; conditions=$(kubectl -n $NS get backupverifyrun velero-fullrestore -o jsonpath='{.status.conditions}')"
    sleep 5
  done
  [ "$phase" = "Succeeded" ] || fail "S5: phase=$phase, want Succeeded"
  pass "S5: full-restore run reached Succeeded"

  # Result must carry at least one finding.
  results=$(kubectl -n "$NS" get backupverifyresults -o name 2>/dev/null | grep velero-fullrestore || true)
  [ -n "$results" ] || fail "S5: no BackupVerifyResult"
  worst=$(kubectl -n "$NS" get backupverifyresult velero-fullrestore-result -o jsonpath='{.status.worstSeverity}' 2>/dev/null)
  [ -n "$worst" ] || fail "S5: status.worstSeverity not populated"
  pass "S5: result has worstSeverity=$worst"

  # Cleanup invariants - sandbox NS gone, Restore CR gone.
  if kubectl get ns "$SANDBOX_NS" >/dev/null 2>&1; then
    fail "S5: sandbox namespace $SANDBOX_NS not cleaned up"
  fi
  if kubectl -n velero get restore velero-fullrestore-restore >/dev/null 2>&1; then
    fail "S5: Velero Restore CR not cleaned up"
  fi
  pass "S5: sandbox + Restore CR cleaned up"
fi

echo
pass "backup-verify smoke: 5/5 scenarios green (S5 may skip)"
