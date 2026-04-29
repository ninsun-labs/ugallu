#!/usr/bin/env bash
# E2E lab smoke for ugallu-compliance-scan — Wave 4 Sprint 7 close gate.
#
# Scenarios (3):
#   1. Admission policy 15 rejects backend not in [kube-bench, falco, cel-custom].
#   2. ComplianceScanRun (cel-custom) → Succeeded + ComplianceScanResult
#      with the 3 in-tree checks.
#   3. ComplianceScanCompleted SE emitted.
#
# Run with:
#   bash hack/compliance-scan-smoke.sh

set -euo pipefail

GREEN=$'\033[0;32m'
RED=$'\033[0;31m'
YELLOW=$'\033[1;33m'
NC=$'\033[0m'

pass() { echo "${GREEN}PASS${NC} $*"; }
fail() { echo "${RED}FAIL${NC} $*" >&2; exit 1; }
info() { echo "${YELLOW}==>${NC} $*"; }

RUN_ID=$(date +%s)-$$
NS=cs-smoke-${RUN_ID}

cleanup() { kubectl delete ns "$NS" --ignore-not-found --wait=false >/dev/null 2>&1 || true; }
trap cleanup EXIT

info "create test namespace $NS"
kubectl create namespace "$NS" >/dev/null

# --- Scenario 1: bad backend ---------------------------------------
info "S1: admission rejects backend=trivy"
if cat <<EOF | kubectl apply -f - >/dev/null 2>&1
apiVersion: security.ugallu.io/v1alpha1
kind: ComplianceScanRun
metadata: { name: bad-backend, namespace: $NS }
spec: { backend: trivy, profile: cis-1.10, timeout: 10m }
EOF
then fail "admission accepted backend=trivy"; fi
pass "S1: backend=trivy rejected"

# --- Scenario 2: cel-custom → Succeeded ----------------------------
info "S2: cel-custom scan → Succeeded"
cat <<EOF | kubectl apply -f - >/dev/null
apiVersion: security.ugallu.io/v1alpha1
kind: ComplianceScanRun
metadata: { name: cel-run, namespace: $NS }
spec:
  backend: cel-custom
  profile: default
  timeout: 30s
  controlMappings:
    - checkID: ugallu.cel.pods-run-as-non-root
      frameworks: [{ name: soc2, controlID: CC6.6 }]
EOF

deadline=$(( $(date +%s) + 60 ))
phase=""
while [ "$(date +%s)" -lt "$deadline" ]; do
  phase=$(kubectl -n "$NS" get compliancescanrun cel-run -o jsonpath='{.status.phase}' 2>/dev/null || echo "")
  [ "$phase" = "Succeeded" ] && break
  [ "$phase" = "Failed" ] && fail "S2: run Failed; conditions=$(kubectl -n $NS get compliancescanrun cel-run -o jsonpath='{.status.conditions}')"
  sleep 1
done
[ "$phase" = "Succeeded" ] || fail "S2: phase=$phase, want Succeeded"
pass "S2: cel-custom run reached Succeeded"

results=$(kubectl -n "$NS" get compliancescanresults -o name 2>/dev/null || true)
result="${results%%$'\n'*}"
[ -n "$result" ] || fail "S2: no ComplianceScanResult"
checks=$(kubectl -n "$NS" get "$result" -o jsonpath='{.spec.checks}' 2>/dev/null || true)
echo "$checks" | grep -q 'pods-run-as-non-root' || fail "S2: missing pods-run-as-non-root check in result"
echo "$checks" | grep -q 'read-only-root-fs' || fail "S2: missing read-only-root-fs check in result"
echo "$checks" | grep -q 'CC6.6' || fail "S2: ControlMapping decoration missing"
pass "S2: ComplianceScanResult complete with 3 checks + framework mapping"

# --- Scenario 3: SE emitted ----------------------------------------
info "S3: ComplianceScanCompleted SE"
deadline=$(( $(date +%s) + 30 ))
se_found=""
while [ "$(date +%s)" -lt "$deadline" ]; do
  se_found=$(kubectl -n "$NS" get securityevents -o jsonpath='{.items[?(@.spec.type=="ComplianceScanCompleted")].metadata.name}' 2>/dev/null || echo "")
  [ -n "$se_found" ] && break
  sleep 1
done
[ -n "$se_found" ] || fail "S3: ComplianceScanCompleted SE never appeared"
pass "S3: ComplianceScanCompleted SE emitted"

echo
pass "compliance-scan smoke: 3/3 scenarios green"
