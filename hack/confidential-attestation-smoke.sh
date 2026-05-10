#!/usr/bin/env bash
# E2E lab smoke for ugallu-confidential-attestation.
#
# Scenarios (4):
#   1. Admission policy 16 rejects nonce shorter than 16 chars.
#   2. Admission policy 16 rejects backend not in [tpm, sev-snp, tdx].
#   3. ConfidentialAttestationRun (tpm, no PolicyRef) → Succeeded with
#      verdict=indeterminate (no TPM device on the lab nodes).
#   4. AttestationVerified SE emitted (info severity for indeterminate).
#
# Run with:
#   bash hack/confidential-attestation-smoke.sh

set -euo pipefail

GREEN=$'\033[0;32m'
RED=$'\033[0;31m'
YELLOW=$'\033[1;33m'
NC=$'\033[0m'

pass() { echo "${GREEN}PASS${NC} $*"; }
fail() { echo "${RED}FAIL${NC} $*" >&2; exit 1; }
info() { echo "${YELLOW}==>${NC} $*"; }

RUN_ID=$(date +%s)-$$
NS=ca-smoke-${RUN_ID}

cleanup() { kubectl delete ns "$NS" --ignore-not-found --wait=false >/dev/null 2>&1 || true; }
trap cleanup EXIT

info "create test namespace $NS"
kubectl create namespace "$NS" >/dev/null

NODE_NAME=$(kubectl get nodes -o jsonpath='{.items[0].metadata.name}')
NONCE=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')

# --- Scenario 1: short nonce ---------------------------------------
info "S1: admission rejects nonce < 16 chars"
if cat <<EOF | kubectl apply -f - >/dev/null 2>&1
apiVersion: security.ugallu.io/v1alpha1
kind: ConfidentialAttestationRun
metadata: { name: bad-nonce, namespace: $NS }
spec:
  backend: tpm
  targetNodeName: $NODE_NAME
  nonce: short
  timeout: 30s
EOF
then fail "admission accepted nonce=short"; fi
pass "S1: short nonce rejected"

# --- Scenario 2: bad backend ---------------------------------------
info "S2: admission rejects backend=tdme"
if cat <<EOF | kubectl apply -f - >/dev/null 2>&1
apiVersion: security.ugallu.io/v1alpha1
kind: ConfidentialAttestationRun
metadata: { name: bad-backend, namespace: $NS }
spec:
  backend: tdme
  targetNodeName: $NODE_NAME
  nonce: $NONCE
  timeout: 30s
EOF
then fail "admission accepted backend=tdme"; fi
pass "S2: bad backend rejected"

# --- Scenario 3: tpm run on a TPM-less node → indeterminate --------
info "S3: tpm run → Succeeded with indeterminate verdict"
cat <<EOF | kubectl apply -f - >/dev/null
apiVersion: security.ugallu.io/v1alpha1
kind: ConfidentialAttestationRun
metadata: { name: tpm-run, namespace: $NS }
spec:
  backend: tpm
  targetNodeName: $NODE_NAME
  nonce: $NONCE
  timeout: 30s
EOF

deadline=$(( $(date +%s) + 60 ))
phase=""
while [ "$(date +%s)" -lt "$deadline" ]; do
  phase=$(kubectl -n "$NS" get confidentialattestationrun tpm-run -o jsonpath='{.status.phase}' 2>/dev/null || echo "")
  [ "$phase" = "Succeeded" ] && break
  [ "$phase" = "Failed" ] && fail "S3: run Failed; conditions=$(kubectl -n $NS get confidentialattestationrun tpm-run -o jsonpath='{.status.conditions}')"
  sleep 1
done
[ "$phase" = "Succeeded" ] || fail "S3: phase=$phase, want Succeeded"
pass "S3: tpm run reached Succeeded"

results=$(kubectl -n "$NS" get confidentialattestationresults -o name 2>/dev/null || true)
result="${results%%$'\n'*}"
[ -n "$result" ] || fail "S3: no ConfidentialAttestationResult"
verdict=$(kubectl -n "$NS" get "$result" -o jsonpath='{.spec.verdict}' 2>/dev/null || echo "")
[ "$verdict" = "indeterminate" ] || fail "S3: verdict=$verdict, want indeterminate"
pass "S3: ConfidentialAttestationResult written with verdict=indeterminate"

# --- Scenario 4: SE emitted ----------------------------------------
info "S4: AttestationVerified SE"
deadline=$(( $(date +%s) + 30 ))
se_found=""
while [ "$(date +%s)" -lt "$deadline" ]; do
  se_found=$(kubectl -n "$NS" get securityevents -o jsonpath='{.items[?(@.spec.type=="AttestationVerified")].metadata.name}' 2>/dev/null || echo "")
  [ -n "$se_found" ] && break
  sleep 1
done
[ -n "$se_found" ] || fail "S4: AttestationVerified SE never appeared"
pass "S4: AttestationVerified SE emitted"

echo
pass "confidential-attestation smoke: 4/4 scenarios green"
