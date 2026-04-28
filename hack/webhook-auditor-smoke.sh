#!/usr/bin/env bash
# E2E lab smoke for ugallu-webhook-auditor — Wave 3 Sprint 1 close gate.
#
# Assumes:
#   - kubectl context already pointed at the lab
#   - ugallu-webhook-auditor running with the real binary (placeholder=false)
#   - WebhookAuditorConfig 'default' singleton present (chart-shipped)
#
# What it covers (3 scenarios — Phase 1 close per design 21 §VIII):
#   1. High-risk MWC emits MutatingWebhookHighRisk + sub-score SEs
#   2. Sub-threshold VWC emits only the active sub-score SE (no top-level)
#   3. Ignore-policy match (ugallu.* glob) skips evaluation
#
# Run with:
#   bash hack/webhook-auditor-smoke.sh

set -euo pipefail

GREEN=$'\033[0;32m'
RED=$'\033[0;31m'
YELLOW=$'\033[1;33m'
NC=$'\033[0m'

pass() { echo "${GREEN}PASS${NC} $*"; }
fail() { echo "${RED}FAIL${NC} $*" >&2; exit 1; }
info() { echo "${YELLOW}==>${NC} $*"; }

# Unique suffix per run so SE deterministic names from previous runs
# don't collide with this run's events.
RUN_ID=$(date +%s)-$$
HIGH_MWC=webhook-smoke-evil-${RUN_ID}
CLEAN_VWC=webhook-smoke-clean-${RUN_ID}
IGNORED_MWC=ugallu.smoke-test-${RUN_ID}

cleanup() {
  kubectl delete mutatingwebhookconfiguration "$HIGH_MWC" "$IGNORED_MWC" --ignore-not-found >/dev/null 2>&1 || true
  kubectl delete validatingwebhookconfiguration "$CLEAN_VWC" --ignore-not-found >/dev/null 2>&1 || true
  kubectl get securityevent --no-headers 2>/dev/null \
    | awk -v rid="$RUN_ID" '$0 ~ rid {print $1}' \
    | xargs -r kubectl delete securityevent --ignore-not-found >/dev/null 2>&1 || true
}
trap cleanup EXIT

apply_mwc() {
  local name=$1 fp=$2 sideeff=$3 resources=$4
  cat <<EOF | kubectl apply -f - >/dev/null
apiVersion: admissionregistration.k8s.io/v1
kind: MutatingWebhookConfiguration
metadata:
  name: ${name}
webhooks:
  - name: h.example.io
    clientConfig:
      url: https://example.invalid/admit
    rules:
      - operations: ["CREATE"]
        apiGroups: [""]
        apiVersions: ["v1"]
        resources: [${resources}]
    failurePolicy: ${fp}
    sideEffects: ${sideeff}
    admissionReviewVersions: ["v1"]
    timeoutSeconds: 5
EOF
}

apply_vwc() {
  local name=$1 fp=$2 sideeff=$3 resources=$4
  cat <<EOF | kubectl apply -f - >/dev/null
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: ${name}
webhooks:
  - name: h.example.io
    clientConfig:
      url: https://example.invalid/admit
    rules:
      - operations: ["CREATE"]
        apiGroups: [""]
        apiVersions: ["v1"]
        resources: [${resources}]
    failurePolicy: ${fp}
    sideEffects: ${sideeff}
    admissionReviewVersions: ["v1"]
    timeoutSeconds: 5
EOF
}

# wait_for_se: polls SE list for one matching <type, subject.name>.
# Returns 0 + prints SE name on success, 1 if not seen within budget.
wait_for_se() {
  local seType=$1 subjectName=$2 budget=${3:-30}
  for _ in $(seq 1 "$budget"); do
    name=$(kubectl get securityevent \
      -o jsonpath='{range .items[?(@.spec.subject.name=="'"$subjectName"'")]}{.metadata.name}{"\t"}{.spec.type}{"\n"}{end}' 2>/dev/null \
      | awk -v t="$seType" '$2==t{print $1; exit}')
    if [ -n "$name" ]; then
      echo "$name"
      return 0
    fi
    sleep 1
  done
  return 1
}

assert_no_se() {
  local seType=$1 subjectName=$2 budget=${3:-3}
  for _ in $(seq 1 "$budget"); do
    name=$(kubectl get securityevent \
      -o jsonpath='{range .items[?(@.spec.subject.name=="'"$subjectName"'")]}{.metadata.name}{"\t"}{.spec.type}{"\n"}{end}' 2>/dev/null \
      | awk -v t="$seType" '$2==t{print $1; exit}')
    if [ -n "$name" ]; then
      fail "unexpected SE $seType for subject $subjectName: $name"
    fi
    sleep 1
  done
}

# --- Test 1: high-risk MWC -------------------------------------------
info "Test 1: high-risk MWC (failurePolicy=Ignore + secrets) → MutatingWebhookHighRisk SE"
apply_mwc "$HIGH_MWC" Ignore None '"secrets"'

high_se=$(wait_for_se "MutatingWebhookHighRisk" "$HIGH_MWC" 60) \
  || fail "MutatingWebhookHighRisk SE never emitted for $HIGH_MWC"
score=$(kubectl get securityevent "$high_se" -o jsonpath='{.spec.signals.risk_score}')
[ -n "$score" ] || fail "SE $high_se missing risk_score signal"
pass "high-risk MWC → SE $high_se (score=$score)"

# Sub-score WebhookFailOpenCriticalAPI must also fire.
sub_se=$(wait_for_se "WebhookFailOpenCriticalAPI" "$HIGH_MWC" 30) \
  || fail "WebhookFailOpenCriticalAPI sub-score SE never emitted"
pass "sub-score SE → $sub_se"

# --- Test 2: clean VWC, only sub-score CA-untrusted fires ------------
info "Test 2: sub-threshold VWC (Fail/None on pods, empty caBundle) → only WebhookCAUntrusted"
apply_vwc "$CLEAN_VWC" Fail None '"pods"'

ca_se=$(wait_for_se "WebhookCAUntrusted" "$CLEAN_VWC" 60) \
  || fail "WebhookCAUntrusted SE never emitted for $CLEAN_VWC"
pass "ca_untrusted sub-score → SE $ca_se"

# Top-level *HighRisk must NOT fire.
assert_no_se "ValidatingWebhookHighRisk" "$CLEAN_VWC" 3
pass "no top-level *HighRisk SE for sub-threshold VWC"

# --- Test 3: ignore-policy match -------------------------------------
info "Test 3: ignore-policy match (ugallu.* glob) skips evaluation"
apply_mwc "$IGNORED_MWC" Ignore None '"secrets"'

assert_no_se "MutatingWebhookHighRisk" "$IGNORED_MWC" 5
assert_no_se "WebhookCAUntrusted" "$IGNORED_MWC" 1
pass "ignored MWC produced no SE"

echo
echo "${GREEN}All 3 webhook-auditor smoke tests passed.${NC}"
