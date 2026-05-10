#!/usr/bin/env bash
# E2E smoke test for ugallu admission policies and CRD lifecycle.
#
# Assumes a kind / kubectl context already pointed at a cluster with
# CRDs + admission policies + control-plane placeholders applied.
#
# Run locally:
#   bash hack/e2e-smoke.sh
#
# Each test is wrapped in a function that exits non-zero on first
# unexpected outcome. The script `set -e`s so the first failure aborts.

set -euo pipefail

GREEN=$'\033[0;32m'
RED=$'\033[0;31m'
YELLOW=$'\033[1;33m'
NC=$'\033[0m'

pass() { echo "${GREEN}PASS${NC} $*"; }
fail() { echo "${RED}FAIL${NC} $*" >&2; exit 1; }
info() { echo "${YELLOW}==>${NC} $*"; }

# --- Test 1: Create a valid SecurityEvent (should succeed) ---------------
info "Test 1: create valid SecurityEvent"
cat <<'EOF' | kubectl apply -f - >/dev/null
apiVersion: security.ugallu.io/v1alpha1
kind: SecurityEvent
metadata:
  name: smoke-valid-1
spec:
  class: Detection
  type: PrivilegedPodChange
  severity: high
  clusterIdentity:
    clusterName: ci
    clusterID: ci-cluster
  source:
    kind: Controller
    name: smoke
  subject:
    kind: Pod
    name: target-pod
    namespace: default
    uid: abc-123
    pod:
      nodeName: node1
      serviceAccountName: default
  detectedAt: "2026-04-26T10:00:00Z"
EOF
pass "valid SecurityEvent created"

# --- Test 2: Mutate Spec (should be denied by Policy 1) ------------------
info "Test 2: Spec mutation must be denied"
if out=$(kubectl patch securityevent smoke-valid-1 \
                  --type=merge -p '{"spec":{"severity":"low"}}' 2>&1); then
  fail "Policy 1 did not deny Spec mutation; got: $out"
fi
echo "$out" | grep -q "Spec is immutable" \
  || fail "expected 'Spec is immutable' message, got: $out"
pass "Policy 1 denied Spec mutation"

# --- Test 3: SubjectKind / discriminator mismatch -----------------------
info "Test 3: discriminator mismatch must be denied"
if out=$(cat <<'EOF' | kubectl apply -f - 2>&1
apiVersion: security.ugallu.io/v1alpha1
kind: SecurityEvent
metadata:
  name: smoke-bad-discriminator
spec:
  class: Detection
  type: HostPathMount
  severity: medium
  clusterIdentity:
    clusterName: ci
  source: { kind: Controller, name: smoke }
  subject:
    kind: Node
    name: target-node
    pod: { nodeName: x }
  detectedAt: "2026-04-26T10:00:00Z"
EOF
); then
  fail "Policy 2 did not deny discriminator mismatch; got: $out"
fi
echo "$out" | grep -q "must match a populated discriminator" \
  || fail "expected discriminator denial, got: $out"
pass "Policy 2 denied discriminator mismatch"

# --- Test 4: Uncatalogued Type ------------------------------------------
info "Test 4: uncatalogued Type must be denied"
if out=$(cat <<'EOF' | kubectl apply -f - 2>&1
apiVersion: security.ugallu.io/v1alpha1
kind: SecurityEvent
metadata:
  name: smoke-bad-type
spec:
  class: Detection
  type: NonExistentType
  severity: low
  clusterIdentity: { clusterName: ci }
  source: { kind: Controller, name: smoke }
  subject:
    kind: Cluster
    name: ci
    cluster: { clusterID: ci }
  detectedAt: "2026-04-26T10:00:00Z"
EOF
); then
  fail "Policy 5 did not deny uncatalogued Type; got: $out"
fi
echo "$out" | grep -q "not in the curated catalog" \
  || fail "expected catalog denial, got: $out"
pass "Policy 5 denied uncatalogued Type"

# --- Test 5: Same uncatalogued Type with experimental label ------------
info "Test 5: experimental label opt-out must be allowed"
cat <<'EOF' | kubectl apply -f - >/dev/null
apiVersion: security.ugallu.io/v1alpha1
kind: SecurityEvent
metadata:
  name: smoke-experimental
  labels:
    ugallu.io/type-experimental: "true"
spec:
  class: Detection
  type: NonExistentType
  severity: low
  clusterIdentity: { clusterName: ci }
  source: { kind: Controller, name: smoke }
  subject:
    kind: Cluster
    name: ci
    cluster: { clusterID: ci }
  detectedAt: "2026-04-26T10:00:00Z"
EOF
pass "experimental opt-out accepted"

# --- Test 6: Status.Acknowledged=true without authorized SA -----------
info "Test 6: ack=true must be denied (no authorized SA configured)"
if out=$(kubectl patch securityevent smoke-valid-1 \
                  --subresource=status --type=merge \
                  -p '{"status":{"acknowledged":true}}' 2>&1); then
  fail "Policy 4 did not deny Acknowledged=true; got: $out"
fi
echo "$out" | grep -q "requires an authorized ServiceAccount" \
  || fail "expected ack denial, got: $out"
pass "Policy 4 denied Acknowledged=true"

# --- Test 7: Status update without ack (should succeed) ---------------
info "Test 7: status update without ack must be allowed"
kubectl patch securityevent smoke-valid-1 \
        --subresource=status --type=merge \
        -p '{"status":{"phase":"Active"}}' >/dev/null
phase=$(kubectl get securityevent smoke-valid-1 -o jsonpath='{.status.phase}')
if [ "$phase" != "Active" ]; then
  fail "expected status.phase=Active, got: $phase"
fi
pass "Test 7 status update accepted"

# --- Cleanup -----------------------------------------------------------
info "Cleanup"
kubectl delete securityevent smoke-valid-1 smoke-experimental --ignore-not-found >/dev/null
pass "cleanup complete"

echo
echo "${GREEN}All 7 smoke tests passed.${NC}"
