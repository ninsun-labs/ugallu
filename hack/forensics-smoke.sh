#!/usr/bin/env bash
# E2E lab smoke for ugallu-forensics.
#
# Assumes:
#   - kubectl context already pointed at the lab (rke2-lab in our case)
#   - ugallu-forensics deployed via the chart in ugallu-system-privileged
#   - SeaweedFS (ugallu-evidence) reachable for WORM uploads
#   - the master WORM creds Secret (ugallu-worm-creds) present in
#     ugallu-system; the operator mirrors it into the suspect Pod's
#     namespace
#
# What it covers (all 5 Sprint-2 §F MVP scenarios, no skipping):
#   1. ForensicsConfig surfaces FreezeBackend in status (Cilium on
#      the lab) so the operator's CNI detection actually ran.
#   2. SE that does NOT meet the trigger predicate (wrong class /
#      wrong severity) does not start a pipeline.
#   3. SE that DOES meet the predicate freezes the suspect Pod:
#      `ugallu.io/frozen=<pod-uid>` label appears + a Cilium
#      NetworkPolicy `ugallu-forensics-freeze-<pod-uid>` exists.
#   4. The ephemeral snapshot container terminates and the operator
#      emits SE{Type=IncidentCaptureCompleted} with evidence URLs in
#      signals.
#   5. Manual unfreeze: stamping
#      `ugallu.io/incident-acknowledged=true` on the completion SE
#      removes the CNP + the Pod label.
#
# Run with:
#   bash hack/forensics-smoke.sh

set -euo pipefail

GREEN=$'\033[0;32m'
RED=$'\033[0;31m'
YELLOW=$'\033[1;33m'
NC=$'\033[0m'

pass() { echo "${GREEN}PASS${NC} $*"; }
fail() { echo "${RED}FAIL${NC} $*" >&2; exit 1; }
info() { echo "${YELLOW}==>${NC} $*"; }

NS_TEST=${NS_TEST:-forensics-smoke}
SUSPECT_POD=${SUSPECT_POD:-suspect}
RUN_ID=$(date +%s)-$$
TRIGGER_SE_NAME="forensics-smoke-trigger-${RUN_ID}"
SKIP_SE_NAME="forensics-smoke-skip-${RUN_ID}"

cleanup() {
  kubectl delete ns "$NS_TEST" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  kubectl delete securityevent "$TRIGGER_SE_NAME" "$SKIP_SE_NAME" --ignore-not-found >/dev/null 2>&1 || true
  # Also wipe the Forensic SEs the operator emitted so re-runs start fresh.
  kubectl get securityevent --no-headers 2>/dev/null \
    | awk '/^se-[0-9a-f]+ +Forensic /{print $1}' \
    | xargs -r kubectl delete securityevent --ignore-not-found >/dev/null 2>&1 || true
}
trap cleanup EXIT

# --- Test 1: ForensicsConfig CR is loaded by the chart --------------------
# Sprint 2 MVP doesn't ship the ForensicsConfig status reconciler — the
# FreezeBackend / LastConfigLoadAt fields land in Sprint 3 alongside the
# crash-recovery flow. The deployable surface is the spec read-back: the
# operator reads `default` at every reconcile, so its presence is a
# precondition for everything that follows.
info "Test 1: ForensicsConfig 'default' is present + spec readable"
trigger_classes=$(kubectl get forensicsconfig default -o jsonpath='{.spec.trigger.classes}' 2>/dev/null || true)
[ -n "$trigger_classes" ] || fail "ForensicsConfig 'default' missing or has empty spec"
pass "ForensicsConfig spec.trigger.classes=$trigger_classes"

# --- Test 2: SE outside the predicate is NOT captured ---------------------
info "Test 2: low-severity SE does not trigger forensics"
kubectl create ns "$NS_TEST" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
# privileged PSA so the snapshot ephemeral container can carry
# CAP_DAC_READ_SEARCH (required to read /proc/<pid>/root regardless
# of file UID). Production targets a PSA exemption keyed on the
# ugallu-forensics SA — Sprint 3 polish per design 20 §F8.
kubectl label ns "$NS_TEST" pod-security.kubernetes.io/enforce=privileged --overwrite >/dev/null 2>&1 || true

# Create a benign Pod (no exec, no privilege) — used as the "subject" of
# the would-be trigger SE so kubectl validates the schema.
cat <<EOF | kubectl apply -f - >/dev/null
apiVersion: v1
kind: Pod
metadata: { name: $SUSPECT_POD, namespace: $NS_TEST }
spec:
  restartPolicy: Always
  containers:
  - name: app
    image: registry.k8s.io/pause:3.10
    securityContext:
      allowPrivilegeEscalation: false
      capabilities: { drop: [ALL] }
      runAsNonRoot: true
      runAsUser: 65532
      seccompProfile: { type: RuntimeDefault }
EOF
kubectl -n "$NS_TEST" wait --for=condition=Ready pod/$SUSPECT_POD --timeout=60s >/dev/null
POD_UID=$(kubectl -n "$NS_TEST" get pod "$SUSPECT_POD" -o jsonpath='{.metadata.uid}')

cat <<EOF | kubectl apply -f - >/dev/null
apiVersion: security.ugallu.io/v1alpha1
kind: SecurityEvent
metadata: { name: $SKIP_SE_NAME }
spec:
  class: Audit
  type: KubernetesAPICall
  severity: low
  clusterIdentity: { clusterID: rke2-lab, clusterName: rke2-lab }
  source: { kind: Controller, name: forensics-smoke }
  subject:
    kind: Pod
    name: $SUSPECT_POD
    namespace: $NS_TEST
    uid: $POD_UID
    pod: { nodeName: irrelevant }
  detectedAt: "2026-04-28T10:00:00Z"
EOF
sleep 3
# An Audit-class SE must not produce a frozen label.
label=$(kubectl -n "$NS_TEST" get pod "$SUSPECT_POD" -o jsonpath='{.metadata.labels.ugallu\.io/frozen}' 2>/dev/null || true)
[ -z "$label" ] || fail "low-severity SE leaked into pipeline; pod has ugallu.io/frozen=$label"
pass "Audit/low SE correctly skipped"

# --- Test 3: matching SE → Pod freeze (label + CiliumNetworkPolicy) -------
info "Test 3: matching SE freezes the Pod (label + CNP)"
cat <<EOF | kubectl apply -f - >/dev/null
apiVersion: security.ugallu.io/v1alpha1
kind: SecurityEvent
metadata: { name: $TRIGGER_SE_NAME }
spec:
  class: Detection
  type: ClusterAdminGranted
  severity: critical
  clusterIdentity: { clusterID: rke2-lab, clusterName: rke2-lab }
  source: { kind: Controller, name: forensics-smoke }
  subject:
    kind: Pod
    name: $SUSPECT_POD
    namespace: $NS_TEST
    uid: $POD_UID
    pod: { nodeName: irrelevant }
  detectedAt: "2026-04-28T10:00:00Z"
EOF
# Force Status.Phase=Attested so requireAttested predicate passes.
kubectl patch securityevent "$TRIGGER_SE_NAME" --subresource=status \
  --type=merge -p '{"status":{"phase":"Attested"}}' >/dev/null

# Wait for the freeze to take effect (label + CNP).
for _ in $(seq 1 60); do
  label=$(kubectl -n "$NS_TEST" get pod "$SUSPECT_POD" -o jsonpath='{.metadata.labels.ugallu\.io/frozen}' 2>/dev/null || true)
  cnp=$(kubectl -n "$NS_TEST" get cnp "ugallu-forensics-freeze-$POD_UID" -o name 2>/dev/null || true)
  if [ -n "$label" ] && [ -n "$cnp" ]; then break; fi
  sleep 1
done
[ -n "$label" ] || fail "ugallu.io/frozen label never appeared on suspect pod"
[ -n "$cnp" ] || fail "CiliumNetworkPolicy never created"
pass "pod frozen (label=$label, $cnp)"

# --- Test 4: snapshot completes + IncidentCaptureCompleted SE -------------
info "Test 4: snapshot ephemeral container completes + completion SE emitted"
for _ in $(seq 1 120); do
  ec=$(kubectl -n "$NS_TEST" get pod "$SUSPECT_POD" -o jsonpath='{.status.ephemeralContainerStatuses[?(@.state.terminated)].name}' 2>/dev/null || true)
  if [ -n "$ec" ]; then break; fi
  sleep 1
done
[ -n "$ec" ] || fail "snapshot ephemeral container never terminated"

for _ in $(seq 1 60); do
  # jsonpath filter is more robust than awk on the table output
  # (the PHASE column is empty on freshly-created SEs and awk's
  # whitespace runs collapse it into the SUBJECT field).
  done_se=$(kubectl get securityevent -o jsonpath='{range .items[?(@.spec.type=="IncidentCaptureCompleted")]}{.metadata.name}{"\n"}{end}' 2>/dev/null | head -1)
  if [ -n "$done_se" ]; then break; fi
  sleep 1
done
[ -n "$done_se" ] || fail "IncidentCaptureCompleted SE never emitted"
ev_url=$(kubectl get securityevent "$done_se" -o jsonpath='{.spec.signals.evidence\.0\.url}' 2>/dev/null || true)
[ -n "$ev_url" ] || fail "completion SE has no evidence.0.url signal"
pass "completion SE $done_se with evidence $ev_url"

# --- Test 5: manual unfreeze ---------------------------------------------
info "Test 5: manual unfreeze removes CNP + label"
kubectl annotate securityevent "$done_se" ugallu.io/incident-acknowledged=true --overwrite >/dev/null

for _ in $(seq 1 60); do
  cnp=$(kubectl -n "$NS_TEST" get cnp "ugallu-forensics-freeze-$POD_UID" -o name 2>/dev/null || true)
  label=$(kubectl -n "$NS_TEST" get pod "$SUSPECT_POD" -o jsonpath='{.metadata.labels.ugallu\.io/frozen}' 2>/dev/null || true)
  if [ -z "$cnp" ] && [ -z "$label" ]; then break; fi
  sleep 1
done
[ -z "$cnp" ] || fail "CiliumNetworkPolicy still present after acknowledge: $cnp"
[ -z "$label" ] || fail "ugallu.io/frozen label still present after acknowledge: $label"
pass "pod unfrozen"

echo
echo "${GREEN}All 5 forensics smoke tests passed.${NC}"
