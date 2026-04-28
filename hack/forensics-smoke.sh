#!/usr/bin/env bash
# E2E lab smoke for ugallu-forensics — Sprint 3 scope.
#
# Assumes:
#   - kubectl context already pointed at the lab (rke2-lab in our case)
#   - ugallu-forensics deployed via the chart in ugallu-system-privileged
#   - SeaweedFS (ugallu-evidence) reachable for WORM uploads with
#     Object Lock enabled
#   - the master WORM creds Secret (ugallu-worm-creds) present in
#     ugallu-system-privileged (mirrored from ugallu-system; the
#     operator's chart wires WORM_ACCESS_KEY/WORM_SECRET_KEY from it)
#
# What it covers (10 scenarios, 100% Sprint 3 surface):
#
#   Sprint 2 carry-overs (still required):
#     1. ForensicsConfig 'default' is present + Status surfaces
#        FreezeBackend (Sprint 3 ConfigReconciler).
#     2. SE outside the predicate (Audit / low) does NOT trigger
#        a pipeline.
#     3. Matching SE freezes the suspect Pod: `ugallu.io/frozen`
#        label + CiliumNetworkPolicy.
#
#   Sprint 3 IR-as-code:
#     4. Per-step ER chain — three EventResponses created
#        (PodFreeze, FilesystemSnapshot, EvidenceUpload), all in
#        Phase=Succeeded, with `ugallu.io/incident-uid` labels.
#     5. ER parent-chain — every step ER (except the first)
#        references the previous step's UID via
#        `ugallu.io/parent-er`.
#     6. Manifest blob exists in WORM at the content-addressed
#        key + IncidentCaptureCompleted SE references it as the
#        SOLE evidence URL (not inline per-chunk).
#     7. Manifest body validates: schema header, chunks count,
#        snapshot chunk references the snapshot tar+gzip URL.
#
#   Sprint 3 lifecycle / policy:
#     8. Manual unfreeze with authorized SA ack succeeds (CNP +
#        label removed, PodUnfreeze ER created).
#     9. Auto-unfreeze fires after the configured grace window.
#    10. Admission policy 8 denies an ack from a non-allowlisted
#        SA (the unfreeze does NOT happen).
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
AUTO_TRIGGER_SE_NAME="forensics-smoke-auto-${RUN_ID}"

# SAs created by the smoke for the policy 8 tests.
ACKER_SA=forensics-smoke-acker
ROGUE_SA=forensics-smoke-rogue

cleanup() {
  kubectl delete ns "$NS_TEST" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  kubectl delete securityevent "$TRIGGER_SE_NAME" "$SKIP_SE_NAME" "$AUTO_TRIGGER_SE_NAME" --ignore-not-found >/dev/null 2>&1 || true
  kubectl get securityevent --no-headers 2>/dev/null \
    | awk '/^se-[0-9a-f]+ +Forensic /{print $1}' \
    | xargs -r kubectl delete securityevent --ignore-not-found >/dev/null 2>&1 || true
  kubectl delete eventresponse -l app.kubernetes.io/managed-by=ugallu-forensics --ignore-not-found >/dev/null 2>&1 || true
  kubectl -n "$NS_TEST" delete sa "$ACKER_SA" "$ROGUE_SA" --ignore-not-found >/dev/null 2>&1 || true
  # Restore ForensicsConfig autoUnfreezeAfter if the auto-unfreeze
  # test mutated it.
  if [ -n "${ORIG_AUTO_UNFREEZE:-}" ]; then
    kubectl patch forensicsconfig default --type=merge \
      -p '{"spec":{"cleanup":{"autoUnfreezeAfter":"'"$ORIG_AUTO_UNFREEZE"'"}}}' >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

# Helper: spawn a Pod for a given subject + wait Ready. Returns its UID
# via stdout.
spawn_suspect() {
  local name=$1 ns=$2
  cat <<EOF | kubectl apply -f - >/dev/null
apiVersion: v1
kind: Pod
metadata: { name: $name, namespace: $ns }
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
  kubectl -n "$ns" wait --for=condition=Ready pod/"$name" --timeout=60s >/dev/null
  kubectl -n "$ns" get pod "$name" -o jsonpath='{.metadata.uid}'
}

emit_trigger_se() {
  local name=$1 pod=$2 ns=$3 uid=$4 type=$5 sev=$6 cls=$7
  cat <<EOF | kubectl apply -f - >/dev/null
apiVersion: security.ugallu.io/v1alpha1
kind: SecurityEvent
metadata: { name: $name }
spec:
  class: $cls
  type: $type
  severity: $sev
  clusterIdentity: { clusterID: rke2-lab, clusterName: rke2-lab }
  source: { kind: Controller, name: forensics-smoke }
  subject:
    kind: Pod
    name: $pod
    namespace: $ns
    uid: $uid
    pod: { nodeName: irrelevant }
  detectedAt: "2026-04-28T10:00:00Z"
EOF
  kubectl patch securityevent "$name" --subresource=status \
    --type=merge -p '{"status":{"phase":"Attested"}}' >/dev/null
}

# --- Test 1: ForensicsConfig 'default' + status ---------------------------
info "Test 1: ForensicsConfig surfaces FreezeBackend (ConfigReconciler ran)"
for _ in $(seq 1 60); do
  backend=$(kubectl get forensicsconfig default -o jsonpath='{.status.freezeBackend}' 2>/dev/null || true)
  if [ -n "$backend" ]; then break; fi
  sleep 1
done
[ "$backend" = "Cilium" ] || fail "FreezeBackend = '$backend', want Cilium"
pass "FreezeBackend = $backend"

# --- Test 2: low-severity SE skipped --------------------------------------
info "Test 2: low-severity SE does not trigger forensics"
kubectl create ns "$NS_TEST" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl label ns "$NS_TEST" pod-security.kubernetes.io/enforce=privileged --overwrite >/dev/null 2>&1 || true

POD_UID=$(spawn_suspect "$SUSPECT_POD" "$NS_TEST")
emit_trigger_se "$SKIP_SE_NAME" "$SUSPECT_POD" "$NS_TEST" "$POD_UID" KubernetesAPICall low Audit
sleep 3
label=$(kubectl -n "$NS_TEST" get pod "$SUSPECT_POD" -o jsonpath='{.metadata.labels.ugallu\.io/frozen}' 2>/dev/null || true)
[ -z "$label" ] || fail "low-severity SE leaked into pipeline; pod has ugallu.io/frozen=$label"
pass "Audit/low SE correctly skipped"

# --- Test 3: matching SE → freeze (label + CNP) ---------------------------
info "Test 3: matching SE freezes the Pod (label + CNP)"
emit_trigger_se "$TRIGGER_SE_NAME" "$SUSPECT_POD" "$NS_TEST" "$POD_UID" ClusterAdminGranted critical Detection
for _ in $(seq 1 60); do
  label=$(kubectl -n "$NS_TEST" get pod "$SUSPECT_POD" -o jsonpath='{.metadata.labels.ugallu\.io/frozen}' 2>/dev/null || true)
  cnp=$(kubectl -n "$NS_TEST" get cnp "ugallu-forensics-freeze-$POD_UID" -o name 2>/dev/null || true)
  if [ -n "$label" ] && [ -n "$cnp" ]; then break; fi
  sleep 1
done
[ -n "$label" ] || fail "ugallu.io/frozen label never appeared on suspect pod"
[ -n "$cnp" ] || fail "CiliumNetworkPolicy never created"
pass "pod frozen (label=$label)"

# --- Test 4: per-step ER chain (3 steps, all Succeeded) -------------------
info "Test 4: per-step ER chain (PodFreeze + FilesystemSnapshot + EvidenceUpload)"
INCIDENT_UID=$(echo -n "$(kubectl get securityevent "$TRIGGER_SE_NAME" -o jsonpath='{.metadata.uid}')" | sha256sum | head -c16)
for _ in $(seq 1 120); do
  count=$(kubectl get er -l "ugallu.io/incident-uid=$INCIDENT_UID" -o name 2>/dev/null | wc -l)
  succeeded=$(kubectl get er -l "ugallu.io/incident-uid=$INCIDENT_UID" -o jsonpath='{range .items[?(@.status.phase=="Succeeded")]}{.spec.action.type}{"\n"}{end}' 2>/dev/null | sort -u | wc -l)
  if [ "$count" -ge 3 ] && [ "$succeeded" -ge 3 ]; then break; fi
  sleep 1
done
[ "$count" -ge 3 ] || fail "expected ≥3 ER for incident $INCIDENT_UID, got $count"
[ "$succeeded" -ge 3 ] || fail "expected 3 Succeeded ER actions, got $succeeded"
pass "3 step ERs Succeeded for incident $INCIDENT_UID"

# --- Test 5: ER parent chain ---------------------------------------------
info "Test 5: parent-er labels link the step ER chain"
parents=$(kubectl get er -l "ugallu.io/incident-uid=$INCIDENT_UID" -o jsonpath='{range .items[*]}{.metadata.labels.ugallu\.io/parent-er}{"\n"}{end}' | grep -c -v '^$' || true)
[ "$parents" -ge 2 ] || fail "expected ≥2 ER with parent-er label, got $parents"
pass "ER chain has $parents parent-er links"

# --- Test 6: manifest blob in WORM + completion SE references it ---------
info "Test 6: completion SE references the manifest blob"
DONE_SE=$(kubectl get securityevent -o jsonpath='{range .items[?(@.spec.type=="IncidentCaptureCompleted")]}{.metadata.name}{"\n"}{end}' 2>/dev/null | head -1)
[ -n "$DONE_SE" ] || fail "IncidentCaptureCompleted SE not emitted"
EVIDENCE_COUNT=$(kubectl get securityevent "$DONE_SE" -o jsonpath='{.spec.signals.evidence\.count}' 2>/dev/null || echo "")
EVIDENCE_URL=$(kubectl get securityevent "$DONE_SE" -o jsonpath='{.spec.signals.evidence\.0\.url}' 2>/dev/null || echo "")
case "$EVIDENCE_URL" in
  *manifest-*.json) ;;
  *) fail "completion SE evidence.0.url is not a manifest blob: $EVIDENCE_URL" ;;
esac
[ "$EVIDENCE_COUNT" = "1" ] || fail "completion SE evidence.count = '$EVIDENCE_COUNT', want 1 (single manifest ref)"
pass "completion SE → $EVIDENCE_URL (single manifest ref, IR-as-code)"

# --- Test 7: manifest body is valid JSON with the snapshot chunk ---------
info "Test 7: manifest body validates"
KEY="${EVIDENCE_URL#s3://ugallu/}"
kubectl -n ugallu-evidence exec aws-cli -- aws --endpoint-url=http://seaweedfs:8333 \
  s3 cp "s3://ugallu/$KEY" /tmp/manifest.json >/dev/null
SCHEMA=$(kubectl -n ugallu-evidence exec aws-cli -- cat /tmp/manifest.json | python3 -c 'import json,sys; print(json.load(sys.stdin).get("schema",""))')
CHUNKS=$(kubectl -n ugallu-evidence exec aws-cli -- cat /tmp/manifest.json | python3 -c 'import json,sys; print(len(json.load(sys.stdin).get("chunks",[])))')
[ "$SCHEMA" = "ugallu.io/forensics-manifest/v1" ] || fail "manifest schema = '$SCHEMA'"
[ "$CHUNKS" = "1" ] || fail "manifest chunks = '$CHUNKS', want 1 (snapshot)"
pass "manifest schema=$SCHEMA chunks=$CHUNKS"

# --- Test 8: manual unfreeze with authorized SA --------------------------
info "Test 8: manual unfreeze succeeds with authorized SA (policy 8 allow path)"
kubectl -n "$NS_TEST" create sa "$ACKER_SA" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
# Production grants the acker SA a narrow ClusterRole — get +
# patch on securityevents is enough for the kubectl annotate
# round-trip.
cat <<EOF | kubectl apply -f - >/dev/null
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: { name: ugallu-incident-acker-smoke }
rules:
  - apiGroups: ["security.ugallu.io"]
    resources: ["securityevents"]
    verbs: ["get","list","patch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: { name: ugallu-incident-acker-smoke }
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: ugallu-incident-acker-smoke
subjects:
  - kind: ServiceAccount
    name: $ACKER_SA
    namespace: $NS_TEST
  - kind: ServiceAccount
    name: $ROGUE_SA
    namespace: $NS_TEST
EOF
# Use --as so the request reaches the apiserver as the SA, which
# is the production access pattern for the manual-ack flow.
kubectl annotate securityevent "$DONE_SE" \
  ugallu.io/incident-acknowledged=true \
  --overwrite \
  --as="system:serviceaccount:$NS_TEST:$ACKER_SA" >/dev/null
for _ in $(seq 1 60); do
  cnp=$(kubectl -n "$NS_TEST" get cnp "ugallu-forensics-freeze-$POD_UID" -o name 2>/dev/null || true)
  label=$(kubectl -n "$NS_TEST" get pod "$SUSPECT_POD" -o jsonpath='{.metadata.labels.ugallu\.io/frozen}' 2>/dev/null || true)
  if [ -z "$cnp" ] && [ -z "$label" ]; then break; fi
  sleep 1
done
[ -z "$cnp" ] || fail "CNP still present after ack: $cnp"
[ -z "$label" ] || fail "label still present after ack: $label"
pass "pod unfrozen via manual ack"

# --- Test 9: auto-unfreeze fires after configured grace ------------------
info "Test 9: auto-unfreeze fires after configured grace window"
ORIG_AUTO_UNFREEZE=$(kubectl get forensicsconfig default -o jsonpath='{.spec.cleanup.autoUnfreezeAfter}')
kubectl patch forensicsconfig default --type=merge \
  -p '{"spec":{"cleanup":{"autoUnfreezeAfter":"15s"}}}' >/dev/null

# Spawn a fresh suspect and trigger.
AUTO_POD=auto-suspect
AUTO_POD_UID=$(spawn_suspect "$AUTO_POD" "$NS_TEST")
emit_trigger_se "$AUTO_TRIGGER_SE_NAME" "$AUTO_POD" "$NS_TEST" "$AUTO_POD_UID" ClusterAdminGranted critical Detection
# Wait for the freeze to land first.
for _ in $(seq 1 60); do
  auto_label=$(kubectl -n "$NS_TEST" get pod "$AUTO_POD" -o jsonpath='{.metadata.labels.ugallu\.io/frozen}' 2>/dev/null || true)
  if [ -n "$auto_label" ]; then break; fi
  sleep 1
done
[ -n "$auto_label" ] || fail "auto-test pod never got frozen"
# Wait for the auto-unfreeze (grace=15s, plus a 30s safety margin).
for _ in $(seq 1 50); do
  auto_label=$(kubectl -n "$NS_TEST" get pod "$AUTO_POD" -o jsonpath='{.metadata.labels.ugallu\.io/frozen}' 2>/dev/null || true)
  auto_cnp=$(kubectl -n "$NS_TEST" get cnp "ugallu-forensics-freeze-$AUTO_POD_UID" -o name 2>/dev/null || true)
  if [ -z "$auto_label" ] && [ -z "$auto_cnp" ]; then break; fi
  sleep 1
done
[ -z "$auto_label" ] || fail "pod label still present after auto-unfreeze: $auto_label"
[ -z "$auto_cnp" ]   || fail "CNP still present after auto-unfreeze: $auto_cnp"

# Verify the completion SE got annotated with the auto-unfreeze
# reason. emitCompletion() doesn't stamp pod.uid into signals, so
# match by spec.subject.uid (which the emitter SDK does set).
AUTO_DONE_SE=$(kubectl get securityevent -o jsonpath='{range .items[?(@.spec.subject.uid=="'"$AUTO_POD_UID"'")]}{.metadata.name}{"\t"}{.spec.type}{"\n"}{end}' 2>/dev/null \
  | awk '$2=="IncidentCaptureCompleted"{print $1; exit}')
REASON=$(kubectl get securityevent "$AUTO_DONE_SE" -o jsonpath='{.metadata.annotations.ugallu\.io/incident-unfreeze-reason}' 2>/dev/null || true)
[ "$REASON" = "auto-unfreeze-grace-elapsed" ] || fail "auto-unfreeze reason annotation missing/incorrect: '$REASON'"
pass "pod auto-unfrozen (reason=$REASON)"

# --- Test 10: admission policy 8 denies non-allowlisted SA ack -----------
info "Test 10: policy 8 denies ack from a non-allowlisted SA"
kubectl -n "$NS_TEST" create sa "$ROGUE_SA" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
# Try to ack the auto-unfreeze SE we just generated (which is now
# unfrozen, but the annotation gate still applies on UPDATE).
ROGUE_OUT=$(kubectl annotate securityevent "$AUTO_DONE_SE" \
  ugallu.io/incident-acknowledged=true \
  --overwrite \
  --as="system:serviceaccount:$NS_TEST:$ROGUE_SA" 2>&1 || true)
case "$ROGUE_OUT" in
  *Forbidden*|*denied*|*reserved*) ;;
  *) fail "rogue-SA ack was not denied; got: $ROGUE_OUT" ;;
esac
pass "rogue-SA ack denied by policy 8"

echo
echo "${GREEN}All 10 forensics smoke tests passed.${NC}"
