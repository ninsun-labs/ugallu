#!/usr/bin/env bash
# End-to-end real-chain smoke.
#
# Exercises the FULL pipeline with no manual Status.Phase=Attested
# patch - everything is driven by the live operators:
#
#   audit-detection (Sigma engine + webhook)
#       ⇣ POST audit event
#   SecurityEvent  (Detection / PrivilegedPodChange / critical)
#       ⇣ ugallu-attestor watches it
#   AttestationBundle  (signed via OpenBao transit / Rekor / WORM)
#       ⇣ markParentAttested
#   SecurityEvent.Status.Phase = Attested
#       ⇣ forensics predicate (requireAttested=true)
#   IR-as-code pipeline:
#       PodFreezeStep            → ER (parent: SE)
#       FilesystemSnapshotStep   → ER (parent: previous)
#       EvidenceUploadStep       → ER + manifest blob in WORM
#   IncidentCaptureCompleted SE
#       ⇣ ack annotation by authorized SA (policy 8 allow path)
#   PodUnfreezeStep              → CNP + label removed
#
# Assumptions (mirrors hack/audit-detection-smoke.sh + hack/forensics-smoke.sh):
#   - kubectl context already pointed at the lab
#   - ugallu-audit-detection running with the real binary, webhook
#     mode, the bearer-token Secret + TLS Secret in place
#   - ugallu-attestor running with the real binary, AttestorConfig
#     'default' wired (signing-mode + Rekor + WORM)
#   - ugallu-forensics running with the real binary,
#     ForensicsConfig 'default' configured with PrivilegedPodChange
#     in whitelistedTypes and requireAttested=true
#   - admission Policy 8 already allows the SA we use to ack
#     (default chart values list system:serviceaccount:forensics-smoke:forensics-smoke-acker)
#
# Total budget: 180s post-trigger. The script bails out as soon as any
# stage exceeds its sub-budget so a regression surfaces fast.
#
# Run with:
#   bash hack/wave2-smoke.sh

set -euo pipefail

GREEN=$'\033[0;32m'
RED=$'\033[0;31m'
YELLOW=$'\033[1;33m'
NC=$'\033[0m'

pass() { echo "${GREEN}PASS${NC} $*"; }
fail() { echo "${RED}FAIL${NC} $*" >&2; exit 1; }
info() { echo "${YELLOW}==>${NC} $*"; }

NS_SYS=${NS_SYS:-ugallu-system}
NS_TEST=${NS_TEST:-wave2-smoke}
SUSPECT_POD=${SUSPECT_POD:-suspect}
RUN_ID=$(date +%s)-$$
RULE=wave2-smoke-privileged-pod
AUDIT_ID=wave2-smoke-${RUN_ID}

# Reuse the SA already plumbed into Policy 8's allowlist by the lab
# helm values (forensicsAckAuthorizedSAs). The smoke recreates it +
# a narrow ClusterRoleBinding so the script is idempotent across
# clean labs and lab-with-prior-forensics-smoke alike.
ACKER_NS=forensics-smoke
ACKER_SA=forensics-smoke-acker

WEBHOOK_HOST=${WEBHOOK_HOST:-ugallu-audit-detection-webhook.${NS_SYS}.svc.cluster.local}
WEBHOOK_PORT=${WEBHOOK_PORT:-443}
WEBHOOK_PATH=${WEBHOOK_PATH:-/v1/audit}
WEBHOOK_SECRET_NAME=${WEBHOOK_SECRET_NAME:-ugallu-audit-webhook-token}
WEBHOOK_SVC_NAME=${WEBHOOK_SVC_NAME:-ugallu-audit-detection-webhook}

TOKEN=$(kubectl -n "$NS_SYS" get secret "$WEBHOOK_SECRET_NAME" -o jsonpath='{.data.token}' | base64 -d)
[ -n "$TOKEN" ] || fail "missing webhook token Secret $NS_SYS/$WEBHOOK_SECRET_NAME"
WEBHOOK_SVC_IP=$(kubectl -n "$NS_SYS" get svc "$WEBHOOK_SVC_NAME" -o jsonpath='{.spec.clusterIP}')
[ -n "$WEBHOOK_SVC_IP" ] || fail "Service $WEBHOOK_SVC_NAME has no ClusterIP"

cleanup() {
  kubectl delete sigmarule "$RULE" --ignore-not-found >/dev/null 2>&1 || true
  kubectl -n "$NS_SYS" delete job wave2-smoke-curl --ignore-not-found >/dev/null 2>&1 || true
  kubectl -n "$NS_SYS" delete configmap wave2-smoke-payload --ignore-not-found >/dev/null 2>&1 || true
  kubectl delete ns "$NS_TEST" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  kubectl delete clusterrolebinding wave2-smoke-acker --ignore-not-found >/dev/null 2>&1 || true
  kubectl delete clusterrole wave2-smoke-acker --ignore-not-found >/dev/null 2>&1 || true
  rm -f /tmp/wave2-smoke-body.json 2>/dev/null || true
  # Orphaned ERs / SEs from the run (best-effort).
  kubectl get securityevent --no-headers 2>/dev/null \
    | awk '/Forensic /{print $1}' \
    | xargs -r kubectl delete securityevent --ignore-not-found >/dev/null 2>&1 || true
  kubectl delete eventresponse -l ugallu.io/incident-uid="$INCIDENT_UID" --ignore-not-found >/dev/null 2>&1 || true
}
INCIDENT_UID="(unset)"
trap cleanup EXIT

# webhook_post: ship the audit event payload through a one-shot
# alpine/curl Job. Mirrors hack/audit-detection-smoke.sh - the
# payload travels via a ConfigMap so JSON quoting doesn't fight the
# YAML block scalar for the curl command, and the in-cluster Job
# bypasses the WARP TLS-inspect proxy that breaks host-side curl.
webhook_post() {
  local payload="$1"
  kubectl -n "$NS_SYS" delete job wave2-smoke-curl --ignore-not-found >/dev/null 2>&1 || true
  kubectl -n "$NS_SYS" delete configmap wave2-smoke-payload --ignore-not-found >/dev/null 2>&1 || true
  printf '%s' "$payload" > /tmp/wave2-smoke-body.json
  kubectl -n "$NS_SYS" create configmap wave2-smoke-payload \
    --from-file=body.json=/tmp/wave2-smoke-body.json >/dev/null
  cat <<EOF | kubectl -n "$NS_SYS" apply -f - >/dev/null
apiVersion: batch/v1
kind: Job
metadata:
  name: wave2-smoke-curl
spec:
  ttlSecondsAfterFinished: 60
  template:
    spec:
      restartPolicy: Never
      securityContext:
        runAsNonRoot: true
        runAsUser: 65532
        runAsGroup: 65532
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: curl
          image: alpine/curl:8.11.1
          env:
            - { name: TOKEN, value: "$TOKEN" }
          command: ["sh", "-c"]
          args:
            - |
              curl -sk -X POST \
                -H "Authorization: Bearer \$TOKEN" \
                -H "Content-Type: application/json" \
                --data @/payload/body.json \
                --resolve ${WEBHOOK_HOST}:${WEBHOOK_PORT}:${WEBHOOK_SVC_IP} \
                https://${WEBHOOK_HOST}:${WEBHOOK_PORT}${WEBHOOK_PATH}
          securityContext:
            allowPrivilegeEscalation: false
            capabilities:
              drop: ["ALL"]
          volumeMounts:
            - { name: payload, mountPath: /payload }
      volumes:
        - name: payload
          configMap:
            name: wave2-smoke-payload
EOF
  kubectl -n "$NS_SYS" wait --for=condition=complete --timeout=60s job/wave2-smoke-curl >/dev/null
}

# wait_for: poll a kubectl-driven condition up to N seconds. usage:
# wait_for "<message>" <max_secs> <bash command that exits 0 on ready>
wait_for() {
  local msg=$1 budget=$2; shift 2
  local i
  for i in $(seq 1 "$budget"); do
    if "$@" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  fail "$msg (after ${budget}s)"
}

# --- preflight ------------------------------------------------------------
info "preflight: SigmaRule on pods + privileged"
kubectl create ns "$NS_TEST" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl label ns "$NS_TEST" pod-security.kubernetes.io/enforce=privileged --overwrite >/dev/null

cat <<EOF | kubectl apply -f - >/dev/null
apiVersion: security.ugallu.io/v1alpha1
kind: SigmaRule
metadata:
  name: $RULE
spec:
  enabled: true
  description: "wave2 smoke: privileged pod create"
  match:
    objectRef:
      resource: ["pods"]
    requestObjectGlob:
      - jsonPath: "\$.spec.containers[*].securityContext.privileged"
        patterns: ["true"]
  emit:
    securityEventType: PrivilegedPodChange
    severity: critical
    class: Detection
  rateLimit:
    burst: 4
    sustainedPerSec: 2
EOF
wait_for "SigmaRule $RULE never went Compiled=True" 30 \
  bash -c "[ \"\$(kubectl get sigmarule $RULE -o jsonpath='{.status.conditions[?(@.type==\"Compiled\")].status}')\" = True ]"
pass "SigmaRule $RULE Compiled=True"

# --- spawn suspect Pod ----------------------------------------------------
info "spawn suspect Pod $NS_TEST/$SUSPECT_POD"
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
kubectl -n "$NS_TEST" wait --for=condition=Ready pod/"$SUSPECT_POD" --timeout=60s >/dev/null
POD_UID=$(kubectl -n "$NS_TEST" get pod "$SUSPECT_POD" -o jsonpath='{.metadata.uid}')
[ -n "$POD_UID" ] || fail "could not read suspect Pod UID"
pass "suspect Pod ready (uid=$POD_UID)"

# Mark t0 - every stage budget is measured from here.
T0=$(date +%s)

# --- stage 1: POST audit event → SE created -------------------------------
info "stage 1: POST audit event (auditID=$AUDIT_ID) → SecurityEvent created"
webhook_post "{
  \"items\": [{
    \"auditID\": \"$AUDIT_ID\",
    \"stage\": \"ResponseComplete\",
    \"verb\": \"create\",
    \"user\": {\"username\": \"system:serviceaccount:kube-system:wave2-smoke-bot\"},
    \"objectRef\": {
      \"apiVersion\": \"v1\",
      \"resource\": \"pods\",
      \"namespace\": \"$NS_TEST\",
      \"name\": \"$SUSPECT_POD\",
      \"uid\": \"$POD_UID\"
    },
    \"requestObject\": {
      \"spec\": {
        \"containers\": [{
          \"name\": \"evil\",
          \"image\": \"registry.k8s.io/pause:3.10\",
          \"securityContext\": {\"privileged\": true}
        }]
      }
    },
    \"stageTimestamp\": \"2026-04-28T10:00:00Z\"
  }]
}"

# Audit-detection's deterministic-name strategy: the SE name is
# derived from (correlationID, type, subjectUID). The smoke locates
# its SE by spec.type + spec.subject.uid (RUN_ID-scoped).
find_trigger_se() {
  kubectl get securityevent \
    -o jsonpath='{range .items[?(@.spec.subject.uid=="'"$POD_UID"'")]}{.metadata.name}{"\t"}{.spec.type}{"\n"}{end}' 2>/dev/null \
    | awk '$2=="PrivilegedPodChange"{print $1; exit}'
}
TRIGGER_SE=""
for _ in $(seq 1 30); do
  TRIGGER_SE=$(find_trigger_se)
  if [ -n "$TRIGGER_SE" ]; then break; fi
  sleep 1
done
[ -n "$TRIGGER_SE" ] || fail "audit-detection never emitted a PrivilegedPodChange SE for pod uid $POD_UID"
pass "trigger SE created: $TRIGGER_SE"

# --- stage 2: AttestationBundle Phase=Sealed ------------------------------
info "stage 2: ugallu-attestor seals the AttestationBundle"
BUNDLE_NAME="att-se-${TRIGGER_SE}"
wait_for "AttestationBundle $BUNDLE_NAME never reached Sealed" 90 \
  bash -c "[ \"\$(kubectl get attestationbundle $BUNDLE_NAME -o jsonpath='{.status.phase}' 2>/dev/null)\" = Sealed ]"
pass "AttestationBundle $BUNDLE_NAME Sealed"

# --- stage 3: SE.Status.Phase=Attested (no manual patch) ------------------
info "stage 3: attestor stamps SE.Status.Phase=Attested"
wait_for "SE $TRIGGER_SE never went Phase=Attested (chain broken at markParentAttested)" 30 \
  bash -c "[ \"\$(kubectl get securityevent $TRIGGER_SE -o jsonpath='{.status.phase}')\" = Attested ]"
pass "SE $TRIGGER_SE Phase=Attested (real attestor, no manual patch)"

# --- stage 4: forensics freezes the suspect Pod ---------------------------
info "stage 4: forensics requireAttested=true predicate fires → freeze"
INCIDENT_UID=$(echo -n "$(kubectl get securityevent "$TRIGGER_SE" -o jsonpath='{.metadata.uid}')" | sha256sum | head -c16)
wait_for "suspect Pod never got the ugallu.io/frozen label" 60 \
  bash -c "[ -n \"\$(kubectl -n $NS_TEST get pod $SUSPECT_POD -o jsonpath='{.metadata.labels.ugallu\\.io/frozen}')\" ]"
wait_for "freeze CNP never created for pod uid $POD_UID" 30 \
  bash -c "kubectl -n $NS_TEST get cnp ugallu-forensics-freeze-$POD_UID >/dev/null"
pass "suspect Pod frozen (incident-uid=$INCIDENT_UID)"

# --- stage 5: per-step ER chain Succeeded (3 steps) -----------------------
info "stage 5: per-step ER chain Succeeded"
wait_for "fewer than 3 ER actions reached Succeeded for incident $INCIDENT_UID" 90 \
  bash -c "[ \"\$(kubectl get er -l ugallu.io/incident-uid=$INCIDENT_UID -o jsonpath='{range .items[?(@.status.phase==\"Succeeded\")]}{.spec.action.type}{\"\\n\"}{end}' | sort -u | wc -l)\" -ge 3 ]"
pass "3 step ERs Succeeded (PodFreeze + FilesystemSnapshot + EvidenceUpload)"

# --- stage 6: IncidentCaptureCompleted SE references manifest -------------
info "stage 6: IncidentCaptureCompleted SE references content-addressed manifest"
DONE_SE=""
for _ in $(seq 1 30); do
  DONE_SE=$(kubectl get securityevent \
    -o jsonpath='{range .items[?(@.spec.subject.uid=="'"$POD_UID"'")]}{.metadata.name}{"\t"}{.spec.type}{"\n"}{end}' 2>/dev/null \
    | awk '$2=="IncidentCaptureCompleted"{print $1; exit}')
  if [ -n "$DONE_SE" ]; then break; fi
  sleep 1
done
[ -n "$DONE_SE" ] || fail "IncidentCaptureCompleted SE not emitted (pipeline never finished)"
EVIDENCE_URL=$(kubectl get securityevent "$DONE_SE" -o jsonpath='{.spec.signals.evidence\.0\.url}')
case "$EVIDENCE_URL" in
  *manifest-*.json) ;;
  *) fail "completion SE evidence.0.url is not a manifest blob: $EVIDENCE_URL" ;;
esac
pass "completion SE → $DONE_SE (manifest=$EVIDENCE_URL)"

# --- stage 7: ack with authorized SA → unfreeze ---------------------------
info "stage 7: manual ack with authorized SA → unfreeze"
kubectl create ns "$ACKER_NS" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl -n "$ACKER_NS" create sa "$ACKER_SA" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
cat <<EOF | kubectl apply -f - >/dev/null
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: { name: wave2-smoke-acker }
rules:
  - apiGroups: ["security.ugallu.io"]
    resources: ["securityevents"]
    verbs: ["get","list","patch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: { name: wave2-smoke-acker }
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: wave2-smoke-acker
subjects:
  - kind: ServiceAccount
    name: $ACKER_SA
    namespace: $ACKER_NS
EOF
kubectl annotate securityevent "$DONE_SE" \
  ugallu.io/incident-acknowledged=true \
  --overwrite \
  --as="system:serviceaccount:$ACKER_NS:$ACKER_SA" >/dev/null
wait_for "freeze CNP still present after ack" 60 \
  bash -c "[ -z \"\$(kubectl -n $NS_TEST get cnp ugallu-forensics-freeze-$POD_UID -o name 2>/dev/null)\" ]"
wait_for "ugallu.io/frozen label still present after ack" 30 \
  bash -c "[ -z \"\$(kubectl -n $NS_TEST get pod $SUSPECT_POD -o jsonpath='{.metadata.labels.ugallu\\.io/frozen}')\" ]"
pass "suspect Pod unfrozen via authorized-SA ack"

T1=$(date +%s)
ELAPSED=$((T1 - T0))
[ "$ELAPSED" -le 180 ] || fail "chain finished in ${ELAPSED}s, exceeds 180s budget"

echo
echo "${GREEN}Real-chain smoke passed in ${ELAPSED}s.${NC}"
echo "  trigger SE   : $TRIGGER_SE"
echo "  bundle       : $BUNDLE_NAME"
echo "  incident UID : $INCIDENT_UID"
echo "  completion SE: $DONE_SE"
echo "  manifest URL : $EVIDENCE_URL"
