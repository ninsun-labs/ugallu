#!/usr/bin/env bash
# Bring up the kind smoke-test infrastructure for ugallu:
#   - SeaweedFS (S3 with Object Lock support, COMPLIANCE mode)
#   - Trillian + MySQL + rekor-server (transparency log, intoto v0.0.2)
#   - Redis (rekor search index)
#   - aws-cli pod (bucket admin + interactive inspection)
#
# Pre-req: a running kind cluster pointed at by the current kubectl
# context, plus CRDs + admission policies already applied.
#
# Usage:
#   bash hack/dev-stack/up.sh

set -euo pipefail

GREEN=$'\033[0;32m'
YELLOW=$'\033[1;33m'
NC=$'\033[0m'
info() { echo "${YELLOW}==>${NC} $*"; }
ok()   { echo "${GREEN}OK${NC}  $*"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

info "Applying SeaweedFS manifest"
# The aws-cli pod has immutable fields (restartPolicy, resources). If
# a previous instance exists with divergent spec, delete it so the
# apply can recreate it cleanly.
kubectl -n ugallu-evidence delete pod aws-cli --ignore-not-found --wait=true >/dev/null 2>&1 || true
kubectl apply -f "${SCRIPT_DIR}/seaweedfs.yaml"

info "Fetching Trillian MySQL schema"
SCHEMA="$(mktemp -t trillian-storage.sql.XXXXXX)"
trap 'rm -f "$SCHEMA"' EXIT
curl -sfSL \
  https://raw.githubusercontent.com/google/trillian/master/storage/mysql/schema/storage.sql \
  -o "$SCHEMA"

info "Creating trillian-schema ConfigMap"
kubectl create configmap trillian-schema \
  -n ugallu-evidence \
  --from-file=storage.sql="$SCHEMA" \
  --dry-run=client -o yaml | kubectl apply -f -

info "Applying Rekor stack manifest"
# - The createtree Job has an immutable Spec template; delete + recreate.
# - The rekor-config ConfigMap must NOT pre-exist with an empty
#   treeID, otherwise scaffolding/createtree skips creation.
kubectl -n ugallu-evidence delete job createtree --ignore-not-found --wait=true >/dev/null 2>&1 || true
if [[ -z "$(kubectl -n ugallu-evidence get cm rekor-config -o jsonpath='{.data.treeID}' 2>/dev/null)" ]]; then
  kubectl -n ugallu-evidence delete cm rekor-config --ignore-not-found --wait=true >/dev/null 2>&1 || true
fi
kubectl apply -f "${SCRIPT_DIR}/rekor.yaml"

info "Waiting for SeaweedFS + MySQL + Redis"
kubectl -n ugallu-evidence rollout status deployment/seaweedfs --timeout=300s
kubectl -n ugallu-evidence rollout status deployment/trillian-mysql --timeout=300s
kubectl -n ugallu-evidence rollout status deployment/redis --timeout=300s

info "Waiting for Trillian log server + signer"
kubectl -n ugallu-evidence rollout status deployment/trillian-log-server --timeout=300s
kubectl -n ugallu-evidence rollout status deployment/trillian-log-signer --timeout=300s

info "Waiting for createtree job (writes treeID into rekor-config ConfigMap)"
kubectl -n ugallu-evidence wait --for=condition=Complete job/createtree --timeout=300s

TREE_ID="$(kubectl -n ugallu-evidence get cm rekor-config -o jsonpath='{.data.treeID}')"
if [[ -z "$TREE_ID" ]]; then
  echo "createtree did not populate rekor-config.treeID; aborting" >&2
  exit 1
fi
ok "Trillian treeID = $TREE_ID"

info "Restarting rekor-server now that treeID is set"
kubectl -n ugallu-evidence rollout restart deployment/rekor-server
kubectl -n ugallu-evidence rollout status deployment/rekor-server --timeout=300s

info "Waiting for aws-cli pod"
kubectl -n ugallu-evidence wait --for=condition=Ready pod/aws-cli --timeout=120s

# Ensure the bucket exists AND has Object Lock + default retention
# enabled. Object Lock can only be enabled at create-time on
# SeaweedFS, so a pre-existing bucket without it gets recreated
# (the dev-stack is explicitly NOT for production — see README).
info "Ensuring bucket 'ugallu' exists with Object Lock + COMPLIANCE retention"
EP="--endpoint-url=http://seaweedfs:8333"
if kubectl -n ugallu-evidence exec aws-cli -- \
     aws s3api head-bucket --bucket ugallu $EP >/dev/null 2>&1; then
  if kubectl -n ugallu-evidence exec aws-cli -- \
       aws s3api get-object-lock-configuration --bucket ugallu $EP >/dev/null 2>&1; then
    ok "bucket already exists with Object Lock"
  else
    info "bucket exists but Object Lock is disabled — recreating (dev-stack only)"
    kubectl -n ugallu-evidence exec aws-cli -- \
      aws s3 rm s3://ugallu/ --recursive $EP >/dev/null 2>&1 || true
    kubectl -n ugallu-evidence exec aws-cli -- \
      aws s3api delete-bucket --bucket ugallu $EP >/dev/null
    kubectl -n ugallu-evidence exec aws-cli -- \
      aws s3api create-bucket --bucket ugallu --object-lock-enabled-for-bucket $EP >/dev/null
    ok "bucket recreated with Object Lock"
  fi
else
  kubectl -n ugallu-evidence exec aws-cli -- \
    aws s3api create-bucket --bucket ugallu --object-lock-enabled-for-bucket $EP >/dev/null
  ok "bucket created with Object Lock"
fi

# Default retention is idempotent: PUT replaces the existing rule
# atomically. 7 days = the design 07 W2 default for evidence blobs.
info "Applying default retention (COMPLIANCE 7d)"
kubectl -n ugallu-evidence exec aws-cli -- \
  aws s3api put-object-lock-configuration --bucket ugallu $EP \
  --object-lock-configuration '{"ObjectLockEnabled":"Enabled","Rule":{"DefaultRetention":{"Mode":"COMPLIANCE","Days":7}}}' >/dev/null
ok "default retention applied"

info "Object Lock configuration:"
kubectl -n ugallu-evidence exec aws-cli -- \
  aws s3api get-object-lock-configuration --bucket ugallu $EP

info "Rekor log info:"
kubectl -n ugallu-evidence exec aws-cli -- \
  sh -c 'curl -s http://rekor-server:3000/api/v1/log' | head -c 400; echo

ok "dev stack ready"
echo
echo "Attestor flags to plug in:"
echo "  --rekor-url=http://rekor-server.ugallu-evidence.svc.cluster.local:3000"
echo "  --worm-backend=s3 \\"
echo "  --worm-s3-endpoint=http://seaweedfs.ugallu-evidence.svc.cluster.local:8333 \\"
echo "  --worm-s3-bucket=ugallu --worm-s3-path-style=true \\"
echo "  --worm-s3-key-prefix=attestations \\"
echo "  --worm-s3-lock-mode=COMPLIANCE \\"
echo "  --worm-s3-access-key=ugallu-access \\"
echo "  --worm-s3-secret-key=ugallu-secret \\"
echo "  --worm-retention=168h"
