#!/usr/bin/env bash
# Bootstrap a dedicated OpenBao transit key for cosign image
# signing. Idempotent - re-running keeps the existing key without
# rotating it; rotation is an explicit `bao write -force` op the
# operator runs out-of-band when warranted.
#
# Why a dedicated key (not the attestor's `ugallu-attestor`)?
#   - Blast radius: compromise of one key doesn't taint the other
#     trust chain (SE bundles vs container images).
#   - Rotation cadence: the attestor's key rarely rotates (Rekor
#     log continuity); the cosign key can rotate per release.
#   - Audit: `vault audit log` cleanly separates data signing
#     events from artifact signing events.
#
# Usage:
#   bash hack/openbao/cosign-key.sh                   # create + policy
#   bash hack/openbao/cosign-key.sh --token-file out  # also mint a 90d token
#
# Requires:
#   - kubectl context pointed at the cluster running OpenBao
#   - OpenBao initialized + unsealed
#   - The `openbao-init` Secret in the `openbao` namespace
#     (root_token field), populated by the cluster bootstrap.

set -euo pipefail

NS=${OPENBAO_NS:-openbao}
POD=${OPENBAO_POD:-openbao-0}
KEY_NAME=${KEY_NAME:-ugallu-cosign-images}
KEY_TYPE=${KEY_TYPE:-ecdsa-p256}
POLICY_NAME=${POLICY_NAME:-cosign-images-signer}
TOKEN_TTL=${TOKEN_TTL:-2160h}      # 90 days

GREEN=$'\033[0;32m'
RED=$'\033[0;31m'
YELLOW=$'\033[1;33m'
NC=$'\033[0m'
info() { echo "${YELLOW}==>${NC} $*"; }
ok()   { echo "${GREEN}OK${NC} $*"; }
fail() { echo "${RED}FAIL${NC} $*" >&2; exit 1; }

write_token_file=""
case "${1:-}" in
  --token-file) write_token_file="$2"; shift 2 ;;
esac

ROOT=$(kubectl -n "$NS" get secret openbao-init -o jsonpath='{.data.root_token}' | base64 -d)
[ -n "$ROOT" ] || fail "openbao-init secret has no root_token"

bao() {
  kubectl -n "$NS" exec "$POD" -- env BAO_TOKEN="$ROOT" bao "$@" -tls-skip-verify
}

# 1. Ensure the transit secrets engine is mounted.
info "ensure transit secrets engine mounted"
if ! bao secrets list -format=json | python3 -c 'import json,sys; print("transit/" in json.load(sys.stdin))' | grep -q True; then
  bao secrets enable transit
  ok "transit enabled"
else
  ok "transit already enabled"
fi

# 2. Create the key (idempotent).
info "ensure transit key $KEY_NAME ($KEY_TYPE)"
if bao read -format=json transit/keys/"$KEY_NAME" >/dev/null 2>&1; then
  ok "key $KEY_NAME already present"
else
  bao write -f transit/keys/"$KEY_NAME" type="$KEY_TYPE"
  ok "key $KEY_NAME created"
fi

# 3. Cosign policy: sign + read public material on the key only.
info "ensure policy $POLICY_NAME"
POLICY=$(cat <<EOF
path "transit/sign/$KEY_NAME/*" { capabilities = ["update"] }
path "transit/sign/$KEY_NAME"   { capabilities = ["update"] }
path "transit/keys/$KEY_NAME"   { capabilities = ["read"] }
path "transit/verify/$KEY_NAME/*" { capabilities = ["update"] }
path "transit/verify/$KEY_NAME"   { capabilities = ["update"] }
EOF
)
echo "$POLICY" | bao policy write "$POLICY_NAME" -
ok "policy $POLICY_NAME applied"

# 4. Optional: mint a token so the user can plug it into the
#    cosign env (`COSIGN_VAULT_TOKEN`).
if [ -n "$write_token_file" ]; then
  info "minting 90d token bound to policy"
  TOKEN=$(bao token create -policy="$POLICY_NAME" -ttl="$TOKEN_TTL" -format=json | python3 -c 'import json,sys; print(json.load(sys.stdin)["auth"]["client_token"])')
  printf "%s" "$TOKEN" > "$write_token_file"
  chmod 600 "$write_token_file"
  ok "token written to $write_token_file"
fi

# 5. Print the cosign command line for reference.
info "ready"
cat <<EOF

Cosign usage (OpenBao path):
  export COSIGN_VAULT_TOKEN=\$(cat $write_token_file 2>/dev/null || echo '<token>')
  export VAULT_ADDR=http://openbao.openbao.svc.cluster.local:8200   # in-cluster
  cosign sign --key 'hashivault://$KEY_NAME' \\
    ghcr.io/ninsun-labs/ugallu/audit-detection:<tag>
  cosign verify --key 'hashivault://$KEY_NAME' \\
    ghcr.io/ninsun-labs/ugallu/audit-detection:<tag>

Key path:
  transit/keys/$KEY_NAME

Public material:
  bao read transit/keys/$KEY_NAME
EOF
