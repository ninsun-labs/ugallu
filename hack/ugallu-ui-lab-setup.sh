#!/usr/bin/env bash
# One-shot lab setup for the ugallu UI on rke2-lab.
#
# What this script does:
#   1. Build the BFF binary + SvelteKit SPA bundle into the
#      multi-binary lab image (`localhost/ugallu-runtime:wave5-rc1`)
#      via `task build:image-multi`.
#   2. Distribute the image to every rke2-lab node (assumes ssh
#      access via NODES env var; falls back to a single
#      `localhost` if NODES is unset).
#   3. Seed the two Secrets the chart needs:
#        - ugallu-ui-cookie  (32-byte HMAC for the session cookie)
#        - ugallu-ui-oidc    (OIDC client_secret from the Keycloak
#          realm; pulled from $UGALLU_UI_OIDC_CLIENT_SECRET if set,
#          otherwise prompted)
#   4. Optionally trigger a helm upgrade if you pass `--apply`:
#        bash hack/ugallu-ui-lab-setup.sh --apply
#
# Idempotent: re-running re-creates Secrets only if missing.
#
# Inputs:
#   UGALLU_UI_NS                 default ugallu-system
#   UGALLU_UI_OIDC_CLIENT_SECRET (optional, prompted if unset)
#   NODES                        space-separated SSH hosts of the
#                                rke2 nodes (default: empty -> skip
#                                image distribution)

set -euo pipefail

GREEN=$'\033[0;32m'; RED=$'\033[0;31m'; YELLOW=$'\033[1;33m'; NC=$'\033[0m'
pass() { echo "${GREEN}OK${NC} $*"; }
fail() { echo "${RED}FAIL${NC} $*" >&2; exit 1; }
info() { echo "${YELLOW}==>${NC} $*"; }

NS="${UGALLU_UI_NS:-ugallu-system}"
TAG="${UGALLU_UI_TAG:-wave5-rc1}"
APPLY="false"
# AUTH_DISABLED=true skips the OIDC client_secret prompt + the
# Secret/ugallu-ui-oidc + Secret/ugallu-ui-cookie seed; mirrors the
# chart's auth.disabled used for the first lab smoke without
# Keycloak.
AUTH_DISABLED="${AUTH_DISABLED:-false}"
for arg in "$@"; do
  case "$arg" in
    --apply) APPLY="true" ;;
    --auth-disabled) AUTH_DISABLED="true" ;;
    --help)
      sed -n '2,32p' "$0"
      exit 0 ;;
  esac
done

# --- 1. Build ------------------------------------------------------
info "build multi-binary lab image (localhost/ugallu-runtime:${TAG})"
task build:image-multi
podman tag localhost/ugallu-runtime:dev localhost/ugallu-runtime:"$TAG"
pass "image localhost/ugallu-runtime:${TAG} built"

# --- 2. Distribute -------------------------------------------------
if [ -n "${NODES:-}" ]; then
  info "distribute image to nodes: $NODES"
  tmp=$(mktemp -t ugallu-runtime-XXXXX.tar)
  podman save -o "$tmp" localhost/ugallu-runtime:"$TAG"
  for n in $NODES; do
    info "  -> $n"
    scp -q "$tmp" "$n:/tmp/ugallu-runtime.tar"
    ssh "$n" "sudo ctr -n=k8s.io images import /tmp/ugallu-runtime.tar && rm /tmp/ugallu-runtime.tar"
  done
  rm -f "$tmp"
  pass "image distributed to $(echo "$NODES" | wc -w) nodes"
else
  echo "${YELLOW}SKIP${NC} image distribution (set NODES='node1 node2 node3' to enable)"
fi

# --- 3. Secrets ----------------------------------------------------
info "ensure namespace $NS exists"
kubectl get ns "$NS" >/dev/null 2>&1 || kubectl create ns "$NS"

if [ "$AUTH_DISABLED" = "true" ]; then
  echo "${YELLOW}NOTE${NC} AUTH_DISABLED=true - skipping OIDC + cookie Secret seed"
else
  info "seed Secret/ugallu-ui-cookie (HMAC for session cookie)"
  if kubectl -n "$NS" get secret ugallu-ui-cookie >/dev/null 2>&1; then
    echo "  already present, leaving as-is"
  else
    kubectl -n "$NS" create secret generic ugallu-ui-cookie \
      --from-literal=cookie_secret="$(openssl rand -hex 32)"
    pass "Secret/ugallu-ui-cookie created"
  fi

  info "seed Secret/ugallu-ui-oidc (Keycloak client_secret)"
  if kubectl -n "$NS" get secret ugallu-ui-oidc >/dev/null 2>&1; then
    echo "  already present, leaving as-is"
  else
    cs="${UGALLU_UI_OIDC_CLIENT_SECRET:-}"
    if [ -z "$cs" ]; then
      read -r -s -p "  Keycloak ugallu-ui client_secret: " cs
      echo
    fi
    [ -n "$cs" ] || fail "OIDC client_secret is empty"
    kubectl -n "$NS" create secret generic ugallu-ui-oidc \
      --from-literal=client_secret="$cs"
    pass "Secret/ugallu-ui-oidc created"
  fi
fi

# --- 4. Apply (optional) -------------------------------------------
if [ "$APPLY" = "true" ]; then
  info "helm upgrade --reuse-values + lab-values-wave5.yaml"
  helm upgrade ugallu charts/ugallu \
    --reuse-values \
    -f hack/lab-values-wave5.yaml \
    --set ugallu-ui.enabled=true \
    --wait --timeout 5m
  pass "helm upgrade completed"
  info "rollout status"
  kubectl -n "$NS" rollout status deploy/ugallu-ui --timeout=180s
  pass "ugallu-ui ready"
  info "smoke"
  bash hack/ugallu-ui-smoke.sh
else
  echo
  echo "${YELLOW}NEXT${NC} run:"
  echo "  helm upgrade ugallu charts/ugallu --reuse-values -f hack/lab-values-wave5.yaml"
  echo "or re-invoke this script with --apply"
fi
