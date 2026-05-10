#!/usr/bin/env bash
# E2E lab smoke for ugallu-ui (SPA + BFF).
#
# Assumes:
#   - kubectl context points at the lab cluster
#   - the ugallu-ui subchart is enabled with a reachable OIDC issuer
#     (the smoke does NOT exercise the OIDC flow itself - that lives
#     behind a browser session - but it asserts the BFF refuses
#     unauthenticated /api calls with the documented loginURL hint)
#   - SecretRefs ugallu-ui-oidc + ugallu-ui-cookie exist
#
# Scenarios:
#   1. Deployment ugallu-ui is Available and the Pod has 2 ready
#      containers (bff + nginx)
#   2. Service ugallu-ui resolves and serves the SPA index.html
#   3. /healthz on the public Service returns 200
#   4. GET /api/v1/me without a session cookie returns 401 with a
#      JSON body carrying loginURL
#   5. GET /api/v1/events without a session cookie returns 401
#   6. (optional) when an Ingress is provisioned, the cert-manager
#      Certificate has Status.Ready=True
#
# Run with:
#   bash hack/ugallu-ui-smoke.sh

set -euo pipefail

GREEN=$'\033[0;32m'
RED=$'\033[0;31m'
YELLOW=$'\033[1;33m'
NC=$'\033[0m'

pass() { echo "${GREEN}PASS${NC} $*"; }
fail() { echo "${RED}FAIL${NC} $*" >&2; exit 1; }
info() { echo "${YELLOW}==>${NC} $*"; }

NS="${UGALLU_UI_NS:-ugallu-system}"
DEP="ugallu-ui"
SVC="ugallu-ui"
PUBLIC_PORT="${UGALLU_UI_PORT:-8080}"

# Detect auth-disabled mode by inspecting the deployment args.
AUTH_DISABLED="false"
if kubectl -n "$NS" get deploy "$DEP" -o jsonpath='{.spec.template.spec.containers[?(@.name=="bff")].args}' 2>/dev/null \
  | grep -q -- '-auth-disabled=true'; then
  AUTH_DISABLED="true"
fi

# --- Scenario 1: deployment health ----------------------------------
info "S1: deployment $DEP is Available with 2 ready containers"
kubectl -n "$NS" rollout status deploy "$DEP" --timeout=120s >/dev/null \
  || fail "S1: deployment $DEP did not roll out"

ready=$(kubectl -n "$NS" get deploy "$DEP" -o jsonpath='{.status.readyReplicas}')
[ "${ready:-0}" -ge 1 ] || fail "S1: readyReplicas=$ready, expected >=1"

container_count=$(kubectl -n "$NS" get deploy "$DEP" -o jsonpath='{.spec.template.spec.containers[*].name}' | wc -w)
[ "$container_count" -eq 2 ] || fail "S1: expected 2 containers, got $container_count"
pass "S1: $DEP ready (containers=$container_count)"

# Pull the actual Pod name for the in-cluster probes below.
POD=$(kubectl -n "$NS" get pod -l app.kubernetes.io/name=ugallu-ui \
  --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}')
[ -n "$POD" ] || fail "S1: no Running ugallu-ui pod"

# --- Scenario 2: SPA index.html served by nginx ---------------------
info "S2: SPA index.html served by nginx via the Service"
spa_status=$(kubectl -n "$NS" run smoke-curl-spa --rm -i --quiet --restart=Never \
  --image=curlimages/curl:8.10.1 --wait=true \
  --command -- \
  curl -fsS -o /dev/null -w '%{http_code}' "http://${SVC}.${NS}.svc.cluster.local:${PUBLIC_PORT}/" \
  2>/dev/null || true)
[ "$spa_status" = "200" ] || fail "S2: GET / returned $spa_status, want 200"
pass "S2: SPA index.html served (HTTP 200)"

# --- Scenario 3: /healthz proxied to BFF ----------------------------
info "S3: /healthz proxied through nginx to the BFF"
hz=$(kubectl -n "$NS" run smoke-curl-hz --rm -i --quiet --restart=Never \
  --image=curlimages/curl:8.10.1 --wait=true \
  --command -- \
  curl -fsS -o /dev/null -w '%{http_code}' "http://${SVC}.${NS}.svc.cluster.local:${PUBLIC_PORT}/healthz" \
  2>/dev/null || true)
[ "$hz" = "200" ] || fail "S3: /healthz returned $hz, want 200"
pass "S3: /healthz returns 200"

if [ "$AUTH_DISABLED" = "true" ]; then
  echo "${YELLOW}NOTE${NC} auth-disabled mode detected: S4/S5 assert 200 + lab-user instead of 401"

  # --- Scenario 4 (auth-disabled): /api/v1/me returns 200 + lab-user
  info "S4: GET /api/v1/me returns 200 + lab-user"
  me_body=$(kubectl -n "$NS" run smoke-curl-me --rm -i --quiet --restart=Never \
    --image=curlimages/curl:8.10.1 --wait=true \
    --command -- \
    sh -c "curl -sS -o /tmp/body -w '%{http_code}' 'http://${SVC}.${NS}.svc.cluster.local:${PUBLIC_PORT}/api/v1/me' && echo --- && cat /tmp/body" \
    2>/dev/null || true)
  echo "$me_body" | grep -q '^200' \
    || fail "S4: /api/v1/me did not return 200 (got: ${me_body%%---*})"
  echo "$me_body" | grep -q 'lab-user' \
    || fail "S4: 200 body missing the lab-user marker"
  pass "S4: /api/v1/me -> 200 + lab-user"

  # --- Scenario 5 (auth-disabled): /api/v1/events returns 200 -------
  info "S5: GET /api/v1/events returns 200"
  ev_status=$(kubectl -n "$NS" run smoke-curl-ev --rm -i --quiet --restart=Never \
    --image=curlimages/curl:8.10.1 --wait=true \
    --command -- \
    curl -sS -o /dev/null -w '%{http_code}' "http://${SVC}.${NS}.svc.cluster.local:${PUBLIC_PORT}/api/v1/events" \
    2>/dev/null || true)
  [ "$ev_status" = "200" ] || fail "S5: /api/v1/events returned $ev_status, want 200"
  pass "S5: /api/v1/events -> 200"
else
  # --- Scenario 4: /api/v1/me unauthenticated -> 401 + loginURL ----
  info "S4: GET /api/v1/me without session cookie returns 401 + loginURL"
  me_body=$(kubectl -n "$NS" run smoke-curl-me --rm -i --quiet --restart=Never \
    --image=curlimages/curl:8.10.1 --wait=true \
    --command -- \
    sh -c "curl -sS -o /tmp/body -w '%{http_code}' 'http://${SVC}.${NS}.svc.cluster.local:${PUBLIC_PORT}/api/v1/me' && echo --- && cat /tmp/body" \
    2>/dev/null || true)
  echo "$me_body" | grep -q '^401' \
    || fail "S4: /api/v1/me did not return 401 (got: ${me_body%%---*})"
  echo "$me_body" | grep -q 'loginURL' \
    || fail "S4: 401 body missing loginURL hint"
  pass "S4: /api/v1/me unauthenticated -> 401 + loginURL"

  # --- Scenario 5: /api/v1/events unauthenticated -> 401 ------------
  info "S5: GET /api/v1/events without session cookie returns 401"
  ev_status=$(kubectl -n "$NS" run smoke-curl-ev --rm -i --quiet --restart=Never \
    --image=curlimages/curl:8.10.1 --wait=true \
    --command -- \
    curl -sS -o /dev/null -w '%{http_code}' "http://${SVC}.${NS}.svc.cluster.local:${PUBLIC_PORT}/api/v1/events" \
    2>/dev/null || true)
  [ "$ev_status" = "401" ] || fail "S5: /api/v1/events returned $ev_status, want 401"
  pass "S5: /api/v1/events unauthenticated -> 401"
fi

# --- Scenario 6: route exposure (HTTPRoute on Gateway API or Ingress)
info "S6: route attached (HTTPRoute or Ingress)"
if kubectl -n "$NS" get httproute ugallu-ui >/dev/null 2>&1; then
  accepted=$(kubectl -n "$NS" get httproute ugallu-ui \
    -o jsonpath='{.status.parents[0].conditions[?(@.type=="Accepted")].status}' \
    2>/dev/null || echo "")
  [ "$accepted" = "True" ] || fail "S6: HTTPRoute ugallu-ui not Accepted (status=$accepted)"
  resolved=$(kubectl -n "$NS" get httproute ugallu-ui \
    -o jsonpath='{.status.parents[0].conditions[?(@.type=="ResolvedRefs")].status}' \
    2>/dev/null || echo "")
  [ "$resolved" = "True" ] || fail "S6: HTTPRoute ugallu-ui ResolvedRefs=$resolved"
  pass "S6: HTTPRoute Accepted + ResolvedRefs"
elif kubectl -n "$NS" get ingress ugallu-ui >/dev/null 2>&1; then
  ready=$(kubectl -n "$NS" get certificate ugallu-ui-tls \
    -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || echo "")
  [ "$ready" = "True" ] || fail "S6: certificate ugallu-ui-tls not Ready (status=$ready)"
  pass "S6: Ingress + certificate ugallu-ui-tls Ready"
else
  echo "${YELLOW}SKIP${NC} S6: no HTTPRoute/Ingress in $NS (routing.kind=none?)"
fi

echo
pass "ugallu-ui smoke: 5/5 scenarios green (S6 may skip)"
