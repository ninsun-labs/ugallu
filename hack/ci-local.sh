#!/usr/bin/env bash
# Copyright 2026 The ninsun-labs Authors.
# SPDX-License-Identifier: Apache-2.0
#
# Run the full CI pipeline locally so we can push only when green.
# Mirrors .github/workflows/ci.yml: build / test / lint per module,
# helm lint+template, generate-drift, type-catalog parity.
#
# Requires: go, golangci-lint, gofumpt, goimports, controller-gen,
#           setup-envtest, helm.

set -euo pipefail

cd "$(dirname "$0")/.."

# Discover Go modules.
mapfile -t MODULES < <(find . -name go.mod -not -path "./.git/*" -not -path "./vendor/*" -exec dirname {} \;)

# Ensure setup-envtest is on PATH and assets are downloaded.
if ! command -v setup-envtest >/dev/null; then
  echo "==> installing setup-envtest"
  go install sigs.k8s.io/controller-runtime/tools/setup-envtest@latest
fi
KUBEBUILDER_ASSETS="$(setup-envtest use 1.32 -p path)"
export KUBEBUILDER_ASSETS

green() { printf '\033[0;32m%s\033[0m\n' "$*"; }
red()   { printf '\033[0;31m%s\033[0m\n' "$*"; }
section() { printf '\n\033[1;33m==> %s\033[0m\n' "$*"; }

section "build (per module)"
for mod in "${MODULES[@]}"; do
  echo "  $mod"
  (cd "$mod" && go build ./...)
done

section "test (per module, race + envtest)"
for mod in "${MODULES[@]}"; do
  echo "  $mod"
  (cd "$mod" && go test -race -timeout 120s ./...)
done

section "lint (per module, skip empty)"
for mod in "${MODULES[@]}"; do
  if find "$mod" -maxdepth 5 -name "*.go" -not -path "*/vendor/*" | head -1 | grep -q .; then
    echo "  $mod"
    (cd "$mod" && golangci-lint run --timeout=5m ./...)
  else
    echo "  $mod (skip: no .go yet)"
  fi
done

section "helm dep update + lint umbrella + lint subcharts"
helm dependency update charts/ugallu >/dev/null
helm lint charts/ugallu
for sub in charts/ugallu/charts/*/; do
  if [[ -f "${sub}Chart.yaml" ]]; then
    echo "  $sub"
    helm lint "$sub"
  fi
done

section "helm template + Kind sanity check"
RENDER=$(mktemp /tmp/ugallu-render.XXXXXX.yaml)
helm template ugallu charts/ugallu --namespace ugallu-system > "$RENDER"
for kind in Namespace ServiceAccount ClusterRole ClusterRoleBinding Role RoleBinding \
            Service DaemonSet Deployment ValidatingAdmissionPolicy ValidatingAdmissionPolicyBinding; do
  if ! grep -q "^kind: ${kind}$" "$RENDER"; then
    red "ERROR: rendered chart missing kind ${kind}"
    exit 1
  fi
done
rm -f "$RENDER"
green "all expected Kinds present"

section "generate-drift (controller-gen object + crd)"
(cd sdk && controller-gen object paths=./pkg/api/v1alpha1/...)
(cd sdk && controller-gen crd paths=./pkg/api/v1alpha1/... output:crd:dir=../crds/bases)
# Scope drift check to paths controller-gen writes; ignore unrelated
# in-progress edits.
GEN_PATHS=(sdk/pkg/api/v1alpha1/zz_generated.deepcopy.go crds/bases)
if ! git diff --quiet -- "${GEN_PATHS[@]}"; then
  red "ERROR: generated files differ from committed:"
  git diff --stat -- "${GEN_PATHS[@]}"
  exit 1
fi
green "no drift in ${GEN_PATHS[*]}"

section "type-catalog parity (SDK <-> admission policy 5)"
sdk_types=$(grep -E '^\s+Type[A-Za-z]+\s+=' sdk/pkg/api/v1alpha1/types.go \
            | sed -E 's/.*= "([^"]+)".*/\1/' | sort -u)
policy_types=$(grep -oE "'[A-Z][A-Za-z]+'" \
                charts/ugallu/charts/admission-policies/templates/05-type-validation.yaml \
                | tr -d "'" | sort -u)
if [[ "$sdk_types" != "$policy_types" ]]; then
  red "ERROR: type catalog drift"
  diff <(echo "$sdk_types") <(echo "$policy_types") | head -20 || true
  exit 1
fi
green "parity OK ($(echo "$sdk_types" | wc -l) types)"

echo
green "=== CI-LOCAL: ALL GREEN ==="
