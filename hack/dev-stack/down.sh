#!/usr/bin/env bash
# Tear down the kind smoke-test infrastructure created by up.sh.
#
# Usage:
#   bash hack/dev-stack/down.sh

set -euo pipefail

YELLOW=$'\033[1;33m'
NC=$'\033[0m'
info() { echo "${YELLOW}==>${NC} $*"; }

info "Deleting Rekor stack"
kubectl delete -f "$(dirname "${BASH_SOURCE[0]}")/rekor.yaml" --ignore-not-found --wait=false

info "Deleting trillian-schema ConfigMap"
kubectl delete -n ugallu-evidence configmap trillian-schema --ignore-not-found

info "Deleting SeaweedFS stack"
kubectl delete -f "$(dirname "${BASH_SOURCE[0]}")/seaweedfs.yaml" --ignore-not-found --wait=false

info "Deleting namespace ugallu-evidence (will cascade)"
kubectl delete namespace ugallu-evidence --ignore-not-found --wait=false

echo "Down submitted; namespace finalizers may take a few seconds."
