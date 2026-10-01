#!/usr/bin/env bash
# Install the pinned tools from pins.env into a directory (default ./.tools/bin), verifying each
# download against its pinned SHA-256; any failure (download, checksum, extraction) stops the script.
# linux/amd64 only: it is what CI runs on. Images are pinned by digest in pins.env, not installed here.
#
#   scripts/tools/install.sh [dir] [tool...]      tools: cosign syft grype gator gatekeeper-chart kind kubectl
#                                                  (default: all)
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source-path=SCRIPTDIR source=pins.env
. "$here/pins.env"
dir="${1:-.tools/bin}"
shift || true
tools=("$@")
[ ${#tools[@]} -gt 0 ] || tools=(cosign syft grype gator gatekeeper-chart kind kubectl)
mkdir -p "$dir"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

fetch() { # url sha256 file
  curl -fsSL --retry 3 -o "$work/$3" "$1"
  echo "$2  $work/$3" | sha256sum -c - >/dev/null || { echo "checksum mismatch for $1" >&2; exit 1; }
}

for tool in "${tools[@]}"; do
  case "$tool" in
    cosign)
      fetch "https://github.com/sigstore/cosign/releases/download/${COSIGN_VERSION}/cosign-linux-amd64" "$COSIGN_SHA256" cosign
      install -m 0755 "$work/cosign" "$dir/cosign"
      ;;
    syft)
      fetch "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_linux_amd64.tar.gz" "$SYFT_SHA256" syft.tgz
      tar -xzf "$work/syft.tgz" -C "$work" syft
      install -m 0755 "$work/syft" "$dir/syft"
      ;;
    grype)
      fetch "https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/grype_${GRYPE_VERSION}_linux_amd64.tar.gz" "$GRYPE_SHA256" grype.tgz
      tar -xzf "$work/grype.tgz" -C "$work" grype
      install -m 0755 "$work/grype" "$dir/grype"
      ;;
    gator)
      fetch "https://github.com/open-policy-agent/gatekeeper/releases/download/${GATOR_VERSION}/gator-${GATOR_VERSION}-linux-amd64.tar.gz" "$GATOR_SHA256" gator.tgz
      tar -xzf "$work/gator.tgz" -C "$work" gator
      install -m 0755 "$work/gator" "$dir/gator"
      ;;
    gatekeeper-chart)
      # The chart archive, verified, for `helm install <dir>/gatekeeper-<version>.tgz`.
      fetch "https://open-policy-agent.github.io/gatekeeper/charts/gatekeeper-${GATEKEEPER_CHART_VERSION}.tgz" "$GATEKEEPER_CHART_SHA256" gatekeeper.tgz
      install -m 0644 "$work/gatekeeper.tgz" "$dir/gatekeeper-${GATEKEEPER_CHART_VERSION}.tgz"
      ;;
    kind)
      fetch "https://github.com/kubernetes-sigs/kind/releases/download/${KIND_VERSION}/kind-linux-amd64" "$KIND_SHA256" kind
      install -m 0755 "$work/kind" "$dir/kind"
      ;;
    kubectl)
      fetch "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/amd64/kubectl" "$KUBECTL_SHA256" kubectl
      install -m 0755 "$work/kubectl" "$dir/kubectl"
      ;;
    *) echo "unknown tool: $tool" >&2; exit 2 ;;
  esac
  echo "installed $tool into $dir"
done
