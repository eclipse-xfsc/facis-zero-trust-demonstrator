#!/usr/bin/env bash
# Package a policy catalogue as the tarball a registry serves (ZT-37): the cluster objects of
# deployment/admission - templates/, constraints/ (with its kustomization) and exemptions.yaml - at the
# paths they have in Git, so an Application that reads the package names the path it names in Git
# (deployment/helm/admission-gitops). The gator suite, the test objects, the chart values and the README
# stay out: they are not applied to a cluster.
#
# The archive is reproducible: the same files give the same bytes, so the same digest, whoever packages
# them and whenever - entries sorted, no owner, no modification time, one mode whatever the checkout's
# umask, no timestamp in the gzip header. Without that, the same commit would publish a different digest
# on every run, and nothing could say whether what a registry serves is what Git holds.
#
#   scripts/supplychain/policy-package.sh <catalogue dir> <out.tar.gz>
set -euo pipefail

[ $# -eq 2 ] || { echo "usage: $0 <catalogue dir> <out.tar.gz>" >&2; exit 2; }
src="$1" out="$2"
members=(templates constraints exemptions.yaml)
for member in "${members[@]}"; do
  [ -e "$src/$member" ] || { echo "policy-package: $src/$member is missing" >&2; exit 1; }
done

tar --sort=name --owner=0 --group=0 --numeric-owner --mtime='1970-01-01 00:00:00Z' --mode='u=rwX,go=rX' \
  --format=ustar -C "$src" -cf - "${members[@]}" | gzip -n -9 > "$out"
sha256sum "$out"
