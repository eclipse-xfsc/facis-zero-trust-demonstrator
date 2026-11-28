#!/usr/bin/env bash
# Cases for the key source: key-source.sh selects the cosign key and the one public key per source and
# refuses anything else; check-key.sh refuses a missing secret, a missing token, an uncommitted public
# key and a key that is not the public key's private half; sbom-backfill.sh verifies a release against
# the key set and never re-signs a release of another key. cosign is a stub: no key, registry or network.
#
#   scripts/supplychain/keys_test.sh
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

failures=0
ok() { echo "ok    $1"; }
fail() { echo "FAIL  $1 ($2)"; [ -s "$work/log" ] && sed 's/^/        /' "$work/log"; failures=$((failures + 1)); }
check() { local name=$1; shift; if "$@" >"$work/log" 2>&1; then ok "$name"; else fail "$name" "the check did not hold"; fi; }
refused() { # name reason command...
  local name=$1 reason=$2; shift 2
  if "$@" >"$work/log" 2>&1; then fail "$name" "accepted, want refused"
  elif grep -q -- "$reason" "$work/log"; then ok "$name"
  else fail "$name" "refused, but not with '$reason'"; fi
}

# key-source.sh
source_is() { # expected-lines env...
  local want=$1; shift
  [ "$(env -i PATH="$PATH" "$@" "$here/key-source.sh")" = "$want" ]
}
check "unset selects the interim key" source_is $'COSIGN_KEY=env://COSIGN_INTERIM_KEY\nSIGNING_PUBLIC_KEY=docs/contracts/keys/interim-cosign.pub\nSIGNING_KEY_SOURCE=interim'
check "client selects the client key file" source_is $'COSIGN_KEY=env://COSIGN_CLIENT_KEY\nSIGNING_PUBLIC_KEY=docs/contracts/keys/client-cosign.pub\nSIGNING_KEY_SOURCE=client' SIGNING_KEY_SOURCE=client
check "openbao-transit selects the transit key through hashivault" source_is \
  $'VAULT_ADDR=https://bao.example:8200\nCOSIGN_KEY=hashivault://ztd-release\nSIGNING_PUBLIC_KEY=docs/contracts/keys/openbao-transit-cosign.pub\nTRANSIT_SECRET_ENGINE_PATH=ztd-transit\nSIGNING_KEY_SOURCE=openbao-transit' \
  SIGNING_KEY_SOURCE=openbao-transit SIGNING_TRANSIT_KEY=ztd-release SIGNING_VAULT_ADDR=https://bao.example:8200 SIGNING_TRANSIT_PATH=ztd-transit
refused "an unknown source is refused" "must be interim, client or openbao-transit" env SIGNING_KEY_SOURCE=vault "$here/key-source.sh"
refused "openbao-transit without the key name is refused" "needs SIGNING_TRANSIT_KEY" \
  env SIGNING_KEY_SOURCE=openbao-transit SIGNING_VAULT_ADDR=https://bao.example "$here/key-source.sh"
refused "openbao-transit without the address is refused" "needs SIGNING_VAULT_ADDR" \
  env SIGNING_KEY_SOURCE=openbao-transit SIGNING_TRANSIT_KEY=k "$here/key-source.sh"

# check-key.sh, with a cosign stub whose public-key prints $STUB_PUBLIC.
mkdir -p "$work/bin" "$work/repo/docs/contracts/keys"
cat > "$work/bin/cosign" <<'STUB'
#!/usr/bin/env bash
case "$1" in
  public-key) cat "$STUB_PUBLIC" ;;
  verify-blob) # --key K ... : verifies when the signature file names the key's basename
    key="$3"; sig=""; while [ $# -gt 0 ]; do [ "$1" = --signature ] && sig="$2"; shift; done
    grep -qx "$(basename "$key")" "$sig" ;;
  *) exit 2 ;;
esac
STUB
chmod +x "$work/bin/cosign"
printf -- '-----BEGIN PUBLIC KEY-----\ninterim\n-----END PUBLIC KEY-----\n' > "$work/repo/docs/contracts/keys/interim-cosign.pub"
printf -- '-----BEGIN PUBLIC KEY-----\ntransit\n-----END PUBLIC KEY-----\n' > "$work/repo/docs/contracts/keys/openbao-transit-cosign.pub"
printf -- '-----BEGIN PUBLIC KEY-----\nother\n-----END PUBLIC KEY-----\n' > "$work/other.pub"
check_key() { (cd "$work/repo" && env COSIGN="$work/bin/cosign" "$@" "$here/check-key.sh"); }

check "the interim key matching its public key passes" check_key STUB_PUBLIC="$work/repo/docs/contracts/keys/interim-cosign.pub" COSIGN_INTERIM_KEY=x
refused "a missing interim secret is refused" "COSIGN_INTERIM_KEY is not set" check_key STUB_PUBLIC="$work/other.pub"
refused "a key that is not the public key's private half is refused" "does not match" \
  check_key STUB_PUBLIC="$work/other.pub" COSIGN_INTERIM_KEY=x
refused "a source whose public key is not committed is refused" "client-cosign.pub is missing" \
  check_key STUB_PUBLIC="$work/other.pub" COSIGN_KEY=env://COSIGN_CLIENT_KEY COSIGN_CLIENT_KEY=x SIGNING_PUBLIC_KEY=docs/contracts/keys/client-cosign.pub
refused "the transit key without a token is refused" "needs VAULT_ADDR and VAULT_TOKEN" \
  check_key STUB_PUBLIC="$work/other.pub" COSIGN_KEY=hashivault://k VAULT_ADDR=https://bao.example SIGNING_PUBLIC_KEY=docs/contracts/keys/openbao-transit-cosign.pub
check "the transit key matching its public key passes" check_key STUB_PUBLIC="$work/repo/docs/contracts/keys/openbao-transit-cosign.pub" \
  COSIGN_KEY=hashivault://k VAULT_ADDR=https://bao.example VAULT_TOKEN=t SIGNING_PUBLIC_KEY=docs/contracts/keys/openbao-transit-cosign.pub
refused "a key file on disk is refused" "must be env://" check_key STUB_PUBLIC="$work/other.pub" COSIGN_KEY=/tmp/cosign.key

# sbom-backfill.sh: the verification against the key set and the decision.
# shellcheck source=scripts/supplychain/sbom-backfill.sh disable=SC1091
. "$here/sbom-backfill.sh"
# shellcheck disable=SC2034 # read by the sourced functions
COSIGN="$work/bin/cosign" KEYS_DIR="$work/repo/docs/contracts/keys"
echo '{}' > "$work/sbom.json"
echo openbao-transit-cosign.pub > "$work/transit.sig"
echo retired-cosign.pub > "$work/unknown.sig"
interim=docs/contracts/keys/interim-cosign.pub transit=docs/contracts/keys/openbao-transit-cosign.pub
check "a pair signed with an older key of the set verifies against that key" \
  test "$(verify_any "$work/sbom.json" "$work/transit.sig")" = "$KEYS_DIR/openbao-transit-cosign.pub"
if verify_any "$work/sbom.json" "$work/unknown.sig" >/dev/null; then fail "a pair signed with no key of the set verifies against none" "it verified"
else ok "a pair signed with no key of the set verifies against none"; fi
check "a verifying pair is left as it is" test "$(sbom_action complete "$transit" "$interim" "$interim")" = "done"
check "a release with no SBOM at all is signed" test "$(sbom_action none "" "$transit" "$interim")" = sign
check "half a pair of a release signed with another key is never replaced" test "$(sbom_action partial "" "$interim" "$transit")" = refuse
check "half a pair of a release signed with the current key is completed" test "$(sbom_action partial "" "$interim" "$interim")" = sign
check "a failing pair of a release signed with the current key is re-signed" test "$(sbom_action complete "" "$interim" "$interim")" = sign
check "a failing pair of a release signed with another key is never re-signed" test "$(sbom_action complete "" "$interim" "$transit")" = refuse

# fetch_assets, with a gh stub: the asset list is $STUB_ASSETS, a download fails when $STUB_DOWNLOAD=fail.
gh() {
  case "$1 $2" in
    "release view") [ "${STUB_LIST:-}" != fail ] || return 1; tr ' ' '\n' <<<"$STUB_ASSETS" ;;
    "release download")
      [ "${STUB_DOWNLOAD:-}" != fail ] || return 1
      local dir=""; shift 3
      while [ $# -gt 0 ]; do case "$1" in --dir) dir=$2; shift ;; --pattern) echo x > "$dir/$2"; shift ;; esac; shift; done ;;
  esac
}
fetched() { # expected assets...
  local want=$1 got; shift
  rm -rf "$work/fetch"; mkdir -p "$work/fetch"
  got="$(STUB_ASSETS="$*" fetch_assets v1.0.0 "$work/fetch")" && [ "$got" = "$want" ]
}
check "a release without SBOM assets is none" fetched none release-manifest.json chart.tgz
check "a release with only the signature is partial" fetched partial sbom.json.sig
check "a release with both is complete" fetched complete sbom.json sbom.json.sig release-manifest.json
for mode in STUB_DOWNLOAD STUB_LIST; do
  rm -rf "$work/fetch"; mkdir -p "$work/fetch"
  if (export "$mode=fail" STUB_ASSETS="sbom.json sbom.json.sig"; fetch_assets v1.0.0 "$work/fetch" >/dev/null); then
    fail "a failed ${mode#STUB_} fails the release, never reads as missing" "it was read as $(STUB_ASSETS="sbom.json sbom.json.sig" fetch_assets v1.0.0 "$work/fetch")"
  else ok "a failed ${mode#STUB_} fails the release, never reads as missing"; fi
done

[ "$failures" -eq 0 ] || { echo "$failures case(s) failed"; exit 1; }
