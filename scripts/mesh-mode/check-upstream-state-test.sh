#!/usr/bin/env bash
# The failure paths of scripts/mesh-mode/check-upstream-state.sh, against local stand-ins for its
# sources: a loopback HTTP server over a temporary document root, with one path that answers 500.
# The checker runs with ALLOW_CI=1, its record in a temporary directory (never docs/evidences/) and
# its three URL overrides (ISTIO_MIGRATE_URL, GITHUB_API, SPIRE_DOC_BASE) pointed at the server.
#
# Cases:
#   happy path      local copies of the three documents      exit 0, nothing unreachable
#   SPIRE 404       the agent document is absent             exit 2, the document unreachable
#   guide 500       the migration guide answers 500          exit 2, the guide unreachable
#   SPIRE wrong     the agent document is another document   exit 2, the expected heading named
#   GitHub 404      the tracking issue is absent             exit 2, the issue unreachable
# On an error the record never says the Broker API is undocumented.
#
# Usage: scripts/mesh-mode/check-upstream-state-test.sh   (exit 0 when every case passes)
# Needs bash, curl, jq, python3 and git, as the checker does. Run by CI in the chart job.
set -uo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
CHECKER=$HERE/check-upstream-state.sh
work=$(mktemp -d)
server_pid=
cleanup() { [ -n "$server_pid" ] && kill "$server_pid" 2>/dev/null; rm -rf "$work"; }
trap cleanup EXIT

SPIRE_TAG=v1.15.3
root=$work/root
mkdir -p "$root/istio" "$root/repos/istio/istio/releases" "$root/repos/istio/istio/issues" \
  "$root/repos/istio/ztunnel/pulls" "$root/repos/spiffe/spire/releases" "$root/spire/$SPIRE_TAG/doc"

# ---- The stand-ins: the shapes the checker reads, nothing more.
cat >"$root/istio/migrate.html" <<'HTML'
<!doctype html>
<html><head><title>Istio / Migrate from Sidecar to Ambient</title></head>
<body><h1>Migrate from Sidecar to Ambient</h1><p>Version Istio 1.31</p>
<h2>What is not supported</h2>
<ul><li>SPIRE as the certificate provider. Ambient mode does not support SPIRE integration.</li></ul>
</body></html>
HTML
cat >"$root/spire/$SPIRE_TAG/doc/spire_agent.md" <<'MD'
# SPIRE Agent Configuration Reference

| experimental | Description | Default |
|---|---|---|
| `broker` | The SPIFFE Broker API | |

## SPIFFE Broker API

> **Status:** experimental.
MD
printf '%s\n' '{"tag_name":"1.31.1","published_at":"2026-09-30T00:00:00Z"}' >"$root/repos/istio/istio/releases/latest"
printf '%s\n' '{"state":"open","title":"SPIRE under ambient","updated_at":"2026-10-01T00:00:00Z"}' >"$root/repos/istio/istio/issues/42339"
for n in 1676 1936 2067; do
  printf '{"state":"open","merged_at":null,"draft":false,"title":"pull %s","labels":[],"updated_at":"2026-10-01T00:00:00Z"}\n' "$n" \
    >"$root/repos/istio/ztunnel/pulls/$n"
done
printf '{"tag_name":"%s","published_at":"2026-09-01T00:00:00Z"}\n' "$SPIRE_TAG" >"$root/repos/spiffe/spire/releases/latest"

# ---- The server: files from the root, 404 for a missing one, 500 for the one path below.
cat >"$work/server.py" <<'PY'
import functools, http.server, sys
root, port_file = sys.argv[1], sys.argv[2]
class Handler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/fail/"):
            self.send_error(500, "Internal Server Error")
            return
        super().do_GET()
    def log_message(self, *args):
        pass
server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), functools.partial(Handler, directory=root))
with open(port_file, "w") as f:
    f.write(str(server.server_address[1]))
server.serve_forever()
PY
python3 "$work/server.py" "$root" "$work/port" &
server_pid=$!
for _ in $(seq 50); do [ -s "$work/port" ] && break; sleep 0.1; done
[ -s "$work/port" ] || { echo "check-upstream-state-test: the local server did not start" >&2; exit 1; }
BASE=http://127.0.0.1:$(cat "$work/port")

failures=0
pass() { printf 'PASS  %s\n' "$1"; }
fail() { printf 'FAIL  %s: %s\n' "$1" "$2" >&2; failures=$((failures + 1)); }

# run_case <name> <expected exit> <migration guide URL>: the checker against the stand-ins; the
# record of the case is left in $work/<name>/upstream-state.md
run_case() {
  local name=$1 want=$2 migrate=$3 got
  mkdir -p "$work/$name"
  env -u GH_TOKEN ALLOW_CI=1 OUT_DIR="$work/$name" ISTIO_MIGRATE_URL="$migrate" GITHUB_API="$BASE" \
    SPIRE_DOC_BASE="$BASE/spire" "$CHECKER" >"$work/$name.log" 2>&1
  got=$?
  if [ "$got" -ne "$want" ]; then
    fail "$name" "exit $got, expected $want"; sed 's/^/      /' "$work/$name.log" >&2; return 1
  fi
  [ -f "$work/$name/upstream-state.md" ] || { fail "$name" "no record written"; return 1; }
  return 0
}
record() { cat "$work/$1/upstream-state.md"; }
has() { grep -qF -- "$2" <<<"$(record "$1")"; }
no_undocumented() { ! has "$1" "not documented in this release"; }

MIGRATE_OK=$BASE/istio/migrate.html
SPIRE_DOC=$root/spire/$SPIRE_TAG/doc/spire_agent.md

# 1. The happy path: the stand-ins are the shapes the checker reads.
if run_case happy 0 "$MIGRATE_OK"; then
  if has happy "UNREACHABLE"; then fail happy "a source is recorded as unreachable"
  elif ! has happy "under the \`experimental\` block"; then fail happy "the Broker API is not recorded as experimental"
  else pass "happy path: exit 0, every source read"; fi
fi

# 2. The SPIRE agent document answers 404.
mv "$SPIRE_DOC" "$work/spire_agent.md"
if run_case spire-404 2 "$MIGRATE_OK"; then
  if ! has spire-404 "UNREACHABLE: SPIRE agent documentation at $SPIRE_TAG"; then fail spire-404 "the SPIRE document is not recorded as unreachable"
  elif ! no_undocumented spire-404; then fail spire-404 "the Broker API is recorded as not documented"
  else pass "SPIRE document 404: exit 2, unreachable, nothing claimed"; fi
fi
mv "$work/spire_agent.md" "$SPIRE_DOC"

# 3. The migration guide answers 500.
if run_case guide-500 2 "$BASE/fail/migrate.html"; then
  if ! has guide-500 "UNREACHABLE: Istio migration guide $BASE/fail/migrate.html"; then fail guide-500 "the guide is not recorded as unreachable"
  elif has guide-500 "MOVED"; then fail guide-500 "a premise is recorded as moved"
  elif ! has guide-500 "unreachable, not judged"; then fail guide-500 "the guide's entry is judged"
  else pass "migration guide 500: exit 2, unreachable, not judged"; fi
fi

# 4. The SPIRE agent document answers 200 with another document.
cp "$SPIRE_DOC" "$work/spire_agent.md"
printf '%s\n' '404: Not Found' >"$SPIRE_DOC"
if run_case spire-wrong 2 "$MIGRATE_OK"; then
  if ! has spire-wrong "expected the first line \"# SPIRE Agent Configuration Reference\""; then fail spire-wrong "the expected heading is not named"
  elif ! no_undocumented spire-wrong; then fail spire-wrong "the Broker API is recorded as not documented"
  else pass "SPIRE document with the wrong body: exit 2, the expected heading named"; fi
fi
mv "$work/spire_agent.md" "$SPIRE_DOC"

# 5. A GitHub API resource answers 404.
mv "$root/repos/istio/istio/issues/42339" "$work/42339"
if run_case github-404 2 "$MIGRATE_OK"; then
  if ! has github-404 "UNREACHABLE: istio/istio#42339 (GitHub API)"; then fail github-404 "the issue is not recorded as unreachable"
  else pass "GitHub API 404: exit 2, the issue unreachable"; fi
fi
mv "$work/42339" "$root/repos/istio/istio/issues/42339"

if [ "$failures" -gt 0 ]; then echo "check-upstream-state-test: $failures case(s) failed" >&2; exit 1; fi
echo "check-upstream-state-test: every case passed"
