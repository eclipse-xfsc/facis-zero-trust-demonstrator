#!/bin/sh
# The zone manager's keeper: the operations the upstream image leaves to nobody, run next to NSD in the
# same pod (same volume, NSD's control socket), because `resign` rewrites the zone file and tells NSD
# to reload through nsd-control, and the upstream ignores that reload's exit status - a resign from
# another pod would report success while the served signatures stay old.
#
#   zone-keeper daily                  loop: at RESIGN_AT (UTC, HH:MM) resign, then back up
#   zone-keeper resign-now [db-url]    resign and require the served SOA signature to move
#   zone-keeper backup-now             consistent copy of the whole state directory into BACKUP_DIR
#   zone-keeper restore-if-empty       init step: an empty volume is filled from BACKUP_DIR/latest.tgz
#   zone-keeper ds [server]            the DS of the served key-signing key (ldns-key2ds, SHA-256)
#   zone-keeper record-ds              hook step: wait for the zone, write its DS into a ConfigMap
#   zone-keeper address                init step: fix the zone's public address before the first start
#
# Environment: TF_DOMAIN_NAME (the zone), VAR_PATH (/var/lib/zonemgr/), BACKUP_DIR
# (/var/lib/zonemgr-backup), RESIGN_AT (00:05), BACKUP_KEEP (14), NSD_HOST (127.0.0.1);
# record-ds: DNS_SERVICE (host to query), DS_CONFIGMAP (name), and the pod's service-account token;
# address: ZONE_ADDRESS (given) or DNS_SERVICE (the LoadBalancer Service to read it from), the
# *_IP variables of the zone configuration, and the service-account token.
set -eu

zone="${TF_DOMAIN_NAME:?TF_DOMAIN_NAME is not set}"
var="${VAR_PATH:-/var/lib/zonemgr/}"
backup_dir="${BACKUP_DIR:-/var/lib/zonemgr-backup}"
nsd_host="${NSD_HOST:-127.0.0.1}"
db="sqlite:///${var%/}/zones.db"

log() { printf '%s zone-keeper %s\n' "$(date -u +%FT%TZ)" "$*"; }

# nsd-control reads its client settings from the server configuration; this container never ran
# script.sh, so it writes the remote-control section itself: the local socket NSD listens on (patch
# 0004), reached through the /run/nsd volume the pod shares between its two containers.
ensure_control() {
  [ -f /etc/nsd/nsd.conf.d/remote.conf ] && return 0
  cat > /etc/nsd/nsd.conf.d/remote.conf <<CONF
remote-control:
    control-enable: yes
    control-interface: /run/nsd/nsd.ctl
CONF
}

# drill takes an address after @, not a name resolved through the search path, so a Service name
# is resolved here first; an address passes through unchanged.
resolve() { getent ahostsv4 "$1" 2>/dev/null | awk '{print $1; exit}'; }

# the expiration of the served SOA signature, YYYYMMDDHHMMSS, or empty
soa_expiration() { drill -D -o rd "@$(resolve "$1")" "$zone" SOA 2>/dev/null | awk '$4=="RRSIG" && $5=="SOA"{print $9; exit}'; }

resign_now() {
  ensure_control
  before="$(soa_expiration "$nsd_host")"
  log "resign: SOA signature expires $before"
  dns-zone-manager-server --database "${1:-$db}" resign >/dev/null
  sleep 1
  after="$(soa_expiration "$nsd_host")"
  if [ -z "$after" ] || [ "$after" -le "${before:-0}" ]; then
    log "resign FAILED: the served SOA signature did not move (before $before, after $after)"
    return 1
  fi
  log "resign ok: SOA signature expires $after"
}

backup_now() {
  [ -d "$backup_dir" ] || { log "backup FAILED: $backup_dir is not mounted"; return 1; }
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  work="$(mktemp -d)"
  chmod 0755 "$work"   # mktemp gives 0700, and the archive carries the directory mode NSD must be able to traverse
  # A consistent copy of the database through SQLite's own backup API, then the rest of the state
  # directory as it is: the NSD zone list, the zone file(s) and the key file.
  python3 - "${var%/}/zones.db" "$work/zones.db" <<'PY'
import sqlite3, sys
src = sqlite3.connect(sys.argv[1]); dst = sqlite3.connect(sys.argv[2])
with dst: src.backup(dst)
dst.close(); src.close()
PY
  for f in "${var%/}"/*; do
    case "$(basename "$f")" in zones.db|lost+found) ;; *) cp -a "$f" "$work/" ;; esac
  done
  tar -czf "$backup_dir/zonemgr-$stamp.tgz" -C "$work" .
  cp "$backup_dir/zonemgr-$stamp.tgz" "$backup_dir/latest.tgz.new" && mv "$backup_dir/latest.tgz.new" "$backup_dir/latest.tgz"
  rm -rf "$work"
  keep="${BACKUP_KEEP:-14}"
  ls -1t "$backup_dir"/zonemgr-*.tgz 2>/dev/null | tail -n +"$((keep + 1))" | while read -r old; do rm -f "$old"; done
  log "backup ok: $backup_dir/zonemgr-$stamp.tgz ($(wc -c < "$backup_dir/zonemgr-$stamp.tgz") bytes), $(ls -1 "$backup_dir"/zonemgr-*.tgz | wc -l) kept"
}

restore_if_empty() {
  if [ -f "${var%/}/zones.db" ]; then
    log "restore: the volume already holds a zone, nothing to do"
  elif [ -f "$backup_dir/latest.tgz" ]; then
    tar -xzf "$backup_dir/latest.tgz" -C "${var%/}"
    chmod 0755 "${var%/}"   # NSD runs as its own user and reads the zone list and zone file from here
    log "restore: the volume was empty, restored from $backup_dir/latest.tgz ($(date -u -r "$backup_dir/latest.tgz" +%FT%TZ))"
  else
    log "restore: the volume is empty and there is no backup; the zone manager will create new keys"
  fi
}

ds_of() {
  tmp="$(mktemp)"
  drill -o rd "@$(resolve "$1")" "$zone" DNSKEY 2>/dev/null | awk '$4=="DNSKEY" && $5==257' > "$tmp"
  [ -s "$tmp" ] || { rm -f "$tmp"; log "ds FAILED: no key-signing key served by $1"; return 1; }
  ldns-key2ds -n -2 "$tmp"
  rm -f "$tmp"
}

record_ds() {
  server="${DNS_SERVICE:?DNS_SERVICE is not set}"
  name="${DS_CONFIGMAP:?DS_CONFIGMAP is not set}"
  i=0
  until [ -n "$(soa_expiration "$server")" ]; do
    i=$((i + 1)); [ "$i" -le 60 ] || { log "record-ds FAILED: $server does not serve $zone signed"; return 1; }
    sleep 2
  done
  ds="$(ds_of "$server")"
  python3 - "$name" "$ds" "$zone" <<'PY'
import json, os, sys, requests
name, ds, zone = sys.argv[1:4]
sa = "/var/run/secrets/kubernetes.io/serviceaccount"
ns = open(f"{sa}/namespace").read().strip()
api = f"https://{os.environ['KUBERNETES_SERVICE_HOST']}:{os.environ.get('KUBERNETES_SERVICE_PORT', '443')}"
headers = {"Authorization": "Bearer " + open(f"{sa}/token").read().strip(), "Content-Type": "application/json"}
body = {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": name, "namespace": ns,
        "labels": {"app.kubernetes.io/name": "train-zone-manager", "ztd.facis.io/record": "ds"}},
        "data": {"zone": zone, "ds": ds + "\n"}}
url = f"{api}/api/v1/namespaces/{ns}/configmaps"
r = requests.get(f"{url}/{name}", headers=headers, verify=f"{sa}/ca.crt", timeout=10)
if r.status_code == 404:
    r = requests.post(url, headers=headers, verify=f"{sa}/ca.crt", json=body, timeout=10)
elif r.ok:
    r = requests.put(f"{url}/{name}", headers=headers, verify=f"{sa}/ca.crt", json=body, timeout=10)
r.raise_for_status()
print(f"ConfigMap {ns}/{name}: {ds}")
PY
}

# The upstream writes the zone's A records - the apex and the glue of its name servers - into its
# database at the first start, from TF_DOMAIN_IP and the *_SERVER_IP variables, and has no command
# to change them afterwards. So the address has to be right before that start. This step runs as an
# init container: once the zone exists it does nothing; otherwise it takes the address from the
# values, or waits for the one the LoadBalancer Service was given, and writes the variables that are
# still empty into address.env on the state volume, which the image's entry point sources.
address() {
  env_file="${var%/}/address.env"
  if [ -f "${var%/}/zones.db" ]; then
    log "address: the zone exists; its records are in the database"
    return 0
  fi
  if [ -n "${ZONE_ADDRESS:-}" ]; then
    addr="$ZONE_ADDRESS"; source="the values"
  else
    svc="${DNS_SERVICE:?neither ZONE_ADDRESS nor DNS_SERVICE is set}"
    log "address: waiting for the address of Service $svc"
    addr="$(python3 - "$svc" <<'PY'
import os, sys, time, requests
svc = sys.argv[1]
sa = "/var/run/secrets/kubernetes.io/serviceaccount"
ns = open(f"{sa}/namespace").read().strip()
api = f"https://{os.environ['KUBERNETES_SERVICE_HOST']}:{os.environ.get('KUBERNETES_SERVICE_PORT', '443')}"
headers = {"Authorization": "Bearer " + open(f"{sa}/token").read().strip()}
deadline = time.time() + int(os.environ.get("ADDRESS_TIMEOUT", "600"))
while time.time() < deadline:
    r = requests.get(f"{api}/api/v1/namespaces/{ns}/services/{svc}", headers=headers, verify=f"{sa}/ca.crt", timeout=10)
    r.raise_for_status()
    for ingress in (r.json().get("status", {}).get("loadBalancer", {}).get("ingress") or []):
        if ingress.get("ip"):
            print(ingress["ip"]); sys.exit(0)
    time.sleep(5)
sys.exit(1)
PY
)" || { log "address FAILED: Service $svc received no address; the zone manager must not start on a guess"; return 1; }
    source="Service $svc"
  fi
  : > "$env_file"
  for name in TF_DOMAIN_IP PRIMARY_SERVER_IP SECONDARY_SERVER_1_IP SECONDARY_SERVER_2_IP; do
    eval "current=\${$name:-}"
    [ -n "$current" ] || printf 'export %s=%s\n' "$name" "$addr" >> "$env_file"
  done
  log "address: $addr from $source; $(grep -c . "$env_file") variable(s) written to $env_file"
}

daily() {
  ensure_control
  at="${RESIGN_AT:-00:05}"
  log "daily: resign and backup at $at UTC"
  while :; do
    now=$(date -u +%s)
    next=$(date -u -d "today $at" +%s)
    [ "$next" -gt "$now" ] || next=$(date -u -d "tomorrow $at" +%s)
    log "daily: next run at $(date -u -d "@$next" +%FT%TZ)"
    sleep $((next - now))
    resign_now || log "daily: resign failed; the signatures expire 28 days after the last successful write"
    backup_now || log "daily: backup failed"
  done
}

case "${1:-}" in
  daily) daily ;;
  resign-now) resign_now "${2:-}" ;;
  backup-now) backup_now ;;
  restore-if-empty) restore_if_empty ;;
  ds) ds_of "${2:-$nsd_host}" ;;
  record-ds) record_ds ;;
  address) address ;;
  *) echo "usage: zone-keeper daily|resign-now [db-url]|backup-now|restore-if-empty|ds [server]|record-ds|address" >&2; exit 2 ;;
esac
