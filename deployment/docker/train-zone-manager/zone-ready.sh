#!/bin/sh
# Readiness for the zone manager: NSD must answer authoritatively for the trust framework's zone.
# `nsd-control zonestatus` only says whether the zone is configured, and after any start of the
# unpatched upstream it is not; so the probe also asks the server for the SOA and requires an
# authoritative NOERROR answer. A pod that fails either check receives no traffic from the Service.
#
#   zone-ready            (TF_DOMAIN_NAME from the environment, as script.sh reads it)
set -eu
zone="${TF_DOMAIN_NAME:?TF_DOMAIN_NAME is not set}"
nsd-control zonestatus "$zone" >/dev/null 2>&1 || { echo "$zone is not configured in NSD" >&2; exit 1; }
answer="$(drill -o rd @127.0.0.1 "$zone" SOA 2>/dev/null)" || { echo "$zone: no answer from NSD" >&2; exit 1; }
case "$answer" in
  *"rcode: NOERROR"*) ;;
  *) echo "$zone: NSD did not answer NOERROR for the SOA" >&2; exit 1 ;;
esac
case "$answer" in
  *"flags: qr aa"*) exit 0 ;;
  *) echo "$zone: the SOA answer is not authoritative" >&2; exit 1 ;;
esac
