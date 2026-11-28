"""Re-publish a TRAIN trust list unchanged, so that TSPA signs its VC with a new validity window.

TSPA signs the trust-list VC only on a publication. This reads the list, PATCHes its first entry
back as read a moment before, and passes only when the PATCH is accepted and the VC then expires
later than it did before. TSPA has no write precondition: a publication landing between this read
and this write is overwritten for that entry, so publishers of the framework must not run at the
job's minute (docs/tspa-publish-api.md, 7.1). Prints HTTP statuses and the windows; never the
token or the client secret.
"""
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime

FW = os.environ["FRAMEWORK"]
API = os.environ["TSPA_URL"].rstrip("/")


def call(method, url, body=None, headers=None):
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, b""


def vc_expiry():
    status, body = call("GET", f"{API}/{FW}/vc/trust-list")
    if status != 200:
        sys.exit(f"GET vc/trust-list: HTTP {status}")
    vc = json.loads(body)
    print(f"VC {vc.get('issuanceDate')} .. {vc.get('expirationDate')}")
    return datetime.fromisoformat(vc["expirationDate"])


with open("/var/run/client/secret") as f:
    secret = f.read().strip()
form = urllib.parse.urlencode(
    {"grant_type": "client_credentials", "client_id": os.environ["CLIENT_ID"], "client_secret": secret}
).encode()
status, body = call("POST", os.environ["TOKEN_URL"], form, {"Content-Type": "application/x-www-form-urlencoded"})
if status != 200:
    sys.exit(f"token: HTTP {status}")
token = json.loads(body)["access_token"]

before = vc_expiry()
status, body = call("GET", f"{API}/{FW}/trust-list")
if status != 200:
    sys.exit(f"GET trust-list: HTTP {status}")
tsps = json.loads(body)["TrustServiceStatusList"].get("TrustServiceProviderList", {}).get("TrustServiceProvider") or []
if isinstance(tsps, dict):
    tsps = [tsps]
if not tsps:
    sys.exit("the trust list has no entry to re-publish")
entry = tsps[0]

status, _ = call(
    "PATCH",
    f"{API}/{FW}/trust-list/tsp/{urllib.parse.quote(entry['UUID'], safe='')}",
    json.dumps({"TrustServiceProvider": entry}).encode(),
    {"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
)
print(f"PATCH entry {entry['UUID']}: HTTP {status}")
if status != 200:
    sys.exit(1)
# The status alone proves nothing (TSPA answers 200 to a request it never ran); the window does.
if vc_expiry() <= before:
    sys.exit("the VC's window was not renewed")
