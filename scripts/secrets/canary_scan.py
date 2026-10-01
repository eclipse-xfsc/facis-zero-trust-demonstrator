#!/usr/bin/env python3
"""Canary-secret scan of a cluster (TDR-BDD-08, docs/secrets.md).

Seeds a synthetic credential (the canary, from ZTD_CANARY) into a Kubernetes Secret that a probe pod
in the data plane consumes as an environment variable and as a file, then collects the raw output of
every container in every namespace - init containers too, and the previous instance of any container
that restarted - and every ConfigMap (data and decoded binaryData), and searches them for:

  - the canary, plain and base64-encoded;
  - the live credentials of the bundled OpenBao, read from the cluster: the unseal key and the
    verification token (Secret ztd-openbao-bootstrap) and the fixture KV value (read with that token);
  - shapes of credentials: PEM private keys, OpenBao/Vault tokens, and in ConfigMaps non-empty
    password fields. A shape match is a pattern check: the root token is revoked and gone by now, so
    it can only be found by its shape.

Pod specs are searched too: a credential written into an env value is plaintext outside a Secret.

A negative control proves the scan can find what it looks for: a pod in its own namespace prints the
canary, and the scan must detect it there. It is scanned and reported apart from the baseline.

Nothing found is printed and no value is written: the evidence holds counts, scope, locations by
pod/container/ConfigMap name, and the canary's SHA-256. Raw output stays in memory. A failure to
collect is reported by operation and exit status, never by kubectl's own message.

A scan is one stage (--stage, default final) and writes scan-<stage>.json. Logs vanish when a pod is
deleted or a hook replaced, so the baseline scans after the install and again at the end; the final
stage folds every earlier stage of the directory into scan.json, which is clean only if all were.
Exit status 0 only when the stage is clean, nothing failed to collect and the control was detected.

  ZTD_CANARY=<synthetic value> scripts/secrets/canary_scan.py --evidence DIR --target T --run R [--stage S]
"""
import argparse
import base64
import hashlib
import json
import os
import re
import socket
import subprocess
import sys
import time
import urllib.request

DATA_NS = "ztd-data"
MGMT_NS = "ztd-mgmt"
LEAK_NS = "ztd-canary-control"
PROBE = "ztd-canary-probe"

SHAPES = {
    "pem-private-key": re.compile(r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----"),
    "openbao-token": re.compile(r"(?<![A-Za-z0-9._-])(?:hv[sbr]|[sbr])\.[A-Za-z0-9]{24,}(?![A-Za-z0-9])"),
}
CONFIGMAP_SHAPES = dict(SHAPES, **{
    "password-field": re.compile(r"(?i)\b(?:password|passwd)[\"']?[ \t]*[:=][ \t]*[\"']?[^\s\"'{}<>,;]+"),
})
# A ConfigMap key named like a credential, with a value, is a credential outside a Secret.
CREDENTIAL_KEY = re.compile(r"(?i)(password|passwd|secret|token|api[-_.]?key|private[-_.]?key|credential)")


def kubectl(*args, stdin=None, check=True):
    """Runs kubectl. A failure is reported by operation and exit status only: kubectl's own message can
    quote what it was given - a Secret's value among it - and evidence must never carry that."""
    p = subprocess.run(["kubectl", *args], input=stdin, capture_output=True, text=True)
    if check and p.returncode != 0:
        raise RuntimeError(f"kubectl {' '.join(a for a in args[:3] if not a.startswith('-'))} failed (exit {p.returncode})")
    return p


def secret_and_pod(ns, name, image, command):
    """A Secret holding the canary and a restricted pod consuming it as env and file."""
    return json.dumps({"apiVersion": "v1", "kind": "List", "items": [
        {"apiVersion": "v1", "kind": "Secret", "metadata": {"name": name, "namespace": ns},
         "type": "Opaque", "stringData": {"credential": os.environ["ZTD_CANARY"]}},
        {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name, "namespace": ns, "labels": {"app.kubernetes.io/name": name}},
         "spec": {
             "automountServiceAccountToken": False, "restartPolicy": "Never",
             "securityContext": {"runAsNonRoot": True, "runAsUser": 100, "seccompProfile": {"type": "RuntimeDefault"}},
             "containers": [{
                 "name": "app", "image": image, "command": ["/bin/sh", "-c", command],
                 "env": [{"name": "CREDENTIAL", "valueFrom": {"secretKeyRef": {"name": name, "key": "credential"}}}],
                 "volumeMounts": [{"name": "cred", "mountPath": "/cred", "readOnly": True}],
                 "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}},
             }],
             "volumes": [{"name": "cred", "secret": {"secretName": name}}],
         }},
    ]})


def wait_ready(ns, name):
    kubectl("-n", ns, "wait", "--for=condition=Ready", f"pod/{name}", "--timeout=180s")


def live_credentials():
    """The bundled OpenBao's credentials, read from the cluster; empty when it is not installed."""
    p = kubectl("-n", MGMT_NS, "get", "secret", "ztd-openbao-bootstrap", "-o", "json", check=False)
    if p.returncode != 0:
        return {}
    data = {k: base64.b64decode(v).decode() for k, v in json.loads(p.stdout).get("data", {}).items()}
    found = {k: data[k] for k in ("unseal-key", "verify-token", "root-token") if data.get(k)}
    if "verify-token" in found:
        found["fixture-kv-value"] = fixture_value(found["verify-token"])
    return found


def fixture_value(token):
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    pf = subprocess.Popen(["kubectl", "-n", MGMT_NS, "port-forward", "svc/ztd-openbao", f"{port}:8200"],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(30):
            try:
                req = urllib.request.Request(f"http://127.0.0.1:{port}/v1/secret/data/ztd-fixture/canary",
                                             headers={"X-Vault-Token": token})
                with urllib.request.urlopen(req, timeout=5) as r:
                    return json.load(r)["data"]["data"]["value"]
            except OSError:
                time.sleep(1)
        raise RuntimeError("cannot read the fixture KV value through a port-forward to ztd-openbao")
    finally:
        pf.terminate()


def needles(values):
    out = {}
    for name, value in values.items():
        out[name] = value
        out[name + " (base64)"] = base64.b64encode(value.encode()).decode()
    return out


def search(text, values, shapes):
    hits = {name: text.count(v) for name, v in values.items() if v and v in text}
    hits.update({name: len(rx.findall(text)) for name, rx in shapes.items() if rx.search(text)})
    return hits


def collect_logs(namespaces_excluded=(), only_ns=None):
    """Every container's output and every pod spec as (location, text); and what could not be collected."""
    pods = json.loads(kubectl("get", "pods", "-A", "-o", "json").stdout)["items"]
    scope = {"pods": 0, "containers": 0, "previous": 0, "notStarted": 0}
    errors = []
    texts = []
    for pod in pods:
        ns, name = pod["metadata"]["namespace"], pod["metadata"]["name"]
        if ns in namespaces_excluded or (only_ns and ns != only_ns):
            continue
        scope["pods"] += 1
        statuses = {s["name"]: s for s in pod["status"].get("initContainerStatuses", []) + pod["status"].get("containerStatuses", [])}
        specs = pod["spec"].get("initContainers", []) + pod["spec"]["containers"]
        texts.append((f"{ns}/{name} spec", json.dumps(specs)))
        for c in specs:
            st = statuses.get(c["name"], {})
            if not ({"running", "terminated"} & set(st.get("state", {}))) and not st.get("lastState"):
                scope["notStarted"] += 1  # never ran: no output exists, which is not a collection failure
                continue
            p = kubectl("-n", ns, "logs", name, "-c", c["name"], check=False)
            if p.returncode != 0:
                errors.append(f"{ns}/{name}/{c['name']}: logs not collected (exit {p.returncode})")
                continue
            scope["containers"] += 1
            texts.append((f"{ns}/{name}/{c['name']}", p.stdout))
            if st.get("restartCount", 0) > 0:
                p = kubectl("-n", ns, "logs", name, "-c", c["name"], "--previous", check=False)
                if p.returncode != 0:
                    errors.append(f"{ns}/{name}/{c['name']} (previous): logs not collected (exit {p.returncode})")
                    continue
                scope["previous"] += 1
                texts.append((f"{ns}/{name}/{c['name']} (previous)", p.stdout))
    return texts, scope, errors


def collect_configmaps():
    """Every ConfigMap as (location, text), each entry as "key: value" so a credential-named key is
    seen with its value; binaryData decoded. Also the keys named like a credential that hold a value."""
    items = json.loads(kubectl("get", "configmaps", "-A", "-o", "json").stdout)["items"]
    texts, keyed = [], []
    for cm in items:
        loc = f"{cm['metadata']['namespace']}/configmap/{cm['metadata']['name']}"
        entries = dict(cm.get("data") or {})
        for k, v in (cm.get("binaryData") or {}).items():
            entries[k] = base64.b64decode(v).decode("utf-8", "replace")
        texts.append((loc, "\n".join(f"{k}: {v}" for k, v in entries.items())))
        names = sorted(k for k, v in entries.items() if v.strip() and CREDENTIAL_KEY.search(k))
        if names:
            keyed.append({"location": loc, "hits": {"credential-key": len(names)}, "keys": names})
    return texts, keyed


def scan(texts, values, shapes):
    findings = []
    for loc, text in texts:
        hits = search(text, values, shapes)
        if hits:
            findings.append({"location": loc, "hits": hits})
    return findings


def fold(evidence, final):
    """Writes scan.json from every scan-<stage>.json in the directory: findings and errors of all
    stages (each labelled with its stage), scope per stage; clean only if every stage was."""
    stages = []
    for name in sorted(os.listdir(evidence)):
        if name.startswith("scan-") and name.endswith(".json"):
            with open(os.path.join(evidence, name)) as f:
                stages.append(json.load(f))
    merged = {k: final.get(k) for k in ("target", "run", "canarySha256", "label", "credentials")}
    # Every stage must be this run's, with this canary: an earlier run's scan left in the directory
    # must not stand in for one of this run's stages.
    foreign = [s.get("stage") for s in stages
               if any(s.get(k) != final.get(k) for k in ("target", "run", "canarySha256"))]
    merged["stages"] = [s["stage"] for s in stages]
    merged["scope"] = {s["stage"]: s.get("scope", {}) for s in stages}
    merged["baseline"] = [dict(f, stage=s["stage"]) for s in stages for f in (s.get("baseline") or [])]
    merged["errors"] = [f"{s['stage']}: {e}" for s in stages for e in s.get("errors", [])]
    merged["errors"] += [f"{st}: from another run, target or canary" for st in foreign]
    merged["negativeControl"] = {"detected": all(s.get("negativeControl", {}).get("detected") for s in stages)}
    clean = not foreign and all(s.get("result") == "clean" for s in stages) and any(s["stage"] == "final" for s in stages)
    merged["result"] = "clean" if clean else "failed"
    with open(os.path.join(evidence, "scan.json"), "w") as f:
        json.dump(merged, f, indent=2)
    print(f"stages {', '.join(merged['stages'])}: {merged['result']}")
    return clean


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--evidence", required=True)
    ap.add_argument("--target", required=True)
    ap.add_argument("--run", required=True)
    ap.add_argument("--stage", default="final")
    ap.add_argument("--image", default="docker.io/curlimages/curl:8.10.1@sha256:d9b4541e214bcd85196d6e92e2753ac6d0ea699f0af5741f8c6cccbfcf00ef4b")
    args = ap.parse_args()
    canary = os.environ.get("ZTD_CANARY", "")
    if len(canary) < 16:
        sys.exit("ZTD_CANARY must hold the synthetic canary (16 characters or more)")

    record = {"target": args.target, "run": args.run, "canarySha256": hashlib.sha256(canary.encode()).hexdigest(),
              "label": "synthetic canary; disposable cluster", "errors": []}
    try:
        kubectl("apply", "-f", "-", stdin=secret_and_pod(DATA_NS, PROBE, args.image,
                'test -n "$CREDENTIAL" && test -s /cred/credential && echo "probe: credential loaded from its Secret"; sleep 3600'))
        kubectl("create", "namespace", LEAK_NS, check=False)
        kubectl("apply", "-f", "-", stdin=secret_and_pod(LEAK_NS, PROBE, args.image, 'echo "control: $CREDENTIAL"; sleep 3600'))
        wait_ready(DATA_NS, PROBE)
        wait_ready(LEAK_NS, PROBE)

        live = live_credentials()
        values = needles(dict(live, canary=canary))
        record["credentials"] = {"searched": sorted(values), "heldInSecrets": sorted(
            [f"{MGMT_NS}/secret/ztd-openbao-bootstrap:{k}" for k in live if k != "fixture-kv-value"] +
            [f"{DATA_NS}/secret/{PROBE}:credential"])}

        logs, scope, errors = collect_logs(namespaces_excluded=(LEAK_NS,))
        configmaps, credential_keys = collect_configmaps()
        scope["configMaps"] = len(configmaps)
        record["scope"] = scope
        record["errors"] = errors
        record["baseline"] = scan(logs, values, SHAPES) + scan(configmaps, values, CONFIGMAP_SHAPES) + credential_keys

        control_logs, _, control_errors = collect_logs(only_ns=LEAK_NS)
        control = scan([t for t in control_logs if not t[0].endswith(" spec")], needles({"canary": canary}), {})
        record["negativeControl"] = {"namespace": LEAK_NS, "detected": bool(control), "errors": control_errors}
    except Exception as e:  # any setup or collection failure is a failed scan, never a clean one
        record["errors"].append(f"{type(e).__name__}: {e}" if isinstance(e, RuntimeError) else type(e).__name__)
    finally:
        kubectl("-n", DATA_NS, "delete", "pod,secret", PROBE, "--ignore-not-found", "--wait=true", check=False)
        kubectl("delete", "namespace", LEAK_NS, "--ignore-not-found", "--wait=true", check=False)

    clean = not record["errors"] and record.get("baseline") == [] and record.get("negativeControl", {}).get("detected")
    record["stage"] = args.stage
    record["result"] = "clean" if clean else "failed"
    os.makedirs(args.evidence, exist_ok=True)
    with open(os.path.join(args.evidence, f"scan-{args.stage}.json"), "w") as f:
        json.dump(record, f, indent=2)
    if args.stage == "final":
        clean = fold(args.evidence, record) and clean
    s = record.get("scope", {})
    print(f"canary scan ({args.stage}) on {args.target}: {s.get('pods', 0)} pods, {s.get('containers', 0)} container logs, "
          f"{s.get('previous', 0)} previous logs, {s.get('configMaps', 0)} ConfigMaps; "
          f"findings {len(record.get('baseline') or [])}, errors {len(record['errors'])}, "
          f"control detected {record.get('negativeControl', {}).get('detected')}: {record['result']}")
    for f in record.get("baseline") or []:
        print(f"  finding at {f['location']}: {', '.join(sorted(f['hits']))}")
    for e in record["errors"]:
        print(f"  error: {e}")
    sys.exit(0 if clean else 1)


if __name__ == "__main__":
    main()
