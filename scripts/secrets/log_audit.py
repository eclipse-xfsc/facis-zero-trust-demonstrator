#!/usr/bin/env python3
"""Pipeline-log audit for the secret-handling baseline (TDR-BDD-08, docs/secrets.md).

The secrets-baseline job (the producer) seeds a synthetic canary into the cluster and prints a masking
control line after registering both values with ::add-mask::. Once that job has completed, a later job
in the same run downloads the producer job's published log through the job-level REST endpoint and
requires: the canary absent (plain and base64), the control line present as ZTD_MASK_CONTROL=*** and
its raw value absent. The control makes the check non-vacuous: a log in which nothing was masked, or
the wrong log, cannot pass. Both values are derived from the run, never real credentials:

  sha256("ztd-<kind>-v1:<repository>:<run id>:<run attempt>"), first 40 hex characters

  log_audit.py derive canary|mask-control        print a value for the current run (GITHUB_* env)
  log_audit.py audit --job NAME --evidence DIR   audit the named job of the current run attempt

The audit uses GITHUB_TOKEN (actions: read), GITHUB_REPOSITORY, GITHUB_RUN_ID, GITHUB_RUN_ATTEMPT and
GITHUB_API_URL. It checks that the producer's evidence (scan.json) names the same run and attempt, and
writes log-audit.json: counts and booleans only.

A second, separate mode audits the jobs that hold signing key material (ZT-10), whatever their
outcome - a failed signing job is audited like a successful one:

  log_audit.py signing-audit --job NAME [--job NAME ...] --out DIR

Every named job of the current run attempt that started is scanned for private-key material: PEM
private-key blocks (cosign's encrypted key included), the same blocks base64-encoded, cosign's key
encryption markers, a signing password or token variable printed with a value instead of ***, and
Vault/OpenBao token shapes. A name absent from the run, or a job that never started (refused by the
environment, skipped), is recorded and not scanned; a run in which no named job exists at all fails,
since the names no longer match the workflow. It
writes signing-audit.json - counts and verdicts, never a matched text - and fails on any hit.
"""
import argparse
import base64
import hashlib
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request


def derive(kind, repo, run_id, attempt):
    return hashlib.sha256(f"ztd-{kind}-v1:{repo}:{run_id}:{attempt}".encode()).hexdigest()[:40]


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def api(path, token, base):
    """GET a GitHub API path; returns (status, body bytes, Location header)."""
    req = urllib.request.Request(base + path, headers={
        "Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"})
    opener = urllib.request.build_opener(NoRedirect)
    try:
        with opener.open(req, timeout=30) as r:
            return r.status, r.read(), r.headers.get("Location")
    except urllib.error.HTTPError as e:
        return e.code, e.read(), e.headers.get("Location")


def producer_job(name, repo, run_id, attempt, token, base):
    status, body, _ = api(f"/repos/{repo}/actions/runs/{run_id}/attempts/{attempt}/jobs?per_page=100", token, base)
    if status != 200:
        raise RuntimeError(f"listing the jobs of run {run_id} attempt {attempt}: HTTP {status}")
    jobs = [j for j in json.loads(body)["jobs"] if j["name"] == name]
    if len(jobs) != 1:
        raise RuntimeError(f"expected one job named {name!r} in run {run_id} attempt {attempt}, found {len(jobs)}")
    job = jobs[0]
    if job["status"] != "completed" or job["conclusion"] != "success":
        raise RuntimeError(f"job {name!r} is {job['status']}/{job['conclusion']}, not completed/success")
    return job["id"]


def job_log(job_id, repo, token, base):
    """The job's plain-text log. The API answers with a redirect to a short-lived signed URL, which is
    followed without the token; an empty or unavailable log is retried, then fails."""
    last = ""
    for _ in range(6):
        status, _, location = api(f"/repos/{repo}/actions/jobs/{job_id}/logs", token, base)
        if status == 302 and location:
            with urllib.request.urlopen(location, timeout=60) as r:
                text = r.read().decode("utf-8", "replace")
            if text.strip():
                return text
            last = "empty log"
        else:
            last = f"HTTP {status}"
        time.sleep(10)
    raise RuntimeError(f"the log of job {job_id} is not available ({last})")


def audit(args):
    env = os.environ
    repo, run_id, attempt = env["GITHUB_REPOSITORY"], env["GITHUB_RUN_ID"], env["GITHUB_RUN_ATTEMPT"]
    base = env.get("GITHUB_API_URL", "https://api.github.com")
    run = f"ci-{run_id}-{attempt}"
    record = {"producerJob": args.job, "run": run, "commit": env.get("GITHUB_SHA", ""), "errors": []}
    try:
        with open(os.path.join(args.evidence, "scan.json")) as f:
            scan = json.load(f)
        if scan.get("run") != run:
            raise RuntimeError(f"the producer evidence is from run {scan.get('run')!r}, not {run!r}: rerun the producer job")
        canary = derive("canary", repo, run_id, attempt)
        control = derive("mask-control", repo, run_id, attempt)
        if scan.get("canarySha256") != hashlib.sha256(canary.encode()).hexdigest():
            raise RuntimeError("the producer evidence was made with another canary")
        job_id = producer_job(args.job, repo, run_id, attempt, env["GITHUB_TOKEN"], base)
        log = job_log(job_id, repo, env["GITHUB_TOKEN"], base)
        record.update({
            "jobId": job_id,
            "logBytes": len(log),
            "canaryHits": log.count(canary) + log.count(base64.b64encode(canary.encode()).decode()),
            "controlRawHits": log.count(control),
            "controlRedacted": "ZTD_MASK_CONTROL=***" in log,
        })
    except Exception as e:  # anything unverifiable is a failed audit, never a clean one
        record["errors"].append(str(e))
    clean = (not record["errors"] and record.get("canaryHits") == 0 and record.get("controlRawHits") == 0
             and record.get("controlRedacted") is True)
    record["result"] = "clean" if clean else "failed"
    with open(os.path.join(args.evidence, "log-audit.json"), "w") as f:
        json.dump(record, f, indent=2)
    print(f"log audit of {args.job!r} ({run}): {record.get('logBytes', 0)} bytes, canary hits {record.get('canaryHits')}, "
          f"control redacted {record.get('controlRedacted')}, control raw hits {record.get('controlRawHits')}: {record['result']}")
    for e in record["errors"]:
        print(f"  error: {e}")
    return 0 if clean else 1


SIGNING_PATTERNS = {
    "pemPrivateKey": re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    "cosignKeyMarker": re.compile(r"ENCRYPTED (?:SIGSTORE|COSIGN) PRIVATE KEY|nacl/secretbox"),
    # A variable that holds a password or token, printed with a value: GitHub prints *** for a secret.
    "secretValue": re.compile(r"\b(?:COSIGN_(?:INTERIM_|CLIENT_)?PASSWORD|VAULT_TOKEN|SIGNING_VAULT_TOKEN|HARBOR_\w*PASSWORD)"
                              r"[ \t]*[:=][ \t]*(?!\*\*\*)[^\s*]\S*"),
    "vaultToken": re.compile(r"(?<![\w.])(?:hvs|hvb|s)\.[A-Za-z0-9_-]{24,}"),
}
PEM_BASE64 = re.compile(r"LS0tLS1CRUdJTi[A-Za-z0-9+/]+={0,2}")


def scan_signing_log(text):
    """Counts of private-key material in one log, by pattern; never the matched text."""
    counts = {name: len(p.findall(text)) for name, p in SIGNING_PATTERNS.items()}
    hits = 0
    for blob in PEM_BASE64.findall(text):
        try:
            decoded = base64.b64decode(blob + "=" * (-len(blob) % 4)).decode("ascii", "replace")
        except ValueError:
            continue
        hits += "PRIVATE KEY" in decoded
    counts["pemPrivateKeyBase64"] = hits
    return counts


def run_jobs(repo, run_id, attempt, token, base):
    status, body, _ = api(f"/repos/{repo}/actions/runs/{run_id}/attempts/{attempt}/jobs?per_page=100", token, base)
    if status != 200:
        raise RuntimeError(f"listing the jobs of run {run_id} attempt {attempt}: HTTP {status}")
    return json.loads(body)["jobs"]


def signing_audit(args):
    env = os.environ
    repo, run_id, attempt = env["GITHUB_REPOSITORY"], env["GITHUB_RUN_ID"], env["GITHUB_RUN_ATTEMPT"]
    base = env.get("GITHUB_API_URL", "https://api.github.com")
    record = {"run": f"ci-{run_id}-{attempt}", "commit": env.get("GITHUB_SHA", ""), "jobs": [], "errors": []}
    try:
        jobs = run_jobs(repo, run_id, attempt, env["GITHUB_TOKEN"], base)
        for name in args.job:
            matching = [j for j in jobs if j["name"] == name]
            if not matching:
                record["jobs"].append({"name": name, "state": "absent"})
            for job in matching:
                entry = {"name": name, "jobId": job["id"], "conclusion": job.get("conclusion")}
                started = any(s.get("conclusion") not in (None, "skipped") for s in job.get("steps") or [])
                if job.get("status") != "completed":
                    raise RuntimeError(f"job {name!r} is {job.get('status')}, not completed")
                if not started:
                    entry["state"] = "not started"
                else:
                    log = job_log(job["id"], repo, env["GITHUB_TOKEN"], base)
                    entry.update({"state": "scanned", "logBytes": len(log), "hits": scan_signing_log(log)})
                record["jobs"].append(entry)
    except Exception as e:  # anything unverifiable is a failed audit, never a clean one
        record["errors"].append(str(e))
    scanned = [j for j in record["jobs"] if j["state"] == "scanned"]
    hits = sum(sum(j["hits"].values()) for j in scanned)
    if all(j["state"] == "absent" for j in record["jobs"]) and not record["errors"]:
        record["errors"].append("no job of this run has any of the names given: the audit names no longer match the workflow")
    record["result"] = "clean" if not record["errors"] and hits == 0 else "failed"
    os.makedirs(args.out, exist_ok=True)
    with open(os.path.join(args.out, "signing-audit.json"), "w") as f:
        json.dump(record, f, indent=2)
    for j in record["jobs"]:
        detail = f", {j['logBytes']} bytes, hits {j['hits']}" if j["state"] == "scanned" else ""
        print(f"signing log audit: {j['name']!r} {j['state']}{detail}")
    for e in record["errors"]:
        print(f"  error: {e}")
    print(f"signing log audit ({record['run']}): {record['result']}")
    return 0 if record["result"] == "clean" else 1


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("derive")
    d.add_argument("kind", choices=["canary", "mask-control"])
    a = sub.add_parser("audit")
    a.add_argument("--job", required=True)
    a.add_argument("--evidence", required=True)
    g = sub.add_parser("signing-audit")
    g.add_argument("--job", action="append", required=True, help="a signing job's name; repeat for each")
    g.add_argument("--out", required=True)
    args = ap.parse_args()
    if args.cmd == "derive":
        e = os.environ
        print(derive(args.kind, e["GITHUB_REPOSITORY"], e["GITHUB_RUN_ID"], e["GITHUB_RUN_ATTEMPT"]))
        return 0
    if args.cmd == "signing-audit":
        return signing_audit(args)
    return audit(args)


if __name__ == "__main__":
    sys.exit(main())
