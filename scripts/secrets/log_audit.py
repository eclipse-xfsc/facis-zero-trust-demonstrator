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
"""
import argparse
import base64
import hashlib
import json
import os
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


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("derive")
    d.add_argument("kind", choices=["canary", "mask-control"])
    a = sub.add_parser("audit")
    a.add_argument("--job", required=True)
    a.add_argument("--evidence", required=True)
    args = ap.parse_args()
    if args.cmd == "derive":
        e = os.environ
        print(derive(args.kind, e["GITHUB_REPOSITORY"], e["GITHUB_RUN_ID"], e["GITHUB_RUN_ATTEMPT"]))
        return 0
    return audit(args)


if __name__ == "__main__":
    sys.exit(main())
