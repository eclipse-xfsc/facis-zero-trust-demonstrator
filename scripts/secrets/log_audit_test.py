"""Cases for log_audit.py's signing-audit mode (the canary mode is unchanged and proved by its row).

    python3 -m unittest scripts/secrets/log_audit_test.py
"""
import base64
import json
import os
import sys
import tempfile
import types
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import log_audit  # noqa: E402

PRIVATE = "-----BEGIN ENCRYPTED SIGSTORE PRIVATE KEY-----\neyJrZGYiOnt9fQ==\n-----END ENCRYPTED SIGSTORE PRIVATE KEY-----"
CLEAN = """##[group]Run scripts/supplychain/check-key.sh
env:
  COSIGN_INTERIM_KEY: ***
  COSIGN_PASSWORD: ***
  COSIGN_CLIENT_KEY: 
  VAULT_TOKEN: 
  SIGNING_KEY_SOURCE: interim
##[endgroup]
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE0lFmUtbg0hz8DzhKG9mz6lKqU1Zf
-----END PUBLIC KEY-----
LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0K
check-key: env://COSIGN_INTERIM_KEY matches docs/contracts/keys/interim-cosign.pub
"""


class ScanTest(unittest.TestCase):
    def test_clean_log(self):
        self.assertEqual(sum(log_audit.scan_signing_log(CLEAN).values()), 0, log_audit.scan_signing_log(CLEAN))

    def test_each_kind_of_material(self):
        cases = {
            "pemPrivateKey": "-----BEGIN EC PRIVATE KEY-----",
            "cosignKeyMarker": '{"cipher":{"name":"nacl/secretbox"}}',
            "pemPrivateKeyBase64": base64.b64encode(PRIVATE.encode()).decode(),
            "secretValue": "  COSIGN_PASSWORD: hunter2",
            "vaultToken": "token hvs.CAESIabcdefghijklmnopqrstuvwxyz0123",
        }
        for name, text in cases.items():
            with self.subTest(name):
                counts = log_audit.scan_signing_log(CLEAN + text + "\n")
                self.assertGreater(counts[name], 0, counts)

    def test_encrypted_cosign_key_block_and_markers(self):
        counts = log_audit.scan_signing_log(PRIVATE)
        self.assertEqual((counts["pemPrivateKey"], counts["cosignKeyMarker"]), (1, 2))  # BEGIN once, marker in BEGIN and END

    def test_masked_and_empty_values_are_not_hits(self):
        text = "VAULT_TOKEN: ***\nHARBOR_PUSH_PASSWORD=***\nCOSIGN_PASSWORD:\nnext-line-value\n"
        self.assertEqual(log_audit.scan_signing_log(text)["secretValue"], 0)


class SigningAuditTest(unittest.TestCase):
    def setUp(self):
        self.out = tempfile.mkdtemp()
        os.environ.update(GITHUB_REPOSITORY="o/r", GITHUB_RUN_ID="7", GITHUB_RUN_ATTEMPT="1", GITHUB_TOKEN="t")
        self.logs = {}
        self.jobs = []
        self._orig = (log_audit.run_jobs, log_audit.job_log)
        log_audit.run_jobs = lambda *a: self.jobs
        log_audit.job_log = lambda job_id, *a: self.logs[job_id]

    def tearDown(self):
        log_audit.run_jobs, log_audit.job_log = self._orig

    def job(self, id_, name, conclusion, started=True):
        steps = [{"name": "Set up job", "conclusion": "success"}] if started else []
        self.jobs.append({"id": id_, "name": name, "status": "completed", "conclusion": conclusion, "steps": steps})

    def audit(self, *names):
        code = log_audit.signing_audit(types.SimpleNamespace(job=list(names), out=self.out))
        with open(os.path.join(self.out, "signing-audit.json")) as f:
            return code, json.load(f)

    def test_success_and_failure_jobs_are_scanned_and_clean(self):
        self.job(1, "Release images", "success")
        self.job(2, "Release", "failure")
        self.logs = {1: CLEAN, 2: CLEAN}
        code, record = self.audit("Release images", "Candidate images", "Release")
        self.assertEqual((code, record["result"]), (0, "clean"))
        self.assertEqual([j["state"] for j in record["jobs"]], ["scanned", "absent", "scanned"])

    def test_key_material_in_a_failed_job_fails_the_audit(self):
        self.job(1, "Release", "failure")
        self.logs = {1: CLEAN + PRIVATE}
        code, record = self.audit("Release")
        self.assertEqual((code, record["result"]), (1, "failed"))
        self.assertNotIn("SIGSTORE PRIVATE KEY-----\n", json.dumps(record))  # counts only, never the text

    def test_a_job_the_environment_refused_is_recorded_not_scanned(self):
        self.job(1, "Release images", "failure", started=False)
        self.job(2, "Release", "success")
        self.logs = {2: CLEAN}
        code, record = self.audit("Release images", "Release")
        self.assertEqual(code, 0)
        self.assertEqual(record["jobs"][0]["state"], "not started")

    def test_jobs_that_never_started_leave_nothing_to_audit(self):
        self.job(1, "Release images", "skipped", started=False)
        code, record = self.audit("Release images", "Release")
        self.assertEqual((code, record["result"]), (0, "clean"))

    def test_names_absent_from_the_run_fail_the_audit(self):
        self.job(1, "Release images", "success")
        code, record = self.audit("Renamed job")
        self.assertEqual((code, record["result"]), (1, "failed"))


if __name__ == "__main__":
    unittest.main()
