# TSA policy proof on kind

The records of one run of `scripts/verify-tsa-policy/verify.sh` on a throwaway kind cluster (arm64,
Docker Desktop), on the commit `environment.json` names, copied unchanged from the script's output.
What the proof does and does not cover is in [TSA policy evaluation](../../tsa-policy.md#proof).

| File | What it holds |
|---|---|
| `verdict.txt` | each check, PASS or FAIL, and the verdict |
| `environment.json` | the TSA, NATS and kind node images by digest, the node architecture and the commit |
| `bundles.txt` | the published references: v1, v2, signed by another key (`other`), unsigned, tampered, and the signed one whose Rego answers with another revision (`lying`) |
| `decisions.jsonl` | every IF-05 answer the evaluator gave, with the correlation id it was asked under |
| `evaluator.log` | the evaluator's decision log: correlation id, rule id, bundle revision |
| `bundle-sidecar.log` | the sidecar's activations and refusals, each with its reason (one line per poll while a refused bundle stays declared) |
| `tsa.log` | the TSA's own log |

The signing keys were generated for the run and discarded with the cluster; nothing here is
secret. The registry names (`kind-registry-tsa:5000`) are the run's local test registry.
