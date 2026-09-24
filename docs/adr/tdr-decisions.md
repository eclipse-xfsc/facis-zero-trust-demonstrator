# TDR decisions ADR 001–006

The Technical Development Requirements prescribe six architecture decisions for the project. They
are binding and not reopened here; this page records how each is applied, where to see it, and
what is not in place yet. The project's own decisions are the numbered records in the
[overview](index.md). A deviation from one of the six would be its own record, and there is none.

Status as of 23 September 2026 (the M2 BDD submission).

## ADR 001 — Deployment engine

> Decision: Helm is the mandatory deployment engine for all ESB modules.
> Consequence: Repeatable Kubernetes-native deployments.

**Applied.** Everything the demonstrator installs is a Helm chart; deploy, redeploy and uninstall
go through Helm, driven by ORCE (`scripts/lifecycle.sh`, Helm v4.3.0 pinned). Charts are linted and
rendered on every pull request (`deployment/helm/README.md` lists the charts).

**Not yet:** the umbrella chart for a zone and the ORCE chart; ORCE is installed from
interim manifests until then. A dry-run gate before release promotion (TDR-BDD-11) is pending.

## ADR 002 — Orchestration layer

> Decision: ORCE is the mandatory runtime for Builder execution.
> Consequence: Unified low-code deployment flow and JSON output.

**Applied.** The deployment workflow runs in ORCE: the `ztd-lifecycle` Builder Node and the
lifecycle flow ([Orchestrated flows](../flows.md), IF-08 in [API documentation](../api-docs.md)),
packaged in a first-party ORCE image. Results are JSON in the ORCE flow context. The acceptance
scenarios TDR-BDD-01..04 drive this workflow on a cluster ([BDD acceptance](../bdd.md)).

**Not yet:** the demonstrator journey flows and UI nodes (ZT-43 and the visualization rows).

## ADR 003 — Automation stack

> Decision: Node.js + Bash + YAML for UI, backend logic, and automation.
> Consequence: Stable and consistent execution environment.

**Applied.** Builder Node logic is Node.js (`ui/nodes/`), its UI HTML, JavaScript and JSON Schema;
automation is Bash under `scripts/`; Helm templates and Kubernetes manifests are YAML. Services
outside ORCE are Go, as the TDR's programming-language rules require for all other services.

## ADR 004 — Identity integration

> Decision: Keycloak mandatory for realm and client configuration.
> Consequence: Single consistent identity model across ESB modules.

**Decided, not yet deployed.** Keycloak is the identity provider, used as a stock product with its
realm held as code ([Keycloak integration](../keycloak.md)); the custom OAuth2 surface lives in the
Go connector so that Keycloak is never forked
([ADR-0003](0003-oauth2-authorisation-surface-in-the-go-connector.md)). The realm export and the
Keycloak deployment are not in the repository yet; the Keycloak integration row (TDR-BDD-05) is
pending.

## ADR 005 — Security baseline

> Decision: TLS 1.3, RBAC, Secrets for credential storage, log masking.
> Consequence: Secure, auditable deployment operations.

**Applied so far:**

- **RBAC.** Least privilege for the deployment workflow: ORCE deploys with a ServiceAccount that
  can only work inside the BDD pool namespaces, and the acceptance runner observes with a read-only
  identity (the `deployment/helm/bdd-pool` chart).
- **Secrets.** ORCE's credentials come from a Kubernetes Secret as bcrypt hashes and a read token;
  ORCE refuses to start without them. No credential is in the image or the repository.
- **Log masking.** The lifecycle node and script mask credential-shaped values in the Helm output
  before it is stored or logged, and never log the deployment values.

**Not yet:** TLS 1.3 on the endpoints. ORCE has no ingress yet and is reached by port-forward;
TLS 1.3 termination comes with its exposure, together with the ORCE chart. The rows that check the baseline at run
time — TLS 1.3 (TDR-BDD-07) and secrets and log masking (TDR-BDD-08) — are pending.

## ADR 006 — Logging and observability

> Decision: Structured JSON logs exposed via ORCE context outputs.
> Consequence: Machine-readable logs for testing and monitoring.

**Applied, within this boundary:** every record sent through the Node-RED logging API in ORCE is one
JSON object per line with `time`, `level`, `type`, `name`, `id` and `msg`, and the lifecycle
workflow's machine-readable errors are exposed in the ORCE flow context. Output written outside the
logging API — `console` calls in function or third-party nodes, Node.js warnings, the container
entrypoint — is not JSON. Details in [ORCE logging](../flows.md#orce-logging); TDR-BDD-06 proves it
on a cluster.

**Not yet:** the observability stack for the services (ZT-27).
