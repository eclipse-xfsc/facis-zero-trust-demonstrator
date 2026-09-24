@cluster @lifecycle
Feature: Deployment lifecycle
  Annex A rows TDR-BDD-01 to TDR-BDD-04 (Technical Development Requirements - BDD Test Suite /
  ORCE Automation QA). Each scenario drives the ORCE lifecycle workflow and decides the outcome
  from the cluster itself, in a dedicated pool namespace, with the release under test given by
  BDD_RELEASE_CHART. Evidence produced with the lifecycle fixture chart is fixture evidence and
  does not accept any other release; the scenario names say so. The steps are the Annex wording,
  and the invalid-parameter example is named in the Outline title only.

  @TDR-BDD-01 @BDD-TDR-001
  Scenario: Successful deployment [fixture release]
    A release can be deployed on the prescribed Kubernetes target environment through Helm with
    zero manual intervention.

    Given an approved release and target cluster
    When the Helm/ORCE deployment workflow is executed
    Then all required resources are created and the release reaches Ready state without manual intervention.

  @TDR-BDD-02 @BDD-TDR-002
  Scenario Outline: Invalid deployment parameters [fixture release] - <case>
    Invalid or incomplete deployment parameters are rejected with a machine-readable error and no
    partial trusted deployment remains.

    Given invalid or incomplete deployment parameters
    When the deployment workflow is executed
    Then deployment fails cleanly, returns a machine-readable error via the automation context, and no partial trusted state is left behind.

    Examples:
      | case                      |
      | release name missing      |
      | values of the wrong type  |
      | chart value rejected      |

  @TDR-BDD-03 @BDD-TDR-003
  Scenario: Idempotent redeployment [fixture release]
    Redeploying an unchanged release succeeds without manual intervention and without creating
    inconsistent duplicate resources.

    Given a successfully deployed release
    When the same release is deployed again
    Then the operation completes successfully and the resulting Kubernetes state remains consistent and ready.

  @TDR-BDD-04 @BDD-TDR-004
  Scenario: Uninstall [fixture release]
    The release can be uninstalled through the documented workflow with zero manual intervention.

    Given a deployed release
    When the uninstall workflow is executed
    Then the release is removed without manual intervention and the expected project resources are no longer present.
