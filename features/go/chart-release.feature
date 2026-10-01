@platform
Feature: Chart release gate
  The Technical Development Requirements deliver the Helm charts with each release,
  and Annex A row TDR-BDD-11 holds the pipeline to its lint and dry-run render as
  blocking gates in front of the package: a chart that fails either is never released.

  @TDR-BDD-11 @BDD-TDR-011
  Scenario: Charts that lint and render are packaged for the release
    Given the release charts
    When the chart check packages them at version "0.0.0-check"
    Then every release chart is packaged at that version

  @TDR-BDD-11 @BDD-TDR-011
  Scenario: A chart that fails the dry-run render is refused a package
    Given a chart whose template does not render
    When the chart check packages it at version "0.0.0-check"
    Then the check fails and no package is produced

  @TDR-BDD-11 @BDD-TDR-011
  Scenario: A chart that fails lint is refused a package
    Given a chart whose metadata does not lint
    When the chart check packages it at version "0.0.0-check"
    Then the check fails and no package is produced
