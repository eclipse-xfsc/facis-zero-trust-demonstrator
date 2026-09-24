@platform @regression
Feature: Delivery pipeline security
  A regression check behind Annex A row ZT-56, which it does not prove: every third-party action
  is pinned to a commit SHA and no pipeline run holds a wildcard write scope. ZT-56 itself (no
  secret in any log, signed artefacts, a refused unreviewed merge) is its own pending scenario in
  supply-chain.feature.

  Scenario: Every workflow is pinned to a commit and scoped to what it needs
    Given the repository workflows
    When the workflow hygiene check runs
    Then it reports no unpinned action and no wildcard write scope
