@docs @regression
Feature: Demonstrator usage documentation
  A regression check behind Annex A row ZT-17, which it does not prove: the usage manual is part
  of the generated documentation site. ZT-17 itself (reproducing the setup step by step, and
  building the documentation from GitHub) is its own pending scenario in documentation.feature.

  Scenario: The usage manual is part of the generated documentation site
    Given the repository documentation
    When the documentation site is assembled
    Then the demonstrator usage manual is included in it
