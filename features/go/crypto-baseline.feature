@platform @regression
Feature: Cryptographic baseline — register conformance
  A regression check behind Annex A row ZT-50, which it does not prove. ZT-50 (SRS 3.3) asks that
  "No deprecated algorithms present in any component" and that "Key lengths documented and
  auditable", inspected on the deployed configuration and the generated artefacts. The scenario
  below proves less: every row of the register in docs/crypto-baseline.md names an accepted
  mechanism and quotes text its file still holds, and the patterns the check scans for (short RSA
  keys, SHA-1 key transport, MD5 and SHA-1 by name, RSA in the Go code) are absent from the Go
  code and the deployment configuration. It cannot tell that a row is missing, and it inspects no
  running zone; ZT-50 is its own pending scenario in security-baseline.feature.

  Scenario: The cryptographic register agrees with the repository
    Given the cryptographic register of the documentation
    When the cryptographic baseline check runs
    Then it reports no mechanism outside the baseline and no setting the register misquotes
