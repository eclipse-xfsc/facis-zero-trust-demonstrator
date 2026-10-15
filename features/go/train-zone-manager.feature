@platform @regression @image
Feature: TRAIN DNS zone manager image
  Regression checks behind Annex A rows ZT-13, ZT-14 and TDR-BDD-10, which they do not prove: the
  first-party image of the upstream zone manager (deployment/docker/train-zone-manager) is built from
  the pinned commit with its patches, starts and serves its zone, serves it again after a restart
  with the same keys, renews its signatures on command and refuses to be built unpatched. The rows
  themselves stay pending until the XFSC stack is deployed. The cases run in Docker through
  scripts/train-zone-manager/image_test.sh when ZTD_IMAGE_TEST=1; otherwise every step is skipped.

  Scenario: The image is built from the pinned upstream commit with its patches
    Given the zone manager image cases have run
    Then the image records the pinned upstream commit
    And a patch that no longer applies fails the build

  Scenario: A first start creates and serves the zone
    Given the zone manager image cases have run
    Then the container is ready after its first start
    And the DS is printed once
    And the SOA is answered authoritatively over UDP and over TCP
    And the upstream base fails at import ldns

  Scenario: A restart with the volume kept serves the same zone
    Given the zone manager image cases have run
    Then the container is ready again after a restart
    And the zone is served with the same DNSKEY set
    And the readiness command refuses a server with no zone

  Scenario: The resign command renews the signatures
    Given the zone manager image cases have run
    Then the resign command exits 0
    And the SOA signature dates and the serial move forward
    And a resign against a missing database fails

  Scenario: The image passes the platform gate
    Given the zone manager image cases have run
    Then the image is linux/amd64
