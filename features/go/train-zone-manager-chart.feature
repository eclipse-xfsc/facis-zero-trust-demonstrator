@platform @regression @chart
Feature: TRAIN DNS zone manager chart
  Regression checks behind Annex A rows ZT-14, ZT-16 and TDR-BDD-10, which they do not prove: the
  chart (deployment/helm/train-zone-manager) installs the zone manager into a zone laid out by the
  umbrella, serves the zone to the world, keeps its keys across reinstalls and restores them from
  backup, re-signs on schedule, and keeps the API inside the management plane. The cases run on a
  throwaway kind cluster through scripts/train-zone-manager/chart_test.sh when ZTD_CHART_TEST=1;
  otherwise every step is skipped.

  Scenario: The chart installs from an empty namespace and serves the zone
    Given the zone manager chart cases have run
    Then the release installs and the pod is ready
    And the zone answers from outside the cluster over UDP and TCP
    And the DS is recorded and matches the served key
    And the zone's own records carry the address the Service was given
    And a server that stops serving the zone is pulled from the Service
    And without an address the zone manager does not start

  Scenario: The keys survive a reinstall
    Given the zone manager chart cases have run
    Then helm uninstall keeps both volumes
    And a reinstall on the kept volumes serves the same key

  Scenario: A backup restores the same key onto a fresh volume
    Given the zone manager chart cases have run
    Then the keeper takes a backup
    And a fresh state volume is restored from the backup with the same key
    And with both volumes gone a new key is created and the old DS is wrong

  Scenario: The daily re-sign runs and is visible
    Given the zone manager chart cases have run
    Then the keeper's resign moves the served signature
    And a resign against a missing database fails loudly
    And the daily run is scheduled

  Scenario: The right ports in the right plane
    Given the zone manager chart cases have run
    Then the DNS Service carries UDP and TCP 53 on one address
    And the release namespace is the management plane
    And the API answers a management-plane pod
    And the API is refused to a data-plane pod

  Scenario: The chart passes the gates
    Given the zone manager chart cases have run
    Then the chart gate passes the chart
