@design
Feature: Management plane and data plane separation
  ZT-55 (SRS 3.3) states three acceptance criteria:
    "Management plane components not reachable from data plane (verified in network test)."
    "Separation enforced at both network policy and service mesh layers."
    "Architecture diagram clearly shows plane separation."
  The scenario below proves none of them against a running system. It proves that the
  specification in section 6 of the architecture document, from which the network test is
  written, is complete and consistent: every path from the data plane to the management plane
  is disposed at both the network policy layer and the service mesh layer, in agreement with its
  verdict, and no management-plane destination is left without a disposition. That is the second
  criterion as the design states it. Reachability, the first criterion, is proved by a second
  scenario carrying the same row tag, written when the matrix is executed against a cluster.

  @ZT-55 @BDD-ZT-055
  Scenario: The plane-separation matrix is complete and consistent at both layers
    Given the plane-separation section of the architecture document
    When the plane-separation conformance check runs
    Then it reports no row that breaks an invariant the section states
