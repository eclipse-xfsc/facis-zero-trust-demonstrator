@platform @regression
Feature: TLS 1.3 on the public ingress
  A check behind Annex A row TDR-BDD-07, which it does not prove. TDR-BDD-07 asks that "TLS 1.3 is
  enforced on all relevant endpoints and older TLS protocol versions are rejected". The scenario
  below proves it for the endpoints a client outside the cluster reaches, the public ingress hosts
  named in BDD_TLS_ENDPOINTS, which must answer HTTP/1.1: each completes a request over TLS 1.3 and
  refuses TLS 1.2, 1.1 and 1.0 with the protocol-version alert. It does not reach the TLS listeners inside the cluster: the
  mesh's minimum is proven from inside the mesh (scripts/verify-mesh-identity), the admission
  provider's is set in its code, and the listeners of istiod, the SPIRE server and the admission
  webhooks are not probed by anything yet. TDR-BDD-07 stays its own pending scenario in
  security-baseline.feature until they are.

  @cluster @tls-ingress
  Scenario: The public ingress accepts TLS 1.3 and refuses every older version
    Given the public TLS endpoints of the target
    When each is attempted with TLS 1.3 and with every older TLS version
    Then TLS 1.3 completes a request and the server refuses every older version
