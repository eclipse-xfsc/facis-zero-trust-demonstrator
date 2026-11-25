# ztd-network-check policy inventory (2026-11-21)

Every NetworkPolicy and CiliumNetworkPolicy of the namespace, read from each zone before and after the change, with server-set metadata removed.

## zone A: before (NetworkPolicy; the namespace held no Cilium policy)

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: diagnostic-traffic
  namespace: ztd-network-check
spec:
  egress:
  - {}
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: source-ip-check
    ports:
    - port: 8080
      protocol: TCP
  podSelector:
    matchLabels:
      app: source-ip-check
  policyTypes:
  - Ingress
  - Egress
```

## zone A: after (1 policies of either kind)

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: diagnostic-traffic
  namespace: ztd-network-check
spec:
  egress:
  - ports:
    - port: 8080
      protocol: TCP
    to:
    - podSelector:
        matchLabels:
          app: source-ip-check
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: source-ip-check
    ports:
    - port: 8080
      protocol: TCP
  podSelector:
    matchLabels:
      app: source-ip-check
  policyTypes:
  - Ingress
  - Egress
```

## zone B: before (NetworkPolicy; the namespace held no Cilium policy)

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: diagnostic-traffic
  namespace: ztd-network-check
spec:
  egress:
  - {}
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: source-ip-check
    ports:
    - port: 8080
      protocol: TCP
  podSelector:
    matchLabels:
      app: source-ip-check
  policyTypes:
  - Ingress
  - Egress
```

## zone B: after (1 policies of either kind)

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: diagnostic-traffic
  namespace: ztd-network-check
spec:
  egress:
  - ports:
    - port: 8080
      protocol: TCP
    to:
    - podSelector:
        matchLabels:
          app: source-ip-check
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: source-ip-check
    ports:
    - port: 8080
      protocol: TCP
  podSelector:
    matchLabels:
      app: source-ip-check
  policyTypes:
  - Ingress
  - Egress
```
