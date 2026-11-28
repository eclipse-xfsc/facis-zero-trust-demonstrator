# M3 T6: OpenBao Kubernetes auth for the connector and the token store

Design: [Secrets: Kubernetes auth](../../secrets.md#kubernetes-auth). Code at commit `54473773`;
the runs record `tree: dirty` because these evidence files were not yet committed.

| Directory | Proof | Verdict |
|---|---|---|
| `kubernetes-auth-kind/` | `scripts/verify-openbao-kubernetes-auth/verify.sh`: the `ztd-openbao` release with `kubernetesAuth` on kind; projected-token login from a pod; the Go token source against the real server and API server (role ttl 20 s): least privilege, background renewal with a rotated token, re-login after expiry, restart, refused wrong ServiceAccount, namespace and audience; the refused upgrade of a configured store | PASS, 6 of 6 |
| `token-store-lifecycle-kind/` | `scripts/verify-token-store/verify.sh`: the token-store chart lifecycle with key custody (#45, unchanged and rerun), plus the Kubernetes-auth stage (role ttl 30 s): login alone with the service token revoked, 7 logins and no readiness failure over 75 s, fail-closed readiness while the login is refused, recovery without restart, fresh login after a pod restart | PASS, 63 of 63 |
| `zone-b-preflight-route/`, `live/`, `zone-b-live-step.md` | zone B: preflight, auth-delegator binding, `--configure-kubernetes-auth` through the reviewed recovery procedure with real logins, guarded path before and after | server side PASS; workload switch done 23 Nov with signed images (`zone-b-live-step.md`) |

Short ttls prove expiry and re-login; they are not a soak. OpenBao server restarts still need the
manual unseal.
