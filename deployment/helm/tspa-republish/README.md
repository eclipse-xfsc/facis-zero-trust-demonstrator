# TSPA re-publication

Our TSPA image signs a trust list's VC with a validity window (`trustlist.vc.validity`, `P30D`) and
only when the list is published ([Publishing to TRAIN](../../../docs/tspa-publish-api.md), section 11).
This chart is the renewal: a CronJob that every week reads the list of `framework`, `PATCH`es its
first entry back as read, and passes only when the VC then expires later than before. A missed run
leaves three weeks. It never creates a list or an entry: a list with no entry fails the job.

TSPA rewrites the whole list on every write and has no precondition, so the job is one more writer
of the framework: a publication landing between its read and its write (well under a second) loses
that entry's change. Publishers of the framework must not run at the job's minute
([section 7.1](../../../docs/tspa-publish-api.md)).

| Value | Meaning |
|---|---|
| `framework` | the trust framework whose list is re-published |
| `tspaUrl` | TSPA's API root (`http://<service>:16003/tspa-service/tspa/v1`) |
| `tokenUrl` | the token endpoint of the realm TSPA trusts |
| `client.id`, `client.secretName`, `client.secretKey` | a confidential client whose service account holds the realm role `enrolltf`, and the existing Secret that holds its secret (the chart creates no Secret) |
| `schedule` | cron, UTC; Mondays 03:17 by default |
| `image.repository`, `image.digest` | a Python 3 image by digest (the script uses the standard library only) |

The job prints the VC's window before and after and the `PATCH`'s status; never the token or the
client secret. Zone B's values are in `zones/zone-b.yaml`:

```bash
helm -n ztd-train upgrade --install tspa-republish deployment/helm/tspa-republish -f deployment/helm/tspa-republish/zones/zone-b.yaml
kubectl -n ztd-train create job tspa-republish-manual --from=cronjob/tspa-republish   # one run now
```
