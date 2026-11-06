# TRAIN DNS zone manager chart: 2026-10-20T23:02:02Z
== Cluster: kind with Cilium (cni.exclusive=false), a registry on the kind network
      cluster ztd-zone-manager: Kubernetes v1.35.8, Cilium 1.20.2, cni.exclusive=false
== Umbrella: the zone layout with its default deny and the API lane
      umbrella installed: management plane ztd-mgmt, data plane ztd-data
== Image: built, pushed to the registry, referenced by digest
      image ztd-zone-manager-registry:5000/ztd/train-zone-manager@sha256:a0c3e09de9d32f0314125872bdb91ea4f71b31d361b1359a436e65611ad23754
== 1 install
PASS  1a helm install --wait succeeded; zone-manager ready=true
PASS  1b the zone answers from outside the cluster over UDP and TCP via the worker node (172.22.0.5:30053)
PASS  1b the zone answers from outside the cluster over UDP and TCP via the control-plane node, cross-node (172.22.0.4:30053)
PASS  1c the DS is recorded in the ConfigMap and matches the served key (tag 61864)
PASS  1e the zone's apex and glue records carry the address the Service was given, 198.51.100.0 (address: 198.51.100.0 from Service train-zone-manager-dns; 4 variable(s) written to /var/lib/zonemgr/address.env)
PASS  1f without an address the zone manager never starts: zone-manager stays PodInitializing; address step: address: waiting for the address of Service train-zone-manager-dns
PASS  1d a server that stops serving the zone is NotReady and has no ready endpoint (endpoints: 'false ')
      NSD started again: ready=true
== 2 reinstall
PASS  2a helm uninstall left both claims behind (resource-policy keep)
PASS  2b reinstalled on the kept volumes: same key tag 61864
== 3 backup
PASS  3a the keeper took a backup: /var/lib/zonemgr-backup/zonemgr-20261020T231239Z.tgz (3179 bytes), 1 kept
PASS  3b a fresh state volume was restored from the backup: same key tag 61864 (2026-10-20T23:13:15Z zone-keeper restore: the volume was empty, restored from /var/lib/zonemgr-backup/latest.tgz (2026-10-20T23:12:39Z))
PASS  3c with both volumes gone a new key is created: tag 61864 -> 12253; the DS the parent would hold is now wrong
      the DS record was rewritten by the hook to 12253; the parent's DS is what has to change next
== 4 resign
PASS  4a resign-now moved the served SOA signature: 20261117231412 -> 20261117231421
PASS  4b resign-now against a missing database fails loudly
PASS  4c the keeper's daily loop is scheduled: next run at 2026-10-21T00:05:00Z
== 5 ports and planes
PASS  5a the DNS Service carries 53/UDP 53/TCP  on one address
PASS  5b the release namespace ztd-mgmt is the management plane
PASS  5c the API answers a management-plane pod: http 200
PASS  5d the API is refused to a data-plane pod: denied ConnectTimeout
== 6 gates
PASS  6a the chart gate (lint, render) passes the chart
# result: all cases passed
