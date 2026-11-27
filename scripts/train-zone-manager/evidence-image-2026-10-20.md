# TRAIN DNS zone manager image: 2026-10-20T23:02:02Z
PASS  1a the image records the pinned upstream commit a431f148c4ef1f3c897385e99b463c556f271070
PASS  1b a patch that no longer applies fails the build at git apply
PASS  1c the image ships no NSD control key pair
PASS  2a the container is ready 9 s after its first start
PASS  2b the DS is printed once at first start: trust.ztd.test.	3600	IN	DS	30036 13 2 804c43e0c56ba515c6ecd99d80a72db73343f4d0ae7f1ba96af5bf4c6dd8bc39
PASS  2c the SOA is answered authoritatively over UDP
PASS  2d the SOA is answered authoritatively over TCP
      SOA serial at first start: 1792537338
PASS  2f NSD takes control over /run/nsd/nsd.ctl only; nothing listens on 8952
PASS  2e the upstream base (python:3.11, Debian 13) fails at import ldns: No module named '_ldns'
PASS  3a the container is ready 1 s after a restart with the volume kept
PASS  3b the zone is served again after the restart
PASS  3c the DNSKEY set is unchanged across the restart (2 keys)
PASS  3d zone-ready refuses a server with no zone: trust.ztd.test is not configured in NSD
PASS  4a the resign command exits 0
PASS  4b the SOA signature moved: expiration 20261117230218 -> 20261117230308, inception 20261020230218 -> 20261020230308
PASS  4c the SOA serial increased: 1792537338 -> 1792537388
PASS  4d a resign against a missing database fails (exit 1)
PASS  5a the image is linux/amd64 (ZT-13)
      5b the vulnerability scan and the signing are the pipeline's gates (ci.yml 'Image build and scan', release.yml)
# result: all cases passed
