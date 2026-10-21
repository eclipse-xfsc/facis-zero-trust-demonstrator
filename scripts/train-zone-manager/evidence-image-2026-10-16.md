# TRAIN DNS zone manager image: 2026-10-16T06:42:42Z
PASS  1a the image records the pinned upstream commit a431f148c4ef1f3c897385e99b463c556f271070
PASS  1b a patch that no longer applies fails the build at git apply
PASS  2a the container is ready 4 s after its first start
PASS  2b the DS is printed once at first start: trust.ztd.test.	3600	IN	DS	12012 13 2 5a9ff6a1e4bfb5424dbe753022f28df4296c5056e473c91739bae6c1bb8fe804
PASS  2c the SOA is answered authoritatively over UDP
PASS  2d the SOA is answered authoritatively over TCP
      SOA serial at first start: 1792132967
PASS  2e the upstream base (python:3.11, Debian 13) fails at import ldns: No module named '_ldns'
PASS  3a the container is ready 0 s after a restart with the volume kept
PASS  3b the zone is served again after the restart
PASS  3c the DNSKEY set is unchanged across the restart (2 keys)
PASS  3d zone-ready refuses a server with no zone: trust.ztd.test is not configured in NSD
PASS  4a the resign command exits 0
PASS  4b the SOA signature moved: expiration 20261113064247 -> 20261113064314, inception 20261016064247 -> 20261016064314
PASS  4c the SOA serial increased: 1792132967 -> 1792132994
PASS  4d a resign against a missing database fails (exit 1)
PASS  5a the image is linux/amd64 (ZT-13)
      5b the vulnerability scan and the signing are the pipeline's gates (ci.yml 'Image build and scan', release.yml)
# result: all cases passed
