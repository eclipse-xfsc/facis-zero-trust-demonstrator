# Attestation configuration

One file per zone: the measured containers whose values the zone's mock attestation evidence
carries and its reference values check. A change here is a change of the zone's measurements and
goes through review like any other. The format, the provisioning steps and the proof are in
[docs/attestation-provisioning.md](../../docs/attestation-provisioning.md).

The `rootfs_sha256` of each `atls-gateway` is a mock value until the gateway image exists: the
SHA-256 of `facis-ztd <zone> atls-gateway rootfs 1`.
