# Interface contracts

This folder holds the machine-readable form of the demonstrator's cross-component interfaces: the
OpenAPI and JSON Schema definitions that components are built against, together with the samples
that show what a valid document looks like. [API documentation](../api-docs.md) is the registry
that names the interfaces and says what each one is for; this folder is what an implementation
actually reads.

A contract is added here when its interface is frozen at v1, and from that point a change to it is
a deliberate, agreed act rather than a surprise to whoever consumes it.

## What is here

| Contract | Covers |
|---|---|
| [`mock-attestation.schema.json`](mock-attestation.schema.json) | The mock attestation document — the evidence a Trusted Execution Environment would emit, produced in software |

### Mock attestation

The demonstrator has no TEE hardware, so it produces the same document in software. The schema
describes that document: one `evidence` object and the `collateral` a verifier needs to check it,
following the types of the pinned attestation component exactly, plus two wrapper fields — `mock`
and `profile` — that mark a sample as synthetic and name the vendor profile it stands for.

[`samples/`](samples/) holds one sample per profile: `sw`, `tpm`, `snp`, `sgx`, `tdx`, `azure-tpm`,
`azure-snp` and `azure-tdx`. The `sw` sample is real output from the software driver and verifies
against the component's own verifier; the hardware profiles are synthetic, so they show the shape
of that evidence and are never presented as vendor evidence. The reasoning, and what would reopen
it, is in [ADR 0011](../adr/0011-mock-tee-evidence-format-and-provisioning.md).

The same document serves both ends of the evidence path — the artefact attached to a release and
checked at admission, and the report exchanged inside the attested channel — which is why one
format is fixed here rather than one per consumer.
