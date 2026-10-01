# Security boundary

This repository defines data contracts, not a trust anchor or control plane.
Deserialization and successful structural validation do not make a document
authentic.

Production consumers must additionally provide:

- canonical payload digest validation and detached-signature verification;
- artifact-role-scoped issuer, key, algorithm, audience, and policy allowlists;
- proof-of-possession verification against the bound device and workload key;
- a signed, current policy-information snapshot and monotonic revocation state;
- independent restore-authority verification and one-use recovery JTI storage;
- an authenticated transport with peer or workload attestation;
- durable, atomic JTI consumption and idempotency;
- a trusted clock and bounded clock-skew policy;
- provider-specific least-privilege enforcement and independent read-back;
- append-only audit retention and protected break-glass recovery.

Treat `workload` as an identity boundary, never as a display label. Producers
must emit the canonical SPIFFE form accepted by `validate_spiffe_workload`;
consumers must reject alternative URI spellings instead of normalizing them
after signature verification.

Do not log signatures as authorization proof, identity attributes beyond the
minimum projection, or provider credentials. Never interpret an
`EnforcementReceiptV1` or `EnforcementReceiptV2` as independent proof that
isolation succeeded.

The `signed` object is excluded from the v1 canonical payload to avoid
self-reference. Its digest must equal `CanonicalPayloadV1::payload_digest()`.
The algorithm, key identifier, and signature therefore remain verifier inputs
and must be allowlisted and checked together; they are not authenticated by
structural validation alone.

Snapshot validation authenticates a bounded claim set, not its sensors. A
compromised policy-information authority can still assert false posture,
incident, management, risk, or revocation data. Keep that role separate from
identity, intent, decision, grant, command, coverage, recovery, and receipt
keys, and require independent read-back before claiming successful isolation.

## Private vulnerability reporting

Report vulnerabilities through this repository's GitHub private vulnerability reporting form. Do not put credentials, personal or customer data, or production certificate material in public issues or pull requests.
