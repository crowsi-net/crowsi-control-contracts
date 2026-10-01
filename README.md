# crowsi-control-contracts

Closed, versioned contracts for the Crowsi Zero Trust control path. This crate
contains serializable Rust types and deterministic validation only. It performs
no I/O, reads no clock, stores no replay state, verifies no cryptographic
signature, and never changes a network or provider.

The authorization ancestry remains on closed v1 contracts, while production
enforcement uses the release- and fence-bound v2 command and receipt:

1. a trusted identity verifier emits `VerifiedIdentityContextV1`;
2. Hatter or another client submits a short-lived `SecurityIntentV1`;
3. independent sources are sealed into `PolicyInformationSnapshotV1`;
4. a Crowsi policy engine emits `PolicyDecisionV1`;
5. the policy administrator mints one `EnforcementGrantV1`;
6. the PA accepts one externally signed `IsolationCommandV2` after release
   reservation commit;
7. the PA commits execution state and sends one `PepExecutionLeaseV2`;
8. restore additionally requires one `RecoveryAuthorizationV1`;
9. the PEP emits `EnforcementReceiptV2`;
10. an independent sensor emits `CoverageAssertionV1`.

Hatter is an intent and projection client, not an identity, policy, grant, or
enforcement authority. Every enforcement authorization is bound to an exact
audience, resource, action, purpose, and channel. Identity, intent, decision,
grant, and command also carry the same profile and proof-of-possession key
reference. Restore requires hardware-bound step-up assurance, which is stronger
than the phishing-resistant assurance required for quarantine and other
containment actions. Recovery authorization is restore-only, one-use, and
binds the exact identity, action, incident, policy snapshot, and revocation
epoch. Its verifier must be independent from command and receipt roles.

Every `workload` field is one canonical SPIFFE ID. The shared validator accepts
only a lowercase DNS-style trust domain and a non-empty segmented path, bounded
to 256 bytes. Empty or dot segments, query, fragment, user-info, port,
percent-encoding, and non-canonical authority forms fail closed. The standalone
JSON Schemas carry the same pattern and bounds.

`IsolationCommandV2` additionally binds the security domain, deployment,
incident, target, coordinator release and digest, checkpoint and sequence,
one-use release reservation, previous and next monotonic fence, expected
provider resource version, expiry, and revocation epoch. Its
`EnforcementReceiptV2` repeats the security boundary, command digest,
reservation, fence, and resource-version CAS evidence. A v1 command or receipt
cannot be substituted into that path.

The PA-to-PEP production wire accepts only the closed
`PepExecutionLeaseV2`, whose embedded command must be an exact
`IsolationCommandV2`, and returns only `EnforcementReceiptV2`. A PEP must reject
a fence that is not greater than its durable latest fence. It must durably
consume a greater fence before checking or changing provider state and must not
roll that fence back after a known resource-version rejection. This permits a
later greater fence without reopening replay of the rejected command.

The policy-information snapshot covers device and workload posture, incident
state, exact management authority, authoritative revocation epoch, risk,
coverage digest, policy digest, and bounded freshness. It authenticates those
claims but cannot prove that the authority's upstream observations are true.

`SignedDigestV1` carries a canonical SHA-256 digest, key identifier, algorithm,
and detached signature. `CanonicalPayloadV1` computes that digest and contract
validation rejects a digest that does not cover the current artifact fields.
The v1 byte representation starts with
`crowsi-control-canonical-v1\0`, then emits every field except `signed` in the
fixed order implemented for that artifact. Every entry is encoded as a
big-endian unsigned 16-bit field-name length, field-name UTF-8 bytes, a
big-endian unsigned 64-bit value length, then value bytes. Integers use
big-endian 64-bit bytes, booleans use one byte, and collections include an
explicit count and indexed entries. Each artifact includes its version in the
encoded artifact tag, so the v1 and v2 command/receipt payloads are
domain-separated while using the same canonical envelope encoding.

This crate does not verify the detached signature. Callers must verify it over
the matching canonical digest against an allowlisted algorithm, key, issuer,
and trust anchor before treating a document as trusted.

## Certificate V2 contracts

Certificate lifecycle contracts are a separate closed family. They define six
non-interchangeable actions: issue, renew, revoke, certificate status,
operation status, and reconciliation of an unknown result. A signed execution
authorization binds the exact service/workload, canonical resource, action,
lease, revision, fence, identity revocation epoch, certificate lifecycle epoch,
policy ancestry, and—where required—independent operator-approval ancestry.

PA release and manager acceptance use
`CertificateManagerHandoffEvidenceV2`. Release alone does not authorize a CA
call. The manager first persists the exact claim, signs it with the
`certificate-manager-handoff-receipt` role, and waits for the PA's exact
durable ACK. Certificate outcome evidence and manager durable-commit evidence
remain separate artifacts and keys. The commit contract signs its event time,
evidence issuance time, short transport expiry, and bounded submission
recovery deadline so delayed first delivery cannot silently extend execution
authority.

These pure types do not enforce replay, trusted time, current revocation,
cryptographic low-S verification, database atomicity, or key uniqueness.
`crowsi-policy-administrator`, `crowsi-certificate-manager`, and
`crowsi-key-provider` must enforce those properties at their respective
boundaries. A SPIFFE-shaped subject remains only a policy identifier; these
contracts do not implement the SPIFFE Workload API.

`EnforcementGrantV1` and `RecoveryAuthorizationV1` fix `use_limit` to one and
carry unique JTIs. V2 also carries a one-use release reservation and monotonic
fence. A PA and PEP must still consume these atomically; pure contract
validation cannot prevent reuse across processes.

Coverage is fail-closed. Partial, unknown, stale, or unmanaged evidence cannot
be represented as verified or healthy. Receipts describe executor claims only;
they do not establish verification. A separate, independent coverage assertion
is required. Isolation readiness additionally requires a verified management
lifeline, a ready enforcer, and ready quarantine, revoke, verify, and restore
capabilities.

The JSON Schemas in `schemas/` are standalone Draft 2020-12 documents. New
incompatible fields or semantics require a new schema URI and Rust type.
Non-secret command, execution-lease, and receipt examples are in `fixtures/`;
their detached signatures are structural placeholders and are not
production-authentic. `cargo run --offline --example render_v2_fixtures`
regenerates equivalent sample output without contacting a provider.
