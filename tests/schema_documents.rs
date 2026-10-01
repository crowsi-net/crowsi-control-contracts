mod support;

use crowsi_control_contracts::{
    AssuranceLevel, CERTIFICATE_AUTHORITY_OUTCOME_EVIDENCE_SCHEMA_V2,
    CERTIFICATE_MANAGER_COMMIT_EVIDENCE_SCHEMA_V2, CERTIFICATE_MANAGER_HANDOFF_EVIDENCE_SCHEMA_V2,
    CERTIFICATE_RECEIPT_SIGNATURE_SCHEMA_V2, COVERAGE_ASSERTION_SCHEMA_V1, ControlAction,
    ENFORCEMENT_GRANT_SCHEMA_V1, ENFORCEMENT_RECEIPT_SCHEMA_V1, ENFORCEMENT_RECEIPT_SCHEMA_V2,
    ISOLATION_COMMAND_SCHEMA_V1, ISOLATION_COMMAND_SCHEMA_V2, PEP_EXECUTION_LEASE_SCHEMA_V2,
    POLICY_DECISION_SCHEMA_V1, POLICY_INFORMATION_SNAPSHOT_SCHEMA_V1,
    RECOVERY_AUTHORIZATION_SCHEMA_V1, SECURITY_INTENT_SCHEMA_V1,
    VERIFIED_IDENTITY_CONTEXT_SCHEMA_V1, VerifiedIdentityContextV1,
};
use serde_json::Value;

use support::authorization_fixture;

const SCHEMAS: [(&str, &str); 16] = [
    (
        VERIFIED_IDENTITY_CONTEXT_SCHEMA_V1,
        include_str!("../schemas/verified-identity-context-v1.schema.json"),
    ),
    (
        SECURITY_INTENT_SCHEMA_V1,
        include_str!("../schemas/security-intent-v1.schema.json"),
    ),
    (
        POLICY_DECISION_SCHEMA_V1,
        include_str!("../schemas/policy-decision-v1.schema.json"),
    ),
    (
        ENFORCEMENT_GRANT_SCHEMA_V1,
        include_str!("../schemas/enforcement-grant-v1.schema.json"),
    ),
    (
        ISOLATION_COMMAND_SCHEMA_V1,
        include_str!("../schemas/isolation-command-v1.schema.json"),
    ),
    (
        ISOLATION_COMMAND_SCHEMA_V2,
        include_str!("../schemas/isolation-command-v2.schema.json"),
    ),
    (
        ENFORCEMENT_RECEIPT_SCHEMA_V1,
        include_str!("../schemas/enforcement-receipt-v1.schema.json"),
    ),
    (
        ENFORCEMENT_RECEIPT_SCHEMA_V2,
        include_str!("../schemas/enforcement-receipt-v2.schema.json"),
    ),
    (
        PEP_EXECUTION_LEASE_SCHEMA_V2,
        include_str!("../schemas/pep-execution-lease-v2.schema.json"),
    ),
    (
        COVERAGE_ASSERTION_SCHEMA_V1,
        include_str!("../schemas/coverage-assertion-v1.schema.json"),
    ),
    (
        POLICY_INFORMATION_SNAPSHOT_SCHEMA_V1,
        include_str!("../schemas/policy-information-snapshot-v1.schema.json"),
    ),
    (
        RECOVERY_AUTHORIZATION_SCHEMA_V1,
        include_str!("../schemas/recovery-authorization-v1.schema.json"),
    ),
    (
        CERTIFICATE_RECEIPT_SIGNATURE_SCHEMA_V2,
        include_str!("../schemas/certificate-receipt-signature-v2.schema.json"),
    ),
    (
        CERTIFICATE_AUTHORITY_OUTCOME_EVIDENCE_SCHEMA_V2,
        include_str!("../schemas/certificate-authority-outcome-evidence-v2.schema.json"),
    ),
    (
        CERTIFICATE_MANAGER_COMMIT_EVIDENCE_SCHEMA_V2,
        include_str!("../schemas/certificate-manager-commit-evidence-v2.schema.json"),
    ),
    (
        CERTIFICATE_MANAGER_HANDOFF_EVIDENCE_SCHEMA_V2,
        include_str!("../schemas/certificate-manager-handoff-evidence-v2.schema.json"),
    ),
];

#[test]
fn all_versioned_schemas_are_valid_json_with_matching_closed_ids() {
    for (expected, source) in SCHEMAS {
        let schema: Value = serde_json::from_str(source).expect("valid schema JSON");
        assert_eq!(schema["$id"], expected);
        assert_eq!(schema["additionalProperties"], false);
        assert_eq!(
            schema["$schema"],
            "https://json-schema.org/draft/2020-12/schema"
        );
    }
}

#[test]
fn serde_contract_rejects_unknown_identity_fields() {
    let fixture =
        authorization_fixture(ControlAction::Quarantine, AssuranceLevel::PhishingResistant);
    let mut value = serde_json::to_value(fixture.identity).expect("serialize identity");
    value
        .as_object_mut()
        .expect("identity object")
        .insert("ambient_authority".to_owned(), Value::Bool(true));
    assert!(serde_json::from_value::<VerifiedIdentityContextV1>(value).is_err());
}
