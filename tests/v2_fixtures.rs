use crowsi_control_contracts::{
    CertificateAuthorityOutcomeEvidenceV2, CertificateManagerCommitEvidenceV2,
    CertificateManagerHandoffEvidenceV2, EnforcementReceiptV2, IsolationCommandV2,
    PepExecutionLeaseV2, Validate,
};
use std::collections::BTreeSet;

#[test]
fn checked_in_v2_fixtures_match_the_rust_contracts() {
    let command: IsolationCommandV2 =
        serde_json::from_str(include_str!("../fixtures/isolation-command-v2.sample.json"))
            .expect("command JSON");
    command.validate().expect("command contract");
    let lease: PepExecutionLeaseV2 = serde_json::from_str(include_str!(
        "../fixtures/pep-execution-lease-v2.sample.json"
    ))
    .expect("lease JSON");
    lease.validate().expect("lease contract");
    let receipt: EnforcementReceiptV2 = serde_json::from_str(include_str!(
        "../fixtures/enforcement-receipt-v2.sample.json"
    ))
    .expect("receipt JSON");
    receipt.validate().expect("receipt contract");
    assert_eq!(receipt.command_jti, command.jti);
    assert_eq!(receipt.command_digest, command.signed.digest);
    assert_eq!(receipt.fence_epoch, command.fence_epoch);
    assert_eq!(lease.command, command);
    assert_eq!(lease.command_digest, command.signed.digest);
    assert_closed_root(
        include_str!("../schemas/isolation-command-v2.schema.json"),
        include_str!("../fixtures/isolation-command-v2.sample.json"),
    );
    assert_closed_root(
        include_str!("../schemas/pep-execution-lease-v2.schema.json"),
        include_str!("../fixtures/pep-execution-lease-v2.sample.json"),
    );
    assert_closed_root(
        include_str!("../schemas/enforcement-receipt-v2.schema.json"),
        include_str!("../fixtures/enforcement-receipt-v2.sample.json"),
    );
    validate_certificate_evidence_fixtures();
}

fn validate_certificate_evidence_fixtures() {
    let authority: CertificateAuthorityOutcomeEvidenceV2 = checked(include_str!(
        "../fixtures/certificate-authority-outcome-evidence-v2.sample.json"
    ));
    let manager: CertificateManagerCommitEvidenceV2 = checked(include_str!(
        "../fixtures/certificate-manager-commit-evidence-v2.sample.json"
    ));
    let handoff: CertificateManagerHandoffEvidenceV2 = checked(include_str!(
        "../fixtures/certificate-manager-handoff-evidence-v2.sample.json"
    ));
    authority.validate().unwrap();
    manager.validate().unwrap();
    handoff.validate().unwrap();
    for (schema, fixture) in [
        (
            include_str!("../schemas/certificate-authority-outcome-evidence-v2.schema.json"),
            include_str!("../fixtures/certificate-authority-outcome-evidence-v2.sample.json"),
        ),
        (
            include_str!("../schemas/certificate-manager-commit-evidence-v2.schema.json"),
            include_str!("../fixtures/certificate-manager-commit-evidence-v2.sample.json"),
        ),
        (
            include_str!("../schemas/certificate-manager-handoff-evidence-v2.schema.json"),
            include_str!("../fixtures/certificate-manager-handoff-evidence-v2.sample.json"),
        ),
    ] {
        assert_closed_root(schema, fixture);
    }
}

fn checked<T: serde::de::DeserializeOwned>(source: &str) -> T {
    serde_json::from_str(source).expect("closed fixture")
}

fn assert_closed_root(schema: &str, fixture: &str) {
    let schema: serde_json::Value = serde_json::from_str(schema).expect("schema");
    let fixture: serde_json::Value = serde_json::from_str(fixture).expect("fixture");
    let keys = fixture
        .as_object()
        .expect("fixture object")
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let required = schema["required"]
        .as_array()
        .expect("required")
        .iter()
        .map(|value| value.as_str().expect("required field"))
        .collect::<BTreeSet<_>>();
    let properties = schema["properties"]
        .as_object()
        .expect("properties")
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    assert_eq!(keys, required);
    assert_eq!(keys, properties);
}
