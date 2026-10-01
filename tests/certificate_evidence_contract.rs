mod support;

use base64::{Engine, engine::general_purpose::STANDARD};
use crowsi_control_contracts::{
    CertificateActionV2, CertificateAuthorityOutcomeEvidenceV2, CertificatePayloadV2,
    CertificateReceiptSignatureV2, Validate,
};
use serde_json::json;
use support::{authority_evidence, handoff_evidence, manager_commit_evidence};

#[test]
fn completion_and_handoff_evidence_are_closed_and_exactly_signed() {
    let authority = authority_evidence();
    let manager = manager_commit_evidence(&authority);
    let handoff = handoff_evidence();
    authority.validate().unwrap();
    manager.validate().unwrap();
    handoff.validate().unwrap();
    let mut unknown = serde_json::to_value(authority).unwrap();
    unknown["ambient_authority"] = json!(true);
    assert!(serde_json::from_value::<CertificateAuthorityOutcomeEvidenceV2>(unknown).is_err());
    let mut unknown = serde_json::to_value(manager).unwrap();
    unknown["ambient_authority"] = json!(true);
    assert!(
        serde_json::from_value::<crowsi_control_contracts::CertificateManagerCommitEvidenceV2>(
            unknown
        )
        .is_err()
    );
    let mut unknown = serde_json::to_value(handoff).unwrap();
    unknown["ambient_authority"] = json!(true);
    assert!(
        serde_json::from_value::<crowsi_control_contracts::CertificateManagerHandoffEvidenceV2>(
            unknown
        )
        .is_err()
    );
}

#[test]
fn nonce_encoding_relation_and_disposition_fail_closed() {
    let mut authority = authority_evidence();
    authority.nonce_base64.push('=');
    authority.signed.digest_sha256 = authority.certificate_digest_sha256();
    assert!(authority.validate().is_err());
    let mut authority = authority_evidence();
    authority.nonce_base64 = "AQ".into();
    authority.signed.digest_sha256 = authority.certificate_digest_sha256();
    assert!(authority.validate().is_err());
    let mut authority = authority_evidence();
    authority.nonce_base64 = "+".repeat(43);
    authority.signed.digest_sha256 = authority.certificate_digest_sha256();
    assert!(authority.validate().is_err());
    let mut authority = authority_evidence();
    authority.action = CertificateActionV2::ReconcileUnknown;
    authority.signed.digest_sha256 = authority.certificate_digest_sha256();
    assert!(authority.validate().is_err());
    let mut value = serde_json::to_value(handoff_evidence()).unwrap();
    value["disposition"] = json!("maybe");
    assert!(
        serde_json::from_value::<crowsi_control_contracts::CertificateManagerHandoffEvidenceV2>(
            value
        )
        .is_err()
    );
}

#[test]
fn receipt_signature_is_raw_canonical_and_metadata_exact() {
    let authority = authority_evidence();
    for malformed in [
        STANDARD.encode([0_u8; 63]),
        STANDARD.encode([0_u8; 65]),
        STANDARD.encode([0_u8; 70]),
        format!("{}=", STANDARD.encode([0_u8; 64])),
    ] {
        let mut value = authority.clone();
        value.signed.signature_base64 = malformed;
        assert!(value.validate().is_err());
    }
    for mutate in [
        |signed: &mut CertificateReceiptSignatureV2| signed.key_id.push_str(".other"),
        |signed: &mut CertificateReceiptSignatureV2| signed.key_version.push_str(".other"),
        |signed: &mut CertificateReceiptSignatureV2| {
            signed.public_key_spki_sha256 = "99".repeat(32);
        },
        |signed: &mut CertificateReceiptSignatureV2| signed.key_purpose.push_str(".other"),
        |signed: &mut CertificateReceiptSignatureV2| signed.digest_sha256 = "98".repeat(32),
    ] {
        let mut value = authority.clone();
        mutate(&mut value.signed);
        assert!(value.validate().is_err());
    }
    let mut json = serde_json::to_value(authority).unwrap();
    json["signed"]["algorithm"] = json!("ecdsa-p256-sha256-der");
    assert!(serde_json::from_value::<CertificateAuthorityOutcomeEvidenceV2>(json).is_err());
}

#[test]
fn key_versions_and_recovery_deadline_are_canonical_and_bounded() {
    for invalid in ["version\n01", "version\0.01", "version.日本", "version 01"] {
        let mut value = handoff_evidence();
        value.receipt_key_version = invalid.into();
        value.signed.key_version = invalid.into();
        value.signed.digest_sha256 = value.certificate_digest_sha256();
        assert!(value.validate().is_err());
    }
    let authority = authority_evidence();
    let mut manager = manager_commit_evidence(&authority);
    manager.submission_recovery_deadline_epoch_s = manager.committed_at_epoch_s + 86_401;
    manager.signed.digest_sha256 = manager.certificate_digest_sha256();
    assert!(manager.validate().is_err());
    let mut manager = manager_commit_evidence(&authority);
    manager.evidence_issued_at_epoch_s = manager.committed_at_epoch_s - 1;
    manager.signed.digest_sha256 = manager.certificate_digest_sha256();
    assert!(manager.validate().is_err());
}
