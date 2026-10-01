use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use crowsi_control_contracts::{
    CERTIFICATE_AUTHORITY_OUTCOME_EVIDENCE_SCHEMA_V2, CertificateActionV2,
    CertificateAuthorityOutcomeEvidenceV2, CertificateExecutionDispositionV2, CertificatePayloadV2,
    CertificateReceiptSignatureAlgorithmV2,
};

use super::placeholder;

pub fn authority_evidence() -> CertificateAuthorityOutcomeEvidenceV2 {
    let mut value = CertificateAuthorityOutcomeEvidenceV2 {
        schema: CERTIFICATE_AUTHORITY_OUTCOME_EVIDENCE_SCHEMA_V2.into(),
        evidence_id: "authority.evidence.sample".into(),
        nonce_base64: URL_SAFE_NO_PAD.encode([1_u8; 32]),
        issuer: "authority://crowsi/certificate".into(),
        audience: "service://crowsi/policy-administrator".into(),
        action: CertificateActionV2::Issue,
        authorization_jti: "authorization.jti.sample".into(),
        operation_id: "operation.certificate.sample".into(),
        lease_digest_sha256: "10".repeat(32),
        authorization_command_digest_sha256: "20".repeat(32),
        target_resource_id: "resource.certificate.sample".into(),
        expected_resource_version: 0,
        previous_fence: 0,
        current_fence: 1,
        previous_lifecycle_revocation_epoch: 0,
        lifecycle_revocation_epoch: 0,
        disposition: CertificateExecutionDispositionV2::Completed,
        authority_outcome_digest_sha256: Some("30".repeat(32)),
        original_authorization_jti: None,
        original_operation_id: None,
        original_lease_digest_sha256: None,
        original_action: None,
        original_authority_command_digest_sha256: None,
        original_unknown_evidence_digest_sha256: None,
        lifecycle_reservation_id: None,
        original_previous_fence: None,
        original_current_fence: None,
        original_previous_lifecycle_revocation_epoch: None,
        original_lifecycle_revocation_epoch: None,
        security_domain: "security.crowsi".into(),
        deployment_id: "deployment.local".into(),
        trust_revision: 7,
        authority_id: "authority.crowsi.local".into(),
        receipt_key_id: "authority.receipt.key".into(),
        receipt_key_version: "version.0001".into(),
        receipt_public_key_spki_sha256: "40".repeat(32),
        receipt_signature_algorithm:
            CertificateReceiptSignatureAlgorithmV2::EcdsaP256Sha256P1363LowS,
        receipt_key_purpose: "certificate-authority-receipt".into(),
        issued_at_epoch_s: 10_000,
        expires_at_epoch_s: 10_030,
        signed: placeholder(
            "authority.receipt.key",
            "version.0001",
            &"40".repeat(32),
            "certificate-authority-receipt",
        ),
    };
    value.signed.digest_sha256 = value.certificate_digest_sha256();
    value
}
