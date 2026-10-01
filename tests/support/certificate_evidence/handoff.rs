use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use crowsi_control_contracts::{
    CERTIFICATE_MANAGER_HANDOFF_EVIDENCE_SCHEMA_V2, CertificateActionV2,
    CertificateManagerHandoffDispositionV2, CertificateManagerHandoffEvidenceV2,
    CertificatePayloadV2, CertificateReceiptSignatureAlgorithmV2,
};

use super::placeholder;

pub fn handoff_evidence() -> CertificateManagerHandoffEvidenceV2 {
    let mut value = CertificateManagerHandoffEvidenceV2 {
        schema: CERTIFICATE_MANAGER_HANDOFF_EVIDENCE_SCHEMA_V2.into(),
        receipt_id: "manager.handoff.sample".into(),
        nonce_base64: URL_SAFE_NO_PAD.encode([3_u8; 32]),
        issuer: "service://crowsi/certificate-manager".into(),
        audience: "service://crowsi/policy-administrator".into(),
        disposition: CertificateManagerHandoffDispositionV2::Accepted,
        action: CertificateActionV2::Issue,
        authorization_jti: "authorization.jti.sample".into(),
        operation_id: "operation.certificate.sample".into(),
        lease_digest_sha256: "10".repeat(32),
        authorization_command_digest_sha256: "20".repeat(32),
        security_domain: "security.crowsi".into(),
        deployment_id: "deployment.local".into(),
        trust_revision: 7,
        target_resource_id: "resource.certificate.sample".into(),
        expected_resource_version: 0,
        previous_fence: 0,
        current_fence: 1,
        previous_lifecycle_revocation_epoch: 0,
        lifecycle_revocation_epoch: 0,
        manager_workload: "spiffe://crowsi.test/certificate-manager".into(),
        receipt_key_id: "manager.handoff.key".into(),
        receipt_key_version: "version.0001".into(),
        receipt_public_key_spki_sha256: "60".repeat(32),
        receipt_signature_algorithm:
            CertificateReceiptSignatureAlgorithmV2::EcdsaP256Sha256P1363LowS,
        receipt_key_purpose: "certificate-manager-handoff-receipt".into(),
        observed_at_epoch_s: 10_005,
        expires_at_epoch_s: 10_035,
        signed: placeholder(
            "manager.handoff.key",
            "version.0001",
            &"60".repeat(32),
            "certificate-manager-handoff-receipt",
        ),
    };
    value.signed.digest_sha256 = value.certificate_digest_sha256();
    value
}
