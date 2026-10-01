use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use crowsi_control_contracts::{
    CERTIFICATE_MANAGER_COMMIT_EVIDENCE_SCHEMA_V2, CertificateActionV2,
    CertificateAuthorityOutcomeEvidenceV2, CertificateExecutionDispositionV2,
    CertificateManagerCommitEvidenceV2, CertificatePayloadV2,
    CertificateReceiptSignatureAlgorithmV2,
};

use super::placeholder;

pub fn manager_commit_evidence(
    authority: &CertificateAuthorityOutcomeEvidenceV2,
) -> CertificateManagerCommitEvidenceV2 {
    let mut value = CertificateManagerCommitEvidenceV2 {
        schema: CERTIFICATE_MANAGER_COMMIT_EVIDENCE_SCHEMA_V2.into(),
        commit_id: "manager.commit.sample".into(),
        nonce_base64: URL_SAFE_NO_PAD.encode([2_u8; 32]),
        issuer: "service://crowsi/certificate-manager".into(),
        audience: "service://crowsi/policy-administrator".into(),
        action: CertificateActionV2::Issue,
        authorization_jti: authority.authorization_jti.clone(),
        operation_id: authority.operation_id.clone(),
        lease_digest_sha256: authority.lease_digest_sha256.clone(),
        authorization_command_digest_sha256: authority.authorization_command_digest_sha256.clone(),
        target_resource_id: authority.target_resource_id.clone(),
        state_revision: 1,
        resource_version: 1,
        previous_fence: 0,
        current_fence: 1,
        previous_lifecycle_revocation_epoch: 0,
        lifecycle_revocation_epoch: 0,
        disposition: CertificateExecutionDispositionV2::Completed,
        authority_evidence_id: authority.evidence_id.clone(),
        authority_evidence_digest_sha256: authority.certificate_digest_sha256(),
        security_domain: "security.crowsi".into(),
        deployment_id: "deployment.local".into(),
        trust_revision: 7,
        manager_workload: "spiffe://crowsi.test/certificate-manager".into(),
        commit_key_id: "manager.commit.key".into(),
        commit_key_version: "version.0001".into(),
        commit_public_key_spki_sha256: "50".repeat(32),
        commit_signature_algorithm:
            CertificateReceiptSignatureAlgorithmV2::EcdsaP256Sha256P1363LowS,
        commit_key_purpose: "certificate-manager-commit-receipt".into(),
        committed_at_epoch_s: 10_010,
        evidence_issued_at_epoch_s: 10_011,
        expires_at_epoch_s: 10_041,
        submission_recovery_deadline_epoch_s: 96_410,
        signed: placeholder(
            "manager.commit.key",
            "version.0001",
            &"50".repeat(32),
            "certificate-manager-commit-receipt",
        ),
    };
    value.signed.digest_sha256 = value.certificate_digest_sha256();
    value
}
