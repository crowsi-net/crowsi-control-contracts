use serde::{Deserialize, Serialize};

use crate::certificate_v2::{
    CertificateActionV2, CertificateExecutionDispositionV2, CertificateLifecycleActionV2,
    CertificatePayloadV2, CertificateReceiptSignatureAlgorithmV2, CertificateReceiptSignatureV2,
    digest::DigestBuilder,
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CertificateAuthorityOutcomeEvidenceV2 {
    pub schema: String,
    pub evidence_id: String,
    pub nonce_base64: String,
    pub issuer: String,
    pub audience: String,
    pub action: CertificateActionV2,
    pub authorization_jti: String,
    pub operation_id: String,
    pub lease_digest_sha256: String,
    pub authorization_command_digest_sha256: String,
    pub target_resource_id: String,
    pub expected_resource_version: u64,
    pub previous_fence: u64,
    pub current_fence: u64,
    pub previous_lifecycle_revocation_epoch: u64,
    pub lifecycle_revocation_epoch: u64,
    pub disposition: CertificateExecutionDispositionV2,
    pub authority_outcome_digest_sha256: Option<String>,
    pub original_authorization_jti: Option<String>,
    pub original_operation_id: Option<String>,
    pub original_lease_digest_sha256: Option<String>,
    pub original_action: Option<CertificateLifecycleActionV2>,
    pub original_authority_command_digest_sha256: Option<String>,
    pub original_unknown_evidence_digest_sha256: Option<String>,
    pub lifecycle_reservation_id: Option<String>,
    pub original_previous_fence: Option<u64>,
    pub original_current_fence: Option<u64>,
    pub original_previous_lifecycle_revocation_epoch: Option<u64>,
    pub original_lifecycle_revocation_epoch: Option<u64>,
    pub security_domain: String,
    pub deployment_id: String,
    pub trust_revision: u64,
    pub authority_id: String,
    pub receipt_key_id: String,
    pub receipt_key_version: String,
    pub receipt_public_key_spki_sha256: String,
    pub receipt_signature_algorithm: CertificateReceiptSignatureAlgorithmV2,
    pub receipt_key_purpose: String,
    pub issued_at_epoch_s: u64,
    pub expires_at_epoch_s: u64,
    pub signed: CertificateReceiptSignatureV2,
}

impl CertificatePayloadV2 for CertificateAuthorityOutcomeEvidenceV2 {
    fn certificate_signing_payload(&self) -> Vec<u8> {
        let mut out = DigestBuilder::new("crowsi-certificate-authority-outcome-evidence-v2");
        for value in [
            &self.schema,
            &self.evidence_id,
            &self.nonce_base64,
            &self.issuer,
            &self.audience,
            self.action.as_str(),
            &self.authorization_jti,
            &self.operation_id,
            &self.lease_digest_sha256,
            &self.authorization_command_digest_sha256,
            &self.target_resource_id,
        ] {
            out.text(value);
        }
        for value in [
            self.expected_resource_version,
            self.previous_fence,
            self.current_fence,
            self.previous_lifecycle_revocation_epoch,
            self.lifecycle_revocation_epoch,
        ] {
            out.number(value);
        }
        out.text(self.disposition.as_str());
        for value in [
            self.authority_outcome_digest_sha256.as_deref(),
            self.original_authorization_jti.as_deref(),
            self.original_operation_id.as_deref(),
            self.original_lease_digest_sha256.as_deref(),
            self.original_action
                .map(CertificateLifecycleActionV2::as_str),
            self.original_authority_command_digest_sha256.as_deref(),
            self.original_unknown_evidence_digest_sha256.as_deref(),
            self.lifecycle_reservation_id.as_deref(),
        ] {
            out.optional(value);
        }
        for value in [
            self.original_previous_fence,
            self.original_current_fence,
            self.original_previous_lifecycle_revocation_epoch,
            self.original_lifecycle_revocation_epoch,
        ] {
            out.optional_number(value);
        }
        for value in [
            &self.security_domain,
            &self.deployment_id,
            &self.authority_id,
            &self.receipt_key_id,
            &self.receipt_key_version,
            &self.receipt_public_key_spki_sha256,
            &self.receipt_key_purpose,
        ] {
            out.text(value);
        }
        out.text(self.receipt_signature_algorithm.as_str());
        out.number(self.trust_revision);
        out.number(self.issued_at_epoch_s);
        out.number(self.expires_at_epoch_s);
        out.finish()
    }
}
