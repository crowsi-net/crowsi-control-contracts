use serde::{Deserialize, Serialize};

use crate::certificate_v2::{
    CertificateActionV2, CertificateManagerHandoffDispositionV2, CertificatePayloadV2,
    CertificateReceiptSignatureAlgorithmV2, CertificateReceiptSignatureV2, digest::DigestBuilder,
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CertificateManagerHandoffEvidenceV2 {
    pub schema: String,
    pub receipt_id: String,
    pub nonce_base64: String,
    pub issuer: String,
    pub audience: String,
    pub disposition: CertificateManagerHandoffDispositionV2,
    pub action: CertificateActionV2,
    pub authorization_jti: String,
    pub operation_id: String,
    pub lease_digest_sha256: String,
    pub authorization_command_digest_sha256: String,
    pub security_domain: String,
    pub deployment_id: String,
    pub trust_revision: u64,
    pub target_resource_id: String,
    pub expected_resource_version: u64,
    pub previous_fence: u64,
    pub current_fence: u64,
    pub previous_lifecycle_revocation_epoch: u64,
    pub lifecycle_revocation_epoch: u64,
    pub manager_workload: String,
    pub receipt_key_id: String,
    pub receipt_key_version: String,
    pub receipt_public_key_spki_sha256: String,
    pub receipt_signature_algorithm: CertificateReceiptSignatureAlgorithmV2,
    pub receipt_key_purpose: String,
    pub observed_at_epoch_s: u64,
    pub expires_at_epoch_s: u64,
    pub signed: CertificateReceiptSignatureV2,
}

impl CertificatePayloadV2 for CertificateManagerHandoffEvidenceV2 {
    fn certificate_signing_payload(&self) -> Vec<u8> {
        let mut out = DigestBuilder::new("crowsi-certificate-manager-handoff-evidence-v2");
        for value in [
            &self.schema,
            &self.receipt_id,
            &self.nonce_base64,
            &self.issuer,
            &self.audience,
            self.disposition.as_str(),
            self.action.as_str(),
            &self.authorization_jti,
            &self.operation_id,
            &self.lease_digest_sha256,
            &self.authorization_command_digest_sha256,
            &self.security_domain,
            &self.deployment_id,
        ] {
            out.text(value);
        }
        out.number(self.trust_revision);
        out.text(&self.target_resource_id);
        for value in [
            self.expected_resource_version,
            self.previous_fence,
            self.current_fence,
            self.previous_lifecycle_revocation_epoch,
            self.lifecycle_revocation_epoch,
        ] {
            out.number(value);
        }
        for value in [
            &self.manager_workload,
            &self.receipt_key_id,
            &self.receipt_key_version,
            &self.receipt_public_key_spki_sha256,
            &self.receipt_key_purpose,
        ] {
            out.text(value);
        }
        out.text(self.receipt_signature_algorithm.as_str());
        out.number(self.observed_at_epoch_s);
        out.number(self.expires_at_epoch_s);
        out.finish()
    }
}
