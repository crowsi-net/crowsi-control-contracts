use serde::{Deserialize, Serialize};

use crate::certificate_v2::{
    CertificateActionV2, CertificateExecutionDispositionV2, CertificatePayloadV2,
    CertificateReceiptSignatureAlgorithmV2, CertificateReceiptSignatureV2, digest::DigestBuilder,
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CertificateManagerCommitEvidenceV2 {
    pub schema: String,
    pub commit_id: String,
    pub nonce_base64: String,
    pub issuer: String,
    pub audience: String,
    pub action: CertificateActionV2,
    pub authorization_jti: String,
    pub operation_id: String,
    pub lease_digest_sha256: String,
    pub authorization_command_digest_sha256: String,
    pub target_resource_id: String,
    pub state_revision: u64,
    pub resource_version: u64,
    pub previous_fence: u64,
    pub current_fence: u64,
    pub previous_lifecycle_revocation_epoch: u64,
    pub lifecycle_revocation_epoch: u64,
    pub disposition: CertificateExecutionDispositionV2,
    pub authority_evidence_id: String,
    pub authority_evidence_digest_sha256: String,
    pub security_domain: String,
    pub deployment_id: String,
    pub trust_revision: u64,
    pub manager_workload: String,
    pub commit_key_id: String,
    pub commit_key_version: String,
    pub commit_public_key_spki_sha256: String,
    pub commit_signature_algorithm: CertificateReceiptSignatureAlgorithmV2,
    pub commit_key_purpose: String,
    pub committed_at_epoch_s: u64,
    pub evidence_issued_at_epoch_s: u64,
    pub expires_at_epoch_s: u64,
    pub submission_recovery_deadline_epoch_s: u64,
    pub signed: CertificateReceiptSignatureV2,
}

impl CertificatePayloadV2 for CertificateManagerCommitEvidenceV2 {
    fn certificate_signing_payload(&self) -> Vec<u8> {
        let mut out = DigestBuilder::new("crowsi-certificate-manager-commit-evidence-v2");
        for value in [
            &self.schema,
            &self.commit_id,
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
            self.state_revision,
            self.resource_version,
            self.previous_fence,
            self.current_fence,
            self.previous_lifecycle_revocation_epoch,
            self.lifecycle_revocation_epoch,
        ] {
            out.number(value);
        }
        out.text(self.disposition.as_str());
        for value in [
            &self.authority_evidence_id,
            &self.authority_evidence_digest_sha256,
            &self.security_domain,
            &self.deployment_id,
            &self.manager_workload,
            &self.commit_key_id,
            &self.commit_key_version,
            &self.commit_public_key_spki_sha256,
            &self.commit_key_purpose,
        ] {
            out.text(value);
        }
        out.text(self.commit_signature_algorithm.as_str());
        out.number(self.trust_revision);
        out.number(self.committed_at_epoch_s);
        out.number(self.evidence_issued_at_epoch_s);
        out.number(self.expires_at_epoch_s);
        out.number(self.submission_recovery_deadline_epoch_s);
        out.finish()
    }
}
