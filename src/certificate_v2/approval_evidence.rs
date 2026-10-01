use serde::{Deserialize, Serialize};

use crate::{
    CERTIFICATE_APPROVAL_EVIDENCE_SCHEMA_V2, Validate, ValidationError,
    certificate_v2::{
        CertificateActionV2, CertificateApprovalAssuranceV2, CertificateApprovalMethodV2,
        CertificateDetachedSignatureV2, CertificatePayloadV2,
        digest::DigestBuilder,
        rules::{bare_digest, canonical_nonce, epoch_window, id},
    },
};

const MAX_APPROVAL_TTL_SECONDS: u64 = 60;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct CertificateApprovalEvidenceV2 {
    pub schema: String,
    pub approval_id: String,
    pub challenge_id: String,
    pub challenge_nonce_base64: String,
    pub issuer: String,
    pub audience: String,
    pub relying_party_id: String,
    pub origin: String,
    pub challenge_authority_ref: String,
    pub approver_pairwise_subject: String,
    pub approver_actor: String,
    pub approver_profile: String,
    pub approver_device: String,
    pub approver_proof_key_ref: String,
    pub action: CertificateActionV2,
    pub target_resource_id: String,
    pub request_digest_sha256: String,
    pub credential_id: String,
    pub ceremony_digest_sha256: String,
    pub channel_binding_digest_sha256: String,
    pub method: CertificateApprovalMethodV2,
    pub assurance: CertificateApprovalAssuranceV2,
    pub user_verified: bool,
    pub phishing_resistant: bool,
    pub authenticator_sign_count: u64,
    pub authenticator_backup_eligible: bool,
    pub authenticator_backup_state: bool,
    pub issued_at_epoch_s: u64,
    pub expires_at_epoch_s: u64,
    pub signed: CertificateDetachedSignatureV2,
}

impl CertificatePayloadV2 for CertificateApprovalEvidenceV2 {
    fn certificate_signing_payload(&self) -> Vec<u8> {
        let mut out = DigestBuilder::new("crowsi-certificate-approval-evidence-v2");
        for value in [
            &self.schema,
            &self.approval_id,
            &self.challenge_id,
            &self.challenge_nonce_base64,
            &self.issuer,
            &self.audience,
            &self.relying_party_id,
            &self.origin,
            &self.challenge_authority_ref,
            &self.approver_pairwise_subject,
            &self.approver_actor,
            &self.approver_profile,
            &self.approver_device,
            &self.approver_proof_key_ref,
            self.action.as_str(),
            &self.target_resource_id,
            &self.request_digest_sha256,
            &self.credential_id,
            &self.ceremony_digest_sha256,
            &self.channel_binding_digest_sha256,
            self.method.as_str(),
            self.assurance.as_str(),
        ] {
            out.text(value);
        }
        out.boolean(self.user_verified);
        out.boolean(self.phishing_resistant);
        out.number(self.authenticator_sign_count);
        out.boolean(self.authenticator_backup_eligible);
        out.boolean(self.authenticator_backup_state);
        out.number(self.issued_at_epoch_s);
        out.number(self.expires_at_epoch_s);
        out.finish()
    }
}

impl Validate for CertificateApprovalEvidenceV2 {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.schema != CERTIFICATE_APPROVAL_EVIDENCE_SCHEMA_V2 {
            return Err(ValidationError::new("schema", "unsupported schema"));
        }
        for (field, value) in [
            ("approval_id", self.approval_id.as_str()),
            ("challenge_id", &self.challenge_id),
            ("approval.issuer", &self.issuer),
            ("approval.audience", &self.audience),
            ("relying_party_id", &self.relying_party_id),
            ("origin", &self.origin),
            ("challenge_authority_ref", &self.challenge_authority_ref),
            ("approver_pairwise_subject", &self.approver_pairwise_subject),
            ("approver_actor", &self.approver_actor),
            ("approver_profile", &self.approver_profile),
            ("approver_device", &self.approver_device),
            ("approver_proof_key_ref", &self.approver_proof_key_ref),
            ("target_resource_id", &self.target_resource_id),
            ("credential_id", &self.credential_id),
        ] {
            id(field, value)?;
        }
        canonical_nonce(
            "challenge_nonce_base64",
            &self.challenge_nonce_base64,
            16,
            384,
        )?;
        bare_digest("request_digest_sha256", &self.request_digest_sha256)?;
        bare_digest("ceremony_digest_sha256", &self.ceremony_digest_sha256)?;
        bare_digest(
            "channel_binding_digest_sha256",
            &self.channel_binding_digest_sha256,
        )?;
        epoch_window(
            self.issued_at_epoch_s,
            self.expires_at_epoch_s,
            MAX_APPROVAL_TTL_SECONDS,
        )?;
        if !self.user_verified
            || !self.phishing_resistant
            || (self.authenticator_backup_state && !self.authenticator_backup_eligible)
        {
            return Err(ValidationError::new(
                "approval_verification",
                "phishing-resistant user verification is required",
            ));
        }
        self.signed.validate()?;
        if self.signed.digest_sha256 != self.certificate_digest_sha256() {
            return Err(ValidationError::new(
                "signed.digest_sha256",
                "does not cover approval evidence",
            ));
        }
        Ok(())
    }
}
