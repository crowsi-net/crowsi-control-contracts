use crate::{
    CERTIFICATE_MANAGER_COMMIT_EVIDENCE_SCHEMA_V2, Validate, ValidationError,
    certificate_v2::{
        CertificateManagerCommitEvidenceV2, CertificatePayloadV2,
        rules::{bare_digest, canonical_nonce, epoch_window, id, version},
    },
};

impl Validate for CertificateManagerCommitEvidenceV2 {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.schema != CERTIFICATE_MANAGER_COMMIT_EVIDENCE_SCHEMA_V2 {
            return Err(ValidationError::new("schema", "unsupported schema"));
        }
        for (field, value) in [
            ("commit_id", self.commit_id.as_str()),
            ("issuer", &self.issuer),
            ("audience", &self.audience),
            ("authorization_jti", &self.authorization_jti),
            ("operation_id", &self.operation_id),
            ("target_resource_id", &self.target_resource_id),
            ("authority_evidence_id", &self.authority_evidence_id),
            ("security_domain", &self.security_domain),
            ("deployment_id", &self.deployment_id),
            ("manager_workload", &self.manager_workload),
            ("commit_key_id", &self.commit_key_id),
            ("commit_key_purpose", &self.commit_key_purpose),
        ] {
            id(field, value)?;
        }
        version("commit_key_version", &self.commit_key_version)?;
        for (field, value) in [
            ("lease_digest_sha256", self.lease_digest_sha256.as_str()),
            (
                "authorization_command_digest_sha256",
                &self.authorization_command_digest_sha256,
            ),
            (
                "authority_evidence_digest_sha256",
                &self.authority_evidence_digest_sha256,
            ),
            (
                "commit_public_key_spki_sha256",
                &self.commit_public_key_spki_sha256,
            ),
        ] {
            bare_digest(field, value)?;
        }
        canonical_nonce("nonce_base64", &self.nonce_base64, 32, 384)?;
        if self.state_revision == 0
            || self.trust_revision == 0
            || self.commit_key_purpose != "certificate-manager-commit-receipt"
        {
            return Err(ValidationError::new(
                "manager_commit",
                "weak nonce or state revision",
            ));
        }
        epoch_window(self.evidence_issued_at_epoch_s, self.expires_at_epoch_s, 60)?;
        if self.submission_recovery_deadline_epoch_s <= self.committed_at_epoch_s
            || self
                .submission_recovery_deadline_epoch_s
                .saturating_sub(self.committed_at_epoch_s)
                > 86_400
            || self.expires_at_epoch_s > self.submission_recovery_deadline_epoch_s
            || self.committed_at_epoch_s > self.evidence_issued_at_epoch_s
            || self.evidence_issued_at_epoch_s >= self.submission_recovery_deadline_epoch_s
        {
            return Err(ValidationError::new(
                "submission_recovery_deadline_epoch_s",
                "must be signed and bounded to 24 hours",
            ));
        }
        self.signed.validate()?;
        if self.signed.key_id != self.commit_key_id
            || self.signed.key_version != self.commit_key_version
            || self.signed.public_key_spki_sha256 != self.commit_public_key_spki_sha256
            || self.signed.key_purpose != self.commit_key_purpose
            || self.signed.algorithm != self.commit_signature_algorithm
            || self.signed.digest_sha256 != self.certificate_digest_sha256()
        {
            return Err(ValidationError::new(
                "signed",
                "must cover the exact manager commit",
            ));
        }
        Ok(())
    }
}
