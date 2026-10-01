use crate::{
    CERTIFICATE_MANAGER_HANDOFF_EVIDENCE_SCHEMA_V2, Validate, ValidationError,
    certificate_v2::{
        CertificateManagerHandoffEvidenceV2, CertificatePayloadV2,
        rules::{bare_digest, canonical_nonce, epoch_window, id, version},
    },
};

impl Validate for CertificateManagerHandoffEvidenceV2 {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.schema != CERTIFICATE_MANAGER_HANDOFF_EVIDENCE_SCHEMA_V2 {
            return Err(ValidationError::new("schema", "unsupported schema"));
        }
        for (field, value) in [
            ("receipt_id", self.receipt_id.as_str()),
            ("issuer", &self.issuer),
            ("audience", &self.audience),
            ("authorization_jti", &self.authorization_jti),
            ("operation_id", &self.operation_id),
            ("security_domain", &self.security_domain),
            ("deployment_id", &self.deployment_id),
            ("target_resource_id", &self.target_resource_id),
            ("manager_workload", &self.manager_workload),
            ("receipt_key_id", &self.receipt_key_id),
            ("receipt_key_purpose", &self.receipt_key_purpose),
        ] {
            id(field, value)?;
        }
        version("receipt_key_version", &self.receipt_key_version)?;
        for (field, value) in [
            ("lease_digest_sha256", self.lease_digest_sha256.as_str()),
            (
                "authorization_command_digest_sha256",
                &self.authorization_command_digest_sha256,
            ),
            (
                "receipt_public_key_spki_sha256",
                &self.receipt_public_key_spki_sha256,
            ),
        ] {
            bare_digest(field, value)?;
        }
        canonical_nonce("nonce_base64", &self.nonce_base64, 32, 384)?;
        if self.trust_revision == 0
            || self.receipt_key_purpose != "certificate-manager-handoff-receipt"
        {
            return Err(ValidationError::new(
                "manager_handoff",
                "invalid trust revision or key purpose",
            ));
        }
        epoch_window(self.observed_at_epoch_s, self.expires_at_epoch_s, 60)?;
        self.signed.validate()?;
        let exact = self.signed.key_id == self.receipt_key_id
            && self.signed.key_version == self.receipt_key_version
            && self.signed.public_key_spki_sha256 == self.receipt_public_key_spki_sha256
            && self.signed.key_purpose == self.receipt_key_purpose
            && self.signed.algorithm == self.receipt_signature_algorithm
            && self.signed.digest_sha256 == self.certificate_digest_sha256();
        exact
            .then_some(())
            .ok_or(ValidationError::new("signed", "must cover exact handoff"))
    }
}
