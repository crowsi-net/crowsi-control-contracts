use crate::{
    CERTIFICATE_AUTHORITY_OUTCOME_EVIDENCE_SCHEMA_V2, Validate, ValidationError,
    certificate_v2::{
        CertificateActionV2, CertificateAuthorityOutcomeEvidenceV2,
        CertificateExecutionDispositionV2, CertificatePayloadV2,
        rules::{bare_digest, canonical_nonce, epoch_window, id, version},
    },
};

impl Validate for CertificateAuthorityOutcomeEvidenceV2 {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.schema != CERTIFICATE_AUTHORITY_OUTCOME_EVIDENCE_SCHEMA_V2 {
            return Err(ValidationError::new("schema", "unsupported schema"));
        }
        for (field, value) in [
            ("evidence_id", self.evidence_id.as_str()),
            ("issuer", &self.issuer),
            ("audience", &self.audience),
            ("authorization_jti", &self.authorization_jti),
            ("operation_id", &self.operation_id),
            ("target_resource_id", &self.target_resource_id),
            ("security_domain", &self.security_domain),
            ("deployment_id", &self.deployment_id),
            ("authority_id", &self.authority_id),
            ("receipt_key_id", &self.receipt_key_id),
            ("receipt_key_purpose", &self.receipt_key_purpose),
        ] {
            id(field, value)?;
        }
        version("receipt_key_version", &self.receipt_key_version)?;
        validate_digests(self)?;
        validate_relation(self)?;
        canonical_nonce("nonce_base64", &self.nonce_base64, 32, 384)?;
        if self.trust_revision == 0 || self.receipt_key_purpose != "certificate-authority-receipt" {
            return Err(ValidationError::new(
                "outcome_evidence",
                "weak nonce or trust revision",
            ));
        }
        epoch_window(self.issued_at_epoch_s, self.expires_at_epoch_s, 60)?;
        self.signed.validate()?;
        if self.signed.key_id != self.receipt_key_id
            || self.signed.key_version != self.receipt_key_version
            || self.signed.public_key_spki_sha256 != self.receipt_public_key_spki_sha256
            || self.signed.key_purpose != self.receipt_key_purpose
            || self.signed.algorithm != self.receipt_signature_algorithm
            || self.signed.digest_sha256 != self.certificate_digest_sha256()
        {
            return Err(ValidationError::new(
                "signed",
                "must cover the exact authority evidence",
            ));
        }
        Ok(())
    }
}

fn validate_digests(value: &CertificateAuthorityOutcomeEvidenceV2) -> Result<(), ValidationError> {
    for (field, digest) in [
        ("lease_digest_sha256", value.lease_digest_sha256.as_str()),
        (
            "authorization_command_digest_sha256",
            &value.authorization_command_digest_sha256,
        ),
        (
            "receipt_public_key_spki_sha256",
            &value.receipt_public_key_spki_sha256,
        ),
    ] {
        bare_digest(field, digest)?;
    }
    for digest in [
        value.authority_outcome_digest_sha256.as_deref(),
        value.original_lease_digest_sha256.as_deref(),
        value.original_authority_command_digest_sha256.as_deref(),
        value.original_unknown_evidence_digest_sha256.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        bare_digest("optional_outcome_digest", digest)?;
    }
    Ok(())
}

fn validate_relation(value: &CertificateAuthorityOutcomeEvidenceV2) -> Result<(), ValidationError> {
    let reconciliation = (
        value.original_authorization_jti.as_deref(),
        value.original_operation_id.as_deref(),
        value.original_lease_digest_sha256.as_deref(),
        value.original_action,
        value.original_authority_command_digest_sha256.as_deref(),
        value.original_unknown_evidence_digest_sha256.as_deref(),
        value.lifecycle_reservation_id.as_deref(),
        value.original_previous_fence,
        value.original_current_fence,
        value.original_previous_lifecycle_revocation_epoch,
        value.original_lifecycle_revocation_epoch,
    );
    let relation_valid = match reconciliation {
        (
            Some(jti),
            Some(operation),
            Some(_),
            Some(_),
            Some(_),
            Some(_),
            Some(reservation),
            Some(_),
            Some(_),
            Some(_),
            Some(_),
        ) => {
            id("original_authorization_jti", jti)?;
            id("original_operation_id", operation)?;
            id("lifecycle_reservation_id", reservation)?;
            value.action == CertificateActionV2::ReconcileUnknown
        }
        (None, None, None, None, None, None, None, None, None, None, None) => {
            value.action != CertificateActionV2::ReconcileUnknown
        }
        _ => false,
    };
    let disposition_valid = if value.action == CertificateActionV2::ReconcileUnknown {
        match value.disposition {
            CertificateExecutionDispositionV2::Completed => {
                value.authority_outcome_digest_sha256.is_some()
            }
            CertificateExecutionDispositionV2::NotExecuted
            | CertificateExecutionDispositionV2::StillUnknown => {
                value.authority_outcome_digest_sha256.is_none()
            }
        }
    } else {
        value.disposition == CertificateExecutionDispositionV2::Completed
            && value.authority_outcome_digest_sha256.is_some()
    };
    (relation_valid && disposition_valid)
        .then_some(())
        .ok_or(ValidationError::new(
            "outcome_relation",
            "invalid disposition binding",
        ))
}
