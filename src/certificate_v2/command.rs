use serde::{Deserialize, Serialize};

use crate::{
    CERTIFICATE_EXECUTION_COMMAND_SCHEMA_V2, Validate, ValidationError,
    certificate_v2::{
        CertificateActionV2, CertificateAuthorizationBindingV2, CertificatePayloadV2,
        CertificateSignatureAlgorithmV2,
        digest::DigestBuilder,
        rules::{bare_digest, epoch_window, id},
    },
};

const MAX_COMMAND_TTL_SECONDS: u64 = 120;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CertificateExecutionCommandV2 {
    pub schema: String,
    pub authorization_id: String,
    pub jti: String,
    pub pa_reservation_id: String,
    pub operation_id: String,
    pub request_digest_sha256: String,
    pub action: CertificateActionV2,
    pub binding: CertificateAuthorizationBindingV2,
    pub decision_id: String,
    pub decision_digest_sha256: String,
    pub grant_id: String,
    pub grant_digest_sha256: String,
    pub signature_key_id: String,
    pub signature_key_version: String,
    pub signature_public_key_spki_sha256: String,
    pub signature_key_purpose: String,
    pub signature_algorithm: CertificateSignatureAlgorithmV2,
    pub related_authorization_jti: Option<String>,
    pub issued_at_epoch_s: u64,
    pub expires_at_epoch_s: u64,
    pub one_use: bool,
}

impl CertificatePayloadV2 for CertificateExecutionCommandV2 {
    fn certificate_signing_payload(&self) -> Vec<u8> {
        let mut out = DigestBuilder::new("crowsi-certificate-execution-command-v2");
        for value in [
            &self.schema,
            &self.authorization_id,
            &self.jti,
            &self.pa_reservation_id,
            &self.operation_id,
            &self.request_digest_sha256,
        ] {
            out.text(value);
        }
        out.text(self.action.as_str());
        self.binding.add_to_digest(&mut out);
        for value in [
            &self.decision_id,
            &self.decision_digest_sha256,
            &self.grant_id,
            &self.grant_digest_sha256,
            &self.signature_key_id,
        ] {
            out.text(value);
        }
        out.text(&self.signature_key_version);
        out.text(&self.signature_public_key_spki_sha256);
        out.text(&self.signature_key_purpose);
        out.text(self.signature_algorithm.as_str());
        out.optional(self.related_authorization_jti.as_deref());
        out.number(self.issued_at_epoch_s);
        out.number(self.expires_at_epoch_s);
        out.boolean(self.one_use);
        out.finish()
    }
}

impl Validate for CertificateExecutionCommandV2 {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.schema != CERTIFICATE_EXECUTION_COMMAND_SCHEMA_V2 {
            return Err(ValidationError::new("schema", "unsupported schema"));
        }
        for (field, value) in [
            ("authorization_id", self.authorization_id.as_str()),
            ("command.jti", &self.jti),
            ("pa_reservation_id", &self.pa_reservation_id),
            ("operation_id", &self.operation_id),
            ("command.decision_id", &self.decision_id),
            ("command.grant_id", &self.grant_id),
            ("signature_key_id", &self.signature_key_id),
            ("signature_key_purpose", &self.signature_key_purpose),
        ] {
            id(field, value)?;
        }
        for (field, value) in [
            ("request_digest_sha256", self.request_digest_sha256.as_str()),
            ("decision_digest_sha256", &self.decision_digest_sha256),
            ("grant_digest_sha256", &self.grant_digest_sha256),
            (
                "signature_public_key_spki_sha256",
                &self.signature_public_key_spki_sha256,
            ),
        ] {
            bare_digest(field, value)?;
        }
        if !(8..=160).contains(&self.signature_key_version.len())
            || !self.signature_key_version.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'-')
            })
        {
            return Err(ValidationError::new(
                "signature_key_version",
                "must be a bounded opaque version",
            ));
        }
        self.binding.validate_for(self.action)?;
        self.validate_relation()?;
        epoch_window(
            self.issued_at_epoch_s,
            self.expires_at_epoch_s,
            MAX_COMMAND_TTL_SECONDS,
        )?;
        self.one_use
            .then_some(())
            .ok_or(ValidationError::new("one_use", "must be true"))
    }
}

impl CertificateExecutionCommandV2 {
    fn validate_relation(&self) -> Result<(), ValidationError> {
        if let Some(value) = &self.related_authorization_jti {
            id("related_authorization_jti", value)?;
            if value == &self.jti {
                return Err(ValidationError::new(
                    "related_authorization_jti",
                    "cannot reference the current authorization",
                ));
            }
        }
        let requires_relation = matches!(
            self.action,
            CertificateActionV2::OperationStatus | CertificateActionV2::ReconcileUnknown
        );
        if requires_relation == self.related_authorization_jti.is_some() {
            Ok(())
        } else {
            Err(ValidationError::new(
                "related_authorization_jti",
                "must exist only for operation status or reconciliation",
            ))
        }
    }
}
