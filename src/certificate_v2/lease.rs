use serde::{Deserialize, Serialize};

use crate::{
    CERTIFICATE_EXECUTION_LEASE_SCHEMA_V2, Validate, ValidationError,
    certificate_v2::{
        CertificateExecutionCommandV2, CertificatePayloadV2,
        digest::DigestBuilder,
        rules::{bare_digest, id},
    },
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CertificateExecutionLeaseV2 {
    pub schema: String,
    pub pa_reservation_id: String,
    pub command: CertificateExecutionCommandV2,
    pub authorization_command_digest_sha256: String,
    pub reserved_at_epoch_s: u64,
    pub one_use: bool,
}

impl CertificatePayloadV2 for CertificateExecutionLeaseV2 {
    fn certificate_signing_payload(&self) -> Vec<u8> {
        let mut out = DigestBuilder::new("crowsi-certificate-execution-lease-v2");
        out.text(&self.schema);
        out.text(&self.pa_reservation_id);
        out.text(&self.authorization_command_digest_sha256);
        out.number(self.reserved_at_epoch_s);
        out.boolean(self.one_use);
        let command = self.command.certificate_signing_payload();
        out.bytes(&command);
        out.finish()
    }
}

impl Validate for CertificateExecutionLeaseV2 {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.schema != CERTIFICATE_EXECUTION_LEASE_SCHEMA_V2 {
            return Err(ValidationError::new("schema", "unsupported schema"));
        }
        id("pa_reservation_id", &self.pa_reservation_id)?;
        bare_digest(
            "authorization_command_digest_sha256",
            &self.authorization_command_digest_sha256,
        )?;
        self.command.validate()?;
        let exact = self.pa_reservation_id == self.command.pa_reservation_id
            && self.authorization_command_digest_sha256 == self.command.certificate_digest_sha256()
            && self.command.issued_at_epoch_s <= self.reserved_at_epoch_s
            && self.reserved_at_epoch_s < self.command.expires_at_epoch_s
            && self.one_use
            && self.command.one_use;
        exact.then_some(()).ok_or(ValidationError::new(
            "lease_binding",
            "reservation, command digest, validity, and one-use flag must match",
        ))
    }
}
