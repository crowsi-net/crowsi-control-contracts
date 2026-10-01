use serde::{Deserialize, Serialize};

use crate::{
    CERTIFICATE_EXECUTION_GRANT_SCHEMA_V2, Validate, ValidationError,
    certificate_v2::{
        CertificateActionV2, CertificateAuthorizationBindingV2, CertificateDetachedSignatureV2,
        CertificatePayloadV2,
        digest::DigestBuilder,
        rules::{bare_digest, epoch_window, id},
    },
};

const MAX_GRANT_TTL_SECONDS: u64 = 120;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CertificateExecutionGrantV2 {
    pub schema: String,
    pub grant_id: String,
    pub jti: String,
    pub decision_id: String,
    pub decision_digest_sha256: String,
    pub request_digest_sha256: String,
    pub action: CertificateActionV2,
    pub binding: CertificateAuthorizationBindingV2,
    pub issued_at_epoch_s: u64,
    pub expires_at_epoch_s: u64,
    pub use_limit: u8,
    pub signed: CertificateDetachedSignatureV2,
}

impl CertificatePayloadV2 for CertificateExecutionGrantV2 {
    fn certificate_signing_payload(&self) -> Vec<u8> {
        let mut out = DigestBuilder::new("crowsi-certificate-execution-grant-v2");
        for value in [
            &self.schema,
            &self.grant_id,
            &self.jti,
            &self.decision_id,
            &self.decision_digest_sha256,
            &self.request_digest_sha256,
        ] {
            out.text(value);
        }
        out.text(self.action.as_str());
        self.binding.add_to_digest(&mut out);
        out.number(self.issued_at_epoch_s);
        out.number(self.expires_at_epoch_s);
        out.number(u64::from(self.use_limit));
        out.finish()
    }
}

impl Validate for CertificateExecutionGrantV2 {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.schema != CERTIFICATE_EXECUTION_GRANT_SCHEMA_V2 {
            return Err(ValidationError::new("schema", "unsupported schema"));
        }
        id("grant_id", &self.grant_id)?;
        id("grant.jti", &self.jti)?;
        id("grant.decision_id", &self.decision_id)?;
        bare_digest("decision_digest_sha256", &self.decision_digest_sha256)?;
        bare_digest("request_digest_sha256", &self.request_digest_sha256)?;
        self.binding.validate_for(self.action)?;
        epoch_window(
            self.issued_at_epoch_s,
            self.expires_at_epoch_s,
            MAX_GRANT_TTL_SECONDS,
        )?;
        if self.use_limit != 1 {
            return Err(ValidationError::new("use_limit", "must be exactly one"));
        }
        self.signed.validate()?;
        if self.signed.digest_sha256 != self.certificate_digest_sha256() {
            return Err(ValidationError::new(
                "signed.digest_sha256",
                "does not cover the grant payload",
            ));
        }
        Ok(())
    }
}
