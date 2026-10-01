use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{
    SIGNED_CERTIFICATE_EXECUTION_AUTHORIZATION_SCHEMA_V2, Validate, ValidationError,
    certificate_v2::rules::{bare_digest, encoded, id},
};

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedCertificateExecutionAuthorizationV2 {
    schema: String,
    verifier_key_id: String,
    pa_pep_lease_base64: String,
    lease_digest_sha256: String,
    signature_base64: String,
}

impl SignedCertificateExecutionAuthorizationV2 {
    #[must_use]
    pub fn new(
        verifier_key_id: impl Into<String>,
        pa_pep_lease_base64: impl Into<String>,
        lease_digest_sha256: impl Into<String>,
        signature_base64: impl Into<String>,
    ) -> Self {
        Self {
            schema: SIGNED_CERTIFICATE_EXECUTION_AUTHORIZATION_SCHEMA_V2.into(),
            verifier_key_id: verifier_key_id.into(),
            pa_pep_lease_base64: pa_pep_lease_base64.into(),
            lease_digest_sha256: lease_digest_sha256.into(),
            signature_base64: signature_base64.into(),
        }
    }

    #[must_use]
    pub fn verifier_key_id(&self) -> &str {
        &self.verifier_key_id
    }

    #[must_use]
    pub fn pa_pep_lease_base64(&self) -> &str {
        &self.pa_pep_lease_base64
    }

    #[must_use]
    pub fn lease_digest_sha256(&self) -> &str {
        &self.lease_digest_sha256
    }

    #[must_use]
    pub fn signature_base64(&self) -> &str {
        &self.signature_base64
    }
}

impl Validate for SignedCertificateExecutionAuthorizationV2 {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.schema != SIGNED_CERTIFICATE_EXECUTION_AUTHORIZATION_SCHEMA_V2 {
            return Err(ValidationError::new("schema", "unsupported schema"));
        }
        id("verifier_key_id", &self.verifier_key_id)?;
        encoded("pa_pep_lease_base64", &self.pa_pep_lease_base64, 524_288)?;
        bare_digest("lease_digest_sha256", &self.lease_digest_sha256)?;
        encoded("signature_base64", &self.signature_base64, 16_384)
    }
}

impl fmt::Debug for SignedCertificateExecutionAuthorizationV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignedCertificateExecutionAuthorizationV2")
            .field("verifier_key_id", &self.verifier_key_id)
            .field("pa_pep_lease", &"[REDACTED]")
            .field("lease_digest_sha256", &self.lease_digest_sha256)
            .field("signature", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}
