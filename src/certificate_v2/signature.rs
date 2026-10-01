use serde::{Deserialize, Serialize};

use crate::{
    Validate, ValidationError,
    certificate_v2::rules::{bare_digest, encoded, id},
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CertificateSignatureAlgorithmV2 {
    Ed25519,
}

impl CertificateSignatureAlgorithmV2 {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ed25519 => "ed25519",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CertificateDetachedSignatureV2 {
    pub key_id: String,
    pub algorithm: CertificateSignatureAlgorithmV2,
    pub digest_sha256: String,
    pub signature_base64: String,
}

impl Validate for CertificateDetachedSignatureV2 {
    fn validate(&self) -> Result<(), ValidationError> {
        id("signed.key_id", &self.key_id)?;
        bare_digest("signed.digest_sha256", &self.digest_sha256)?;
        encoded("signed.signature_base64", &self.signature_base64, 16_384)
    }
}
