use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};

use crate::{
    Validate, ValidationError,
    certificate_v2::rules::{bare_digest, id, version},
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CertificateReceiptSignatureAlgorithmV2 {
    EcdsaP256Sha256P1363LowS,
}

impl CertificateReceiptSignatureAlgorithmV2 {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EcdsaP256Sha256P1363LowS => "ecdsa-p256-sha256-p1363-low-s",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CertificateReceiptSignatureV2 {
    pub key_id: String,
    pub key_version: String,
    pub public_key_spki_sha256: String,
    pub key_purpose: String,
    pub algorithm: CertificateReceiptSignatureAlgorithmV2,
    pub digest_sha256: String,
    pub signature_base64: String,
}

impl Validate for CertificateReceiptSignatureV2 {
    fn validate(&self) -> Result<(), ValidationError> {
        id("receipt_signature.key_id", &self.key_id)?;
        id("receipt_signature.key_purpose", &self.key_purpose)?;
        version("receipt_signature.key_version", &self.key_version)?;
        bare_digest(
            "receipt_signature.public_key_spki_sha256",
            &self.public_key_spki_sha256,
        )?;
        bare_digest("receipt_signature.digest_sha256", &self.digest_sha256)?;
        let bytes = STANDARD.decode(&self.signature_base64).map_err(|_| {
            ValidationError::new("receipt_signature.signature_base64", "invalid base64")
        })?;
        if bytes.len() != 64 || STANDARD.encode(&bytes) != self.signature_base64 {
            return Err(ValidationError::new(
                "receipt_signature.signature_base64",
                "must be canonical 64-byte IEEE P1363",
            ));
        }
        Ok(())
    }
}
