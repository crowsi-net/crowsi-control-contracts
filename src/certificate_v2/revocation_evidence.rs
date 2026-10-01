use serde::{Deserialize, Serialize};

use crate::{
    CERTIFICATE_REVOCATION_EVIDENCE_SCHEMA_V2, Validate, ValidationError,
    certificate_v2::{
        CertificateDetachedSignatureV2, CertificatePayloadV2,
        digest::DigestBuilder,
        rules::{bare_digest, id},
    },
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CertificateRevocationEvidenceV2 {
    pub schema: String,
    pub snapshot_id: String,
    pub issuer: String,
    pub audience: String,
    pub pairwise_subject: String,
    pub previous_identity_revocation_epoch: u64,
    pub identity_revocation_epoch: u64,
    pub verified_at_epoch_s: u64,
    pub authoritative: bool,
    pub signed: CertificateDetachedSignatureV2,
}

impl CertificatePayloadV2 for CertificateRevocationEvidenceV2 {
    fn certificate_signing_payload(&self) -> Vec<u8> {
        let mut out = DigestBuilder::new("crowsi-certificate-identity-revocation-evidence-v2");
        for value in [
            &self.schema,
            &self.snapshot_id,
            &self.issuer,
            &self.audience,
            &self.pairwise_subject,
        ] {
            out.text(value);
        }
        out.number(self.previous_identity_revocation_epoch);
        out.number(self.identity_revocation_epoch);
        out.number(self.verified_at_epoch_s);
        out.boolean(self.authoritative);
        out.finish()
    }
}

impl Validate for CertificateRevocationEvidenceV2 {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.schema != CERTIFICATE_REVOCATION_EVIDENCE_SCHEMA_V2 {
            return Err(ValidationError::new("schema", "unsupported schema"));
        }
        for (field, value) in [
            ("snapshot_id", self.snapshot_id.as_str()),
            ("revocation.issuer", &self.issuer),
            ("revocation.audience", &self.audience),
            ("pairwise_subject", &self.pairwise_subject),
        ] {
            id(field, value)?;
        }
        if !self.authoritative
            || self.previous_identity_revocation_epoch > self.identity_revocation_epoch
        {
            return Err(ValidationError::new(
                "identity_revocation_epoch",
                "authoritative revocation evidence cannot roll back",
            ));
        }
        self.signed.validate()?;
        bare_digest("signed.digest_sha256", &self.signed.digest_sha256)?;
        if self.signed.digest_sha256 != self.certificate_digest_sha256() {
            return Err(ValidationError::new(
                "signed.digest_sha256",
                "does not cover revocation evidence",
            ));
        }
        Ok(())
    }
}
