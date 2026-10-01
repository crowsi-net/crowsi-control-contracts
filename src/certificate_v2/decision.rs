use serde::{Deserialize, Serialize};

use crate::{
    CERTIFICATE_POLICY_DECISION_SCHEMA_V2, Validate, ValidationError,
    certificate_v2::{
        CertificateActionV2, CertificateAuthorizationBindingV2, CertificateDetachedSignatureV2,
        CertificatePayloadV2,
        digest::DigestBuilder,
        rules::{bare_digest, epoch_window, id},
    },
};

const MAX_DECISION_TTL_SECONDS: u64 = 300;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CertificateDecisionEffectV2 {
    Permit,
    Deny,
}

impl CertificateDecisionEffectV2 {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Permit => "permit",
            Self::Deny => "deny",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CertificatePolicyDecisionV2 {
    pub schema: String,
    pub decision_id: String,
    pub request_digest_sha256: String,
    pub action: CertificateActionV2,
    pub binding: CertificateAuthorizationBindingV2,
    pub effect: CertificateDecisionEffectV2,
    pub issued_at_epoch_s: u64,
    pub expires_at_epoch_s: u64,
    pub signed: CertificateDetachedSignatureV2,
}

impl CertificatePayloadV2 for CertificatePolicyDecisionV2 {
    fn certificate_signing_payload(&self) -> Vec<u8> {
        let mut out = DigestBuilder::new("crowsi-certificate-policy-decision-v2");
        out.text(&self.schema);
        out.text(&self.decision_id);
        out.text(&self.request_digest_sha256);
        out.text(self.action.as_str());
        self.binding.add_to_digest(&mut out);
        out.text(self.effect.as_str());
        out.number(self.issued_at_epoch_s);
        out.number(self.expires_at_epoch_s);
        out.finish()
    }
}

impl Validate for CertificatePolicyDecisionV2 {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.schema != CERTIFICATE_POLICY_DECISION_SCHEMA_V2 {
            return Err(ValidationError::new("schema", "unsupported schema"));
        }
        id("decision_id", &self.decision_id)?;
        bare_digest("request_digest_sha256", &self.request_digest_sha256)?;
        self.binding.validate_for(self.action)?;
        epoch_window(
            self.issued_at_epoch_s,
            self.expires_at_epoch_s,
            MAX_DECISION_TTL_SECONDS,
        )?;
        self.signed.validate()?;
        if self.effect != CertificateDecisionEffectV2::Permit {
            return Err(ValidationError::new(
                "effect",
                "only permit decisions can authorize execution",
            ));
        }
        if self.signed.digest_sha256 != self.certificate_digest_sha256() {
            return Err(ValidationError::new(
                "signed.digest_sha256",
                "does not cover the decision payload",
            ));
        }
        Ok(())
    }
}
