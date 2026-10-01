use serde::{Deserialize, Serialize};

use crate::{
    AssuranceLevel, CanonicalPayloadV1, SignedDigestV1, VERIFIED_IDENTITY_CONTEXT_SCHEMA_V1,
    validation::{Validate, ValidationError, https_uri, identifier, opaque, schema, short_window},
    workload::spiffe_workload,
};

const MAX_IDENTITY_TTL_MILLIS: i64 = 900_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiedIdentityContextV1 {
    pub schema: String,
    pub context_id: String,
    pub issuer: String,
    pub pairwise_subject: String,
    pub actor: String,
    pub device: String,
    pub workload: String,
    pub profile: String,
    pub proof_key_ref: String,
    pub assurance: AssuranceLevel,
    pub authorization_grant_id: String,
    pub revocation_epoch: u64,
    pub authenticated_at: String,
    pub expires_at: String,
    pub audience: String,
    pub signed: SignedDigestV1,
}

impl Validate for VerifiedIdentityContextV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        schema(&self.schema, VERIFIED_IDENTITY_CONTEXT_SCHEMA_V1)?;
        identifier("context_id", &self.context_id)?;
        https_uri("issuer", &self.issuer)?;
        opaque("pairwise_subject", &self.pairwise_subject, 256)?;
        opaque("actor", &self.actor, 256)?;
        opaque("device", &self.device, 256)?;
        spiffe_workload("workload", &self.workload)?;
        opaque("profile", &self.profile, 256)?;
        opaque("proof_key_ref", &self.proof_key_ref, 256)?;
        opaque("authorization_grant_id", &self.authorization_grant_id, 256)?;
        identifier("audience", &self.audience)?;
        short_window(
            "authenticated_at",
            &self.authenticated_at,
            &self.expires_at,
            MAX_IDENTITY_TTL_MILLIS,
        )?;
        self.signed.validate()?;
        self.validate_payload_digest()
    }
}
