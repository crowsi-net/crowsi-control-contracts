use serde::{Deserialize, Serialize};

use crate::{
    ActionBindingV1, CanonicalPayloadV1, SECURITY_INTENT_SCHEMA_V1, SignedDigestV1,
    validation::{Validate, ValidationError, identifier, opaque, schema, short_window},
    workload::spiffe_workload,
};

const MAX_INTENT_TTL_MILLIS: i64 = 300_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityIntentV1 {
    pub schema: String,
    pub intent_id: String,
    pub jti: String,
    pub identity_context_id: String,
    pub pairwise_subject: String,
    pub actor: String,
    pub device: String,
    pub workload: String,
    pub profile: String,
    pub proof_key_ref: String,
    pub revocation_epoch: u64,
    pub binding: ActionBindingV1,
    pub requested_at: String,
    pub expires_at: String,
    pub reason: String,
    pub signed: SignedDigestV1,
}

impl Validate for SecurityIntentV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        schema(&self.schema, SECURITY_INTENT_SCHEMA_V1)?;
        identifier("intent_id", &self.intent_id)?;
        identifier("jti", &self.jti)?;
        identifier("identity_context_id", &self.identity_context_id)?;
        opaque("pairwise_subject", &self.pairwise_subject, 256)?;
        opaque("actor", &self.actor, 256)?;
        opaque("device", &self.device, 256)?;
        spiffe_workload("workload", &self.workload)?;
        opaque("profile", &self.profile, 256)?;
        opaque("proof_key_ref", &self.proof_key_ref, 256)?;
        self.binding.validate()?;
        opaque("reason", &self.reason, 512)?;
        short_window(
            "requested_at",
            &self.requested_at,
            &self.expires_at,
            MAX_INTENT_TTL_MILLIS,
        )?;
        self.signed.validate()?;
        self.validate_payload_digest()
    }
}
