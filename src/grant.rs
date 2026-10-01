use serde::{Deserialize, Serialize};

use crate::{
    ActionBindingV1, AssuranceLevel, CanonicalPayloadV1, ENFORCEMENT_GRANT_SCHEMA_V1,
    SignedDigestV1,
    validation::{Validate, ValidationError, digest, identifier, opaque, schema, short_window},
    workload::spiffe_workload,
};

const MAX_GRANT_TTL_MILLIS: i64 = 120_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnforcementGrantV1 {
    pub schema: String,
    pub grant_id: String,
    pub jti: String,
    pub decision_id: String,
    pub intent_jti: String,
    pub identity_context_id: String,
    pub pairwise_subject: String,
    pub actor: String,
    pub device: String,
    pub workload: String,
    pub profile: String,
    pub proof_key_ref: String,
    pub revocation_epoch: u64,
    pub binding: ActionBindingV1,
    pub assurance: AssuranceLevel,
    pub issued_at: String,
    pub expires_at: String,
    pub use_limit: u8,
    pub policy_digest: String,
    pub signed: SignedDigestV1,
}

impl Validate for EnforcementGrantV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        schema(&self.schema, ENFORCEMENT_GRANT_SCHEMA_V1)?;
        identifier("grant_id", &self.grant_id)?;
        identifier("jti", &self.jti)?;
        identifier("decision_id", &self.decision_id)?;
        identifier("intent_jti", &self.intent_jti)?;
        identifier("identity_context_id", &self.identity_context_id)?;
        opaque("pairwise_subject", &self.pairwise_subject, 256)?;
        opaque("actor", &self.actor, 256)?;
        opaque("device", &self.device, 256)?;
        spiffe_workload("workload", &self.workload)?;
        opaque("profile", &self.profile, 256)?;
        opaque("proof_key_ref", &self.proof_key_ref, 256)?;
        self.binding.validate()?;
        if !self
            .assurance
            .meets(self.binding.action.required_assurance())
        {
            return Err(ValidationError::new(
                "assurance",
                "is weaker than the action requires",
            ));
        }
        if self.use_limit != 1 {
            return Err(ValidationError::new("use_limit", "must be exactly one"));
        }
        short_window(
            "issued_at",
            &self.issued_at,
            &self.expires_at,
            MAX_GRANT_TTL_MILLIS,
        )?;
        digest("policy_digest", &self.policy_digest)?;
        self.signed.validate()?;
        self.validate_payload_digest()
    }
}
