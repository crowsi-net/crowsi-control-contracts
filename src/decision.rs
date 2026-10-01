use serde::{Deserialize, Serialize};

use crate::{
    ActionBindingV1, AssuranceLevel, CanonicalPayloadV1, POLICY_DECISION_SCHEMA_V1, SignedDigestV1,
    validation::{Validate, ValidationError, digest, identifier, opaque, schema, short_window},
    workload::spiffe_workload,
};

const MAX_DECISION_TTL_MILLIS: i64 = 300_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DecisionEffect {
    Permit,
    Deny,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyDecisionV1 {
    pub schema: String,
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
    pub effect: DecisionEffect,
    pub binding: ActionBindingV1,
    pub required_assurance: AssuranceLevel,
    pub issued_at: String,
    pub expires_at: String,
    pub policy_digest: String,
    pub signed: SignedDigestV1,
}

impl Validate for PolicyDecisionV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        schema(&self.schema, POLICY_DECISION_SCHEMA_V1)?;
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
            .required_assurance
            .meets(self.binding.action.required_assurance())
        {
            return Err(ValidationError::new(
                "required_assurance",
                "is weaker than the action requires",
            ));
        }
        short_window(
            "issued_at",
            &self.issued_at,
            &self.expires_at,
            MAX_DECISION_TTL_MILLIS,
        )?;
        digest("policy_digest", &self.policy_digest)?;
        self.signed.validate()?;
        self.validate_payload_digest()
    }
}
