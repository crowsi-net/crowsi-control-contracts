use serde::{Deserialize, Serialize};

use crate::{
    ActionBindingV1, CanonicalPayloadV1, ISOLATION_COMMAND_SCHEMA_V1, SignedDigestV1,
    validation::{Validate, ValidationError, identifier, opaque, schema, short_window},
    workload::spiffe_workload,
};

const MAX_COMMAND_TTL_MILLIS: i64 = 60_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IsolationCommandV1 {
    pub schema: String,
    pub command_id: String,
    pub jti: String,
    pub enforcement_grant_jti: String,
    pub decision_id: String,
    pub pairwise_subject: String,
    pub actor: String,
    pub device: String,
    pub workload: String,
    pub profile: String,
    pub proof_key_ref: String,
    pub revocation_epoch: u64,
    pub binding: ActionBindingV1,
    pub provider: String,
    pub expected_resource_version: String,
    pub issued_at: String,
    pub expires_at: String,
    pub signed: SignedDigestV1,
}

impl Validate for IsolationCommandV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        schema(&self.schema, ISOLATION_COMMAND_SCHEMA_V1)?;
        identifier("command_id", &self.command_id)?;
        identifier("jti", &self.jti)?;
        identifier("enforcement_grant_jti", &self.enforcement_grant_jti)?;
        identifier("decision_id", &self.decision_id)?;
        opaque("pairwise_subject", &self.pairwise_subject, 256)?;
        opaque("actor", &self.actor, 256)?;
        opaque("device", &self.device, 256)?;
        spiffe_workload("workload", &self.workload)?;
        opaque("profile", &self.profile, 256)?;
        opaque("proof_key_ref", &self.proof_key_ref, 256)?;
        self.binding.validate()?;
        identifier("provider", &self.provider)?;
        if self.provider != self.binding.audience {
            return Err(ValidationError::new(
                "provider",
                "must equal the bound audience",
            ));
        }
        opaque(
            "expected_resource_version",
            &self.expected_resource_version,
            256,
        )?;
        short_window(
            "issued_at",
            &self.issued_at,
            &self.expires_at,
            MAX_COMMAND_TTL_MILLIS,
        )?;
        self.signed.validate()?;
        self.validate_payload_digest()
    }
}
