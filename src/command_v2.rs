use serde::{Deserialize, Serialize};

use crate::{
    ActionBindingV1, CanonicalPayloadV1, ISOLATION_COMMAND_SCHEMA_V2, SignedDigestV1,
    validation::{Validate, ValidationError, digest, identifier, opaque, schema, short_window},
    workload::spiffe_workload,
};

const MAX_COMMAND_TTL_MILLIS: i64 = 60_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IsolationCommandV2 {
    pub schema: String,
    pub command_id: String,
    pub jti: String,
    pub security_domain: String,
    pub deployment_id: String,
    pub incident_id: String,
    pub target_id: String,
    pub release_id: String,
    pub release_digest: String,
    pub checkpoint_id: String,
    pub checkpoint_digest: String,
    pub checkpoint_sequence: u64,
    pub release_reservation_id: String,
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
    pub previous_fence_epoch: u64,
    pub fence_epoch: u64,
    pub expected_resource_version: String,
    pub issued_at: String,
    pub expires_at: String,
    pub signed: SignedDigestV1,
}

impl Validate for IsolationCommandV2 {
    fn validate(&self) -> Result<(), ValidationError> {
        schema(&self.schema, ISOLATION_COMMAND_SCHEMA_V2)?;
        for (field, value) in [
            ("command_id", self.command_id.as_str()),
            ("jti", &self.jti),
            ("security_domain", &self.security_domain),
            ("deployment_id", &self.deployment_id),
            ("incident_id", &self.incident_id),
            ("release_id", &self.release_id),
            ("checkpoint_id", &self.checkpoint_id),
            ("release_reservation_id", &self.release_reservation_id),
            ("enforcement_grant_jti", &self.enforcement_grant_jti),
            ("decision_id", &self.decision_id),
            ("provider", &self.provider),
        ] {
            identifier(field, value)?;
        }
        for (field, value) in [
            ("target_id", self.target_id.as_str()),
            ("pairwise_subject", &self.pairwise_subject),
            ("actor", &self.actor),
            ("device", &self.device),
            ("profile", &self.profile),
            ("proof_key_ref", &self.proof_key_ref),
            ("expected_resource_version", &self.expected_resource_version),
        ] {
            opaque(field, value, 256)?;
        }
        spiffe_workload("workload", &self.workload)?;
        digest("release_digest", &self.release_digest)?;
        digest("checkpoint_digest", &self.checkpoint_digest)?;
        self.binding.validate()?;
        self.validate_cas()?;
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

impl IsolationCommandV2 {
    fn validate_cas(&self) -> Result<(), ValidationError> {
        let exact = self.target_id == self.binding.resource
            && self.provider == self.binding.audience
            && self.checkpoint_sequence > 0
            && self.fence_epoch > 0
            && self.previous_fence_epoch.checked_add(1) == Some(self.fence_epoch);
        if exact {
            Ok(())
        } else {
            Err(ValidationError::new(
                "cas_binding",
                "target, provider, checkpoint, and fence must match exactly",
            ))
        }
    }
}
