use serde::{Deserialize, Serialize};

use crate::{
    ActionBindingV1, CanonicalPayloadV1, ControlAction, RECOVERY_AUTHORIZATION_SCHEMA_V1,
    SignedDigestV1,
    validation::{
        Validate, ValidationError, digest, identifier, opaque, schema, short_window, timestamp,
        valid_at,
    },
};

const MAX_RECOVERY_TTL_MILLIS: i64 = 60_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryAuthorizationV1 {
    pub schema: String,
    pub authorization_id: String,
    pub jti: String,
    pub identity_context_id: String,
    pub pairwise_subject: String,
    pub binding: ActionBindingV1,
    pub incident_id: String,
    pub policy_snapshot_id: String,
    pub policy_snapshot_digest: String,
    pub authoritative_revocation_epoch: u64,
    pub issued_at: String,
    pub expires_at: String,
    pub use_limit: u8,
    pub signed: SignedDigestV1,
}

impl Validate for RecoveryAuthorizationV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        schema(&self.schema, RECOVERY_AUTHORIZATION_SCHEMA_V1)?;
        identifier("authorization_id", &self.authorization_id)?;
        identifier("jti", &self.jti)?;
        identifier("identity_context_id", &self.identity_context_id)?;
        opaque("pairwise_subject", &self.pairwise_subject, 256)?;
        self.binding.validate()?;
        if self.binding.action != ControlAction::Restore {
            return Err(ValidationError::new(
                "binding.action",
                "recovery authorization is restore-only",
            ));
        }
        identifier("incident_id", &self.incident_id)?;
        identifier("policy_snapshot_id", &self.policy_snapshot_id)?;
        digest("policy_snapshot_digest", &self.policy_snapshot_digest)?;
        if self.use_limit != 1 {
            return Err(ValidationError::new("use_limit", "must be exactly one"));
        }
        short_window(
            "issued_at",
            &self.issued_at,
            &self.expires_at,
            MAX_RECOVERY_TTL_MILLIS,
        )?;
        self.signed.validate()?;
        self.validate_payload_digest()
    }
}

impl RecoveryAuthorizationV1 {
    /// Revalidates recovery authority using a trusted caller clock.
    ///
    /// # Errors
    ///
    /// Rejects malformed, not-yet-current, expired, or non-restore authority.
    pub fn validate_at(&self, now: &str) -> Result<(), ValidationError> {
        self.validate()?;
        timestamp("now", now)?;
        if valid_at(&self.issued_at, &self.expires_at, now) {
            Ok(())
        } else {
            Err(ValidationError::new(
                "now",
                "recovery authorization is not current",
            ))
        }
    }
}
