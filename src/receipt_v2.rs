use serde::{Deserialize, Serialize};

use crate::{
    ActionBindingV1, CanonicalPayloadV1, ENFORCEMENT_RECEIPT_SCHEMA_V2, EnforcementOutcome,
    SignedDigestV1,
    validation::{Validate, ValidationError, digest, identifier, opaque, schema, timestamp},
};

const MAX_RESIDUAL_EXPOSURES: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnforcementReceiptV2 {
    pub schema: String,
    pub receipt_id: String,
    pub command_jti: String,
    pub command_digest: String,
    pub security_domain: String,
    pub deployment_id: String,
    pub incident_id: String,
    pub target_id: String,
    pub release_reservation_id: String,
    pub fence_epoch: u64,
    pub binding: ActionBindingV1,
    pub provider: String,
    pub outcome: EnforcementOutcome,
    pub authorization_consumed: bool,
    pub applied_at: String,
    pub expected_resource_version: String,
    pub resulting_resource_version: Option<String>,
    pub residual_exposures: Vec<String>,
    pub evidence_digest: String,
    pub signed: SignedDigestV1,
}

impl Validate for EnforcementReceiptV2 {
    fn validate(&self) -> Result<(), ValidationError> {
        schema(&self.schema, ENFORCEMENT_RECEIPT_SCHEMA_V2)?;
        for (field, value) in [
            ("receipt_id", self.receipt_id.as_str()),
            ("command_jti", &self.command_jti),
            ("security_domain", &self.security_domain),
            ("deployment_id", &self.deployment_id),
            ("incident_id", &self.incident_id),
            ("release_reservation_id", &self.release_reservation_id),
            ("provider", &self.provider),
        ] {
            identifier(field, value)?;
        }
        digest("command_digest", &self.command_digest)?;
        opaque("target_id", &self.target_id, 256)?;
        opaque(
            "expected_resource_version",
            &self.expected_resource_version,
            256,
        )?;
        self.binding.validate()?;
        if self.fence_epoch == 0
            || self.target_id != self.binding.resource
            || self.provider != self.binding.audience
            || !self.authorization_consumed
        {
            return Err(ValidationError::new(
                "enforcement_binding",
                "authorization, target, provider, and fence must match",
            ));
        }
        timestamp("applied_at", &self.applied_at)?;
        self.validate_outcome()?;
        digest("evidence_digest", &self.evidence_digest)?;
        self.signed.validate()?;
        self.validate_payload_digest()
    }
}

impl EnforcementReceiptV2 {
    fn validate_outcome(&self) -> Result<(), ValidationError> {
        if self.residual_exposures.len() > MAX_RESIDUAL_EXPOSURES {
            return Err(ValidationError::new(
                "residual_exposures",
                "exceeds the item limit",
            ));
        }
        for exposure in &self.residual_exposures {
            opaque("residual_exposures", exposure, 256)?;
        }
        if let Some(version) = self.resulting_resource_version.as_deref() {
            opaque("resulting_resource_version", version, 256)?;
        }
        if self.outcome == EnforcementOutcome::Partial && self.residual_exposures.is_empty() {
            return Err(ValidationError::new(
                "residual_exposures",
                "partial outcomes require residual exposure",
            ));
        }
        if self.outcome == EnforcementOutcome::Applied {
            if self.resulting_resource_version.is_none() {
                return Err(ValidationError::new(
                    "resulting_resource_version",
                    "applied outcomes require a resulting version",
                ));
            }
            if !self.residual_exposures.is_empty() {
                return Err(ValidationError::new(
                    "residual_exposures",
                    "applied outcomes cannot retain exposure",
                ));
            }
        }
        Ok(())
    }
}
