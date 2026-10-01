use serde::{Deserialize, Serialize};

use crate::{
    ActionBindingV1, CanonicalPayloadV1, ENFORCEMENT_RECEIPT_SCHEMA_V1, SignedDigestV1,
    validation::{Validate, ValidationError, digest, identifier, opaque, schema, timestamp},
};

const MAX_RESIDUAL_EXPOSURES: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EnforcementOutcome {
    Applied,
    Rejected,
    Failed,
    Partial,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnforcementReceiptV1 {
    pub schema: String,
    pub receipt_id: String,
    pub command_jti: String,
    pub enforcement_grant_jti: String,
    pub binding: ActionBindingV1,
    pub provider: String,
    pub outcome: EnforcementOutcome,
    pub grant_consumed: bool,
    pub applied_at: String,
    pub resulting_resource_version: Option<String>,
    pub residual_exposures: Vec<String>,
    pub evidence_digest: String,
    pub signed: SignedDigestV1,
}

impl Validate for EnforcementReceiptV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        schema(&self.schema, ENFORCEMENT_RECEIPT_SCHEMA_V1)?;
        identifier("receipt_id", &self.receipt_id)?;
        identifier("command_jti", &self.command_jti)?;
        identifier("enforcement_grant_jti", &self.enforcement_grant_jti)?;
        self.binding.validate()?;
        identifier("provider", &self.provider)?;
        if self.provider != self.binding.audience {
            return Err(ValidationError::new(
                "provider",
                "must equal the bound audience",
            ));
        }
        if !self.grant_consumed {
            return Err(ValidationError::new(
                "grant_consumed",
                "must be true before execution",
            ));
        }
        timestamp("applied_at", &self.applied_at)?;
        self.validate_outcome()?;
        digest("evidence_digest", &self.evidence_digest)?;
        self.signed.validate()?;
        self.validate_payload_digest()
    }
}

impl EnforcementReceiptV1 {
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
        if self.outcome == EnforcementOutcome::Partial && self.residual_exposures.is_empty() {
            return Err(ValidationError::new(
                "residual_exposures",
                "partial outcomes require residual exposure",
            ));
        }
        if self.outcome == EnforcementOutcome::Applied {
            let version = self
                .resulting_resource_version
                .as_deref()
                .unwrap_or_default();
            opaque("resulting_resource_version", version, 256)?;
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
