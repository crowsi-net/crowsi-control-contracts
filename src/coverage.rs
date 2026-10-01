use serde::{Deserialize, Serialize};

use crate::{
    ActionCoverageV1, COVERAGE_ASSERTION_SCHEMA_V1, CanonicalPayloadV1, EnforcementReadiness,
    ManagementLifeline, SignedDigestV1,
    time::unix_millis,
    validation::{
        Validate, ValidationError, digest, identifier, opaque, schema, short_window, timestamp,
    },
};

const MAX_COVERAGE_TTL_MILLIS: i64 = 300_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CoverageLevel {
    Complete,
    Partial,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Freshness {
    Fresh,
    Stale,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Management {
    Managed,
    Unmanaged,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Verification {
    Verified,
    Unverified,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Health {
    Healthy,
    Degraded,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageAssertionV1 {
    pub schema: String,
    pub assertion_id: String,
    pub resource: String,
    pub observer_id: String,
    pub coverage: CoverageLevel,
    pub freshness: Freshness,
    pub management: Management,
    pub verification: Verification,
    pub health: Health,
    pub management_lifeline: ManagementLifeline,
    pub enforcement_readiness: EnforcementReadiness,
    pub action_coverage: ActionCoverageV1,
    pub observed_at: String,
    pub valid_until: String,
    pub evidence_digest: String,
    pub signed: SignedDigestV1,
}

impl Validate for CoverageAssertionV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        schema(&self.schema, COVERAGE_ASSERTION_SCHEMA_V1)?;
        identifier("assertion_id", &self.assertion_id)?;
        opaque("resource", &self.resource, 256)?;
        identifier("observer_id", &self.observer_id)?;
        short_window(
            "observed_at",
            &self.observed_at,
            &self.valid_until,
            MAX_COVERAGE_TTL_MILLIS,
        )?;
        self.validate_state()?;
        digest("evidence_digest", &self.evidence_digest)?;
        self.signed.validate()?;
        self.validate_payload_digest()
    }
}

impl CoverageAssertionV1 {
    /// Revalidates freshness using a caller-supplied trusted time.
    ///
    /// # Errors
    ///
    /// Rejects an expired assertion that still claims verified or healthy.
    pub fn validate_at(&self, now: &str) -> Result<(), ValidationError> {
        self.validate()?;
        timestamp("now", now)?;
        let expired = unix_millis(now)
            .zip(unix_millis(&self.valid_until))
            .is_none_or(|(now, valid_until)| now >= valid_until);
        if expired
            && (self.verification == Verification::Verified || self.health == Health::Healthy)
        {
            return Err(ValidationError::new(
                "valid_until",
                "expired evidence cannot be verified or healthy",
            ));
        }
        Ok(())
    }

    fn validate_state(&self) -> Result<(), ValidationError> {
        let insufficient = self.coverage != CoverageLevel::Complete
            || self.freshness == Freshness::Stale
            || self.management == Management::Unmanaged;
        if insufficient && self.verification == Verification::Verified {
            return Err(ValidationError::new(
                "verification",
                "insufficient evidence cannot be verified",
            ));
        }
        if (insufficient || self.verification != Verification::Verified)
            && self.health == Health::Healthy
        {
            return Err(ValidationError::new(
                "health",
                "insufficient evidence cannot be healthy",
            ));
        }
        Ok(())
    }
}
