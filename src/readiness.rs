use serde::{Deserialize, Serialize};

use crate::{
    CoverageAssertionV1, CoverageLevel, Freshness, Management, ValidationError, Verification,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ManagementLifeline {
    Verified,
    Unverified,
    Absent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EnforcementReadiness {
    Ready,
    Degraded,
    Unavailable,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CapabilityStatus {
    Ready,
    Unavailable,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionCoverageV1 {
    pub quarantine: CapabilityStatus,
    pub revoke: CapabilityStatus,
    pub verify: CapabilityStatus,
    pub restore: CapabilityStatus,
}

impl ActionCoverageV1 {
    #[must_use]
    pub fn all_ready(&self) -> bool {
        self.quarantine == CapabilityStatus::Ready
            && self.revoke == CapabilityStatus::Ready
            && self.verify == CapabilityStatus::Ready
            && self.restore == CapabilityStatus::Ready
    }
}

impl CoverageAssertionV1 {
    /// Checks whether emergency isolation can preserve a verified management path.
    ///
    /// # Errors
    ///
    /// Rejects incomplete evidence, an unsafe lifeline, or any missing required
    /// quarantine, revoke, independent verification, or restore capability.
    pub fn validate_isolation_ready_at(&self, now: &str) -> Result<(), ValidationError> {
        self.validate_at(now)?;
        let trustworthy = self.coverage == CoverageLevel::Complete
            && self.freshness == Freshness::Fresh
            && self.management == Management::Managed
            && self.verification == Verification::Verified;
        if !trustworthy {
            return Err(ValidationError::new(
                "coverage",
                "isolation requires complete verified evidence",
            ));
        }
        if self.management_lifeline != ManagementLifeline::Verified {
            return Err(ValidationError::new(
                "management_lifeline",
                "a verified recovery path is required",
            ));
        }
        if self.enforcement_readiness != EnforcementReadiness::Ready {
            return Err(ValidationError::new(
                "enforcement_readiness",
                "enforcer is not ready",
            ));
        }
        if !self.action_coverage.all_ready() {
            return Err(ValidationError::new(
                "action_coverage",
                "quarantine, revoke, verify, and restore must be ready",
            ));
        }
        Ok(())
    }
}
