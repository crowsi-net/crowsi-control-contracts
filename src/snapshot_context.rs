use serde::{Deserialize, Serialize};

use crate::{
    ActionBindingV1,
    validation::{Validate, ValidationError, identifier, opaque, short_window},
};

const MAX_CONTEXT_TTL_MILLIS: i64 = 300_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PolicyPostureState {
    Trusted,
    Untrusted,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PolicyIncidentState {
    Normal,
    Detected,
    ContainmentRequested,
    Contained,
    RecoveryPending,
    RecoveryAuthorized,
    Restoring,
    Monitoring,
    Closed,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PolicyAuthorityState {
    Authorized,
    Denied,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PostureAssertionV1 {
    pub target: String,
    pub state: PolicyPostureState,
    pub observed_at: String,
    pub valid_until: String,
}

impl Validate for PostureAssertionV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        opaque("posture.target", &self.target, 256)?;
        short_window(
            "posture.observed_at",
            &self.observed_at,
            &self.valid_until,
            MAX_CONTEXT_TTL_MILLIS,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IncidentAssertionV1 {
    pub incident_id: String,
    pub resource: String,
    pub state: PolicyIncidentState,
    pub observed_at: String,
    pub valid_until: String,
}

impl Validate for IncidentAssertionV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        identifier("incident.incident_id", &self.incident_id)?;
        opaque("incident.resource", &self.resource, 256)?;
        short_window(
            "incident.observed_at",
            &self.observed_at,
            &self.valid_until,
            MAX_CONTEXT_TTL_MILLIS,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagementAuthorityAssertionV1 {
    pub state: PolicyAuthorityState,
    pub identity_context_id: String,
    pub authorization_grant_id: String,
    pub revocation_epoch: u64,
    pub binding: ActionBindingV1,
    pub observed_at: String,
    pub valid_until: String,
}

impl Validate for ManagementAuthorityAssertionV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        identifier(
            "management_authority.identity_context_id",
            &self.identity_context_id,
        )?;
        opaque(
            "management_authority.authorization_grant_id",
            &self.authorization_grant_id,
            256,
        )?;
        self.binding.validate()?;
        short_window(
            "management_authority.observed_at",
            &self.observed_at,
            &self.valid_until,
            MAX_CONTEXT_TTL_MILLIS,
        )
    }
}
