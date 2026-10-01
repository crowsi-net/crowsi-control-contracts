use serde::{Deserialize, Serialize};

use crate::{
    CanonicalPayloadV1, IncidentAssertionV1, ManagementAuthorityAssertionV1,
    POLICY_INFORMATION_SNAPSHOT_SCHEMA_V1, PostureAssertionV1, SignedDigestV1,
    time::unix_millis,
    validation::{
        Validate, ValidationError, digest, identifier, opaque, schema, short_window, timestamp,
        valid_at,
    },
};

const MAX_SNAPSHOT_TTL_MILLIS: i64 = 60_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyInformationSnapshotV1 {
    pub schema: String,
    pub snapshot_id: String,
    pub identity_context_id: String,
    pub pairwise_subject: String,
    pub device_posture: PostureAssertionV1,
    pub workload_posture: PostureAssertionV1,
    pub incident: IncidentAssertionV1,
    pub management_authority: ManagementAuthorityAssertionV1,
    pub authoritative_revocation_epoch: u64,
    pub risk_score: u8,
    pub coverage_assertion_id: String,
    pub coverage_digest: String,
    pub policy_digest: String,
    pub issued_at: String,
    pub expires_at: String,
    pub signed: SignedDigestV1,
}

impl Validate for PolicyInformationSnapshotV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        schema(&self.schema, POLICY_INFORMATION_SNAPSHOT_SCHEMA_V1)?;
        identifier("snapshot_id", &self.snapshot_id)?;
        identifier("identity_context_id", &self.identity_context_id)?;
        opaque("pairwise_subject", &self.pairwise_subject, 256)?;
        self.device_posture.validate()?;
        self.workload_posture.validate()?;
        self.incident.validate()?;
        self.management_authority.validate()?;
        if self.risk_score > 100 {
            return Err(ValidationError::new("risk_score", "must be at most 100"));
        }
        identifier("coverage_assertion_id", &self.coverage_assertion_id)?;
        digest("coverage_digest", &self.coverage_digest)?;
        digest("policy_digest", &self.policy_digest)?;
        short_window(
            "issued_at",
            &self.issued_at,
            &self.expires_at,
            MAX_SNAPSHOT_TTL_MILLIS,
        )?;
        self.validate_links()?;
        self.signed.validate()?;
        self.validate_payload_digest()
    }
}

impl PolicyInformationSnapshotV1 {
    /// Revalidates this signed snapshot against a trusted caller clock.
    ///
    /// # Errors
    ///
    /// Rejects a malformed, not-yet-current, or expired snapshot.
    pub fn validate_at(&self, now: &str) -> Result<(), ValidationError> {
        self.validate()?;
        timestamp("now", now)?;
        if valid_at(&self.issued_at, &self.expires_at, now) {
            Ok(())
        } else {
            Err(ValidationError::new("now", "snapshot is not current"))
        }
    }

    fn validate_links(&self) -> Result<(), ValidationError> {
        let authority = &self.management_authority;
        let exact = self.identity_context_id == authority.identity_context_id
            && self.authoritative_revocation_epoch == authority.revocation_epoch
            && self.incident.resource == authority.binding.resource;
        let windows = [
            (
                &self.device_posture.observed_at,
                &self.device_posture.valid_until,
            ),
            (
                &self.workload_posture.observed_at,
                &self.workload_posture.valid_until,
            ),
            (&self.incident.observed_at, &self.incident.valid_until),
            (&authority.observed_at, &authority.valid_until),
        ];
        if exact
            && windows
                .into_iter()
                .all(|(start, end)| contains(start, end, &self.issued_at, &self.expires_at))
        {
            Ok(())
        } else {
            Err(ValidationError::new(
                "snapshot",
                "context links and validity must match exactly",
            ))
        }
    }
}

fn contains(parent_start: &str, parent_end: &str, child_start: &str, child_end: &str) -> bool {
    unix_millis(parent_start)
        .zip(unix_millis(parent_end))
        .zip(unix_millis(child_start))
        .zip(unix_millis(child_end))
        .is_some_and(|(((start, end), issued), expires)| start <= issued && expires <= end)
}
