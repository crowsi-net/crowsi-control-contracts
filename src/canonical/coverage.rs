use crate::{
    CapabilityStatus, CoverageAssertionV1, CoverageLevel, EnforcementReadiness, Freshness, Health,
    Management, ManagementLifeline, Verification,
};

use super::{CanonicalPayloadV1, Encoder, claimed};

impl CanonicalPayloadV1 for CoverageAssertionV1 {
    fn signing_payload(&self) -> Vec<u8> {
        let mut value = Encoder::new("coverage-assertion-v1");
        value.text("schema", &self.schema);
        value.text("assertion_id", &self.assertion_id);
        value.text("resource", &self.resource);
        value.text("observer_id", &self.observer_id);
        value.text("coverage", coverage(self.coverage));
        value.text("freshness", freshness(self.freshness));
        value.text("management", management(self.management));
        value.text("verification", verification(self.verification));
        value.text("health", health(self.health));
        value.text("management_lifeline", lifeline(self.management_lifeline));
        value.text(
            "enforcement_readiness",
            readiness(self.enforcement_readiness),
        );
        value.text(
            "action_coverage.quarantine",
            capability(self.action_coverage.quarantine),
        );
        value.text(
            "action_coverage.revoke",
            capability(self.action_coverage.revoke),
        );
        value.text(
            "action_coverage.verify",
            capability(self.action_coverage.verify),
        );
        value.text(
            "action_coverage.restore",
            capability(self.action_coverage.restore),
        );
        value.text("observed_at", &self.observed_at);
        value.text("valid_until", &self.valid_until);
        value.text("evidence_digest", &self.evidence_digest);
        value.finish()
    }

    fn claimed_payload_digest(&self) -> &str {
        claimed(&self.signed)
    }
}

const fn coverage(value: CoverageLevel) -> &'static str {
    match value {
        CoverageLevel::Complete => "complete",
        CoverageLevel::Partial => "partial",
        CoverageLevel::Unknown => "unknown",
    }
}

const fn freshness(value: Freshness) -> &'static str {
    match value {
        Freshness::Fresh => "fresh",
        Freshness::Stale => "stale",
    }
}

const fn management(value: Management) -> &'static str {
    match value {
        Management::Managed => "managed",
        Management::Unmanaged => "unmanaged",
    }
}

const fn verification(value: Verification) -> &'static str {
    match value {
        Verification::Verified => "verified",
        Verification::Unverified => "unverified",
    }
}

const fn health(value: Health) -> &'static str {
    match value {
        Health::Healthy => "healthy",
        Health::Degraded => "degraded",
        Health::Unknown => "unknown",
    }
}

const fn lifeline(value: ManagementLifeline) -> &'static str {
    match value {
        ManagementLifeline::Verified => "verified",
        ManagementLifeline::Unverified => "unverified",
        ManagementLifeline::Absent => "absent",
    }
}

const fn readiness(value: EnforcementReadiness) -> &'static str {
    match value {
        EnforcementReadiness::Ready => "ready",
        EnforcementReadiness::Degraded => "degraded",
        EnforcementReadiness::Unavailable => "unavailable",
        EnforcementReadiness::Unknown => "unknown",
    }
}

const fn capability(value: CapabilityStatus) -> &'static str {
    match value {
        CapabilityStatus::Ready => "ready",
        CapabilityStatus::Unavailable => "unavailable",
        CapabilityStatus::Unknown => "unknown",
    }
}
