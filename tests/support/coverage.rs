use crowsi_control_contracts::{
    ActionCoverageV1, COVERAGE_ASSERTION_SCHEMA_V1, CanonicalPayloadV1, CapabilityStatus,
    CoverageAssertionV1, CoverageLevel, EnforcementReadiness, Freshness, Health, Management,
    ManagementLifeline, Verification,
};

use super::common::{digest, signed};

pub fn coverage_fixture() -> CoverageAssertionV1 {
    let mut value = CoverageAssertionV1 {
        schema: COVERAGE_ASSERTION_SCHEMA_V1.to_owned(),
        assertion_id: "coverage.1".to_owned(),
        resource: "incus://project/default/instance/worker-a".to_owned(),
        observer_id: "crowsi-sensor-incus".to_owned(),
        coverage: CoverageLevel::Complete,
        freshness: Freshness::Fresh,
        management: Management::Managed,
        verification: Verification::Verified,
        health: Health::Healthy,
        management_lifeline: ManagementLifeline::Verified,
        enforcement_readiness: EnforcementReadiness::Ready,
        action_coverage: ActionCoverageV1 {
            quarantine: CapabilityStatus::Ready,
            revoke: CapabilityStatus::Ready,
            verify: CapabilityStatus::Ready,
            restore: CapabilityStatus::Ready,
        },
        observed_at: "2026-08-01T00:00:00.000Z".to_owned(),
        valid_until: "2026-08-01T00:05:00.000Z".to_owned(),
        evidence_digest: digest(),
        signed: signed(),
    };
    value.signed.digest = value.payload_digest();
    value
}
