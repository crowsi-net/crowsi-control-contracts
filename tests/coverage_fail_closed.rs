mod support;

use crowsi_control_contracts::{
    CanonicalPayloadV1, CapabilityStatus, CoverageLevel, EnforcementReadiness, Freshness, Health,
    Management, ManagementLifeline, Validate, Verification,
};

use support::coverage_fixture;

const NOW: &str = "2026-08-01T00:02:00.000Z";

#[test]
fn partial_unknown_stale_and_unmanaged_cannot_be_verified_or_healthy() {
    let mut partial = coverage_fixture();
    partial.coverage = CoverageLevel::Partial;
    partial.signed.digest = partial.payload_digest();
    assert!(partial.validate().is_err());
    let mut unknown = coverage_fixture();
    unknown.coverage = CoverageLevel::Unknown;
    unknown.signed.digest = unknown.payload_digest();
    assert!(unknown.validate().is_err());
    let mut stale = coverage_fixture();
    stale.freshness = Freshness::Stale;
    stale.signed.digest = stale.payload_digest();
    assert!(stale.validate().is_err());
    let mut unmanaged = coverage_fixture();
    unmanaged.management = Management::Unmanaged;
    unmanaged.signed.digest = unmanaged.payload_digest();
    assert!(unmanaged.validate().is_err());
    let mut unverified = coverage_fixture();
    unverified.verification = Verification::Unverified;
    unverified.signed.digest = unverified.payload_digest();
    assert_eq!(unverified.health, Health::Healthy);
    assert!(unverified.validate().is_err());
}

#[test]
fn trusted_time_prevents_expired_evidence_from_remaining_verified() {
    let coverage = coverage_fixture();
    assert!(coverage.validate_at(NOW).is_ok());
    assert!(coverage.validate_at("2026-08-01T00:05:00.000Z").is_err());
}

#[test]
fn isolation_requires_verified_lifeline_and_ready_enforcer() {
    let coverage = coverage_fixture();
    assert!(coverage.validate_isolation_ready_at(NOW).is_ok());
    let mut lifeline = coverage.clone();
    lifeline.management_lifeline = ManagementLifeline::Unverified;
    lifeline.signed.digest = lifeline.payload_digest();
    assert!(lifeline.validate_isolation_ready_at(NOW).is_err());
    lifeline.management_lifeline = ManagementLifeline::Absent;
    lifeline.signed.digest = lifeline.payload_digest();
    assert!(lifeline.validate_isolation_ready_at(NOW).is_err());
    let mut enforcer = coverage;
    enforcer.enforcement_readiness = EnforcementReadiness::Degraded;
    enforcer.signed.digest = enforcer.payload_digest();
    assert!(enforcer.validate_isolation_ready_at(NOW).is_err());
}

#[test]
fn every_containment_and_recovery_capability_is_required() {
    let base = coverage_fixture();
    let mut quarantine = base.clone();
    quarantine.action_coverage.quarantine = CapabilityStatus::Unavailable;
    quarantine.signed.digest = quarantine.payload_digest();
    assert!(quarantine.validate_isolation_ready_at(NOW).is_err());
    let mut revoke = base.clone();
    revoke.action_coverage.revoke = CapabilityStatus::Unknown;
    revoke.signed.digest = revoke.payload_digest();
    assert!(revoke.validate_isolation_ready_at(NOW).is_err());
    let mut verify = base.clone();
    verify.action_coverage.verify = CapabilityStatus::Unavailable;
    verify.signed.digest = verify.payload_digest();
    assert!(verify.validate_isolation_ready_at(NOW).is_err());
    let mut restore = base;
    restore.action_coverage.restore = CapabilityStatus::Unknown;
    restore.signed.digest = restore.payload_digest();
    assert!(restore.validate_isolation_ready_at(NOW).is_err());
}
