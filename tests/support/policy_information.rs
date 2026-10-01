use crowsi_control_contracts::{
    AssuranceLevel, CanonicalPayloadV1, ControlAction, IncidentAssertionV1,
    ManagementAuthorityAssertionV1, POLICY_INFORMATION_SNAPSHOT_SCHEMA_V1, PolicyAuthorityState,
    PolicyIncidentState, PolicyInformationSnapshotV1, PolicyPostureState, PostureAssertionV1,
    RECOVERY_AUTHORIZATION_SCHEMA_V1, RecoveryAuthorizationV1,
};

use super::{
    authorization_fixture,
    common::{digest, signed},
    coverage_fixture,
};

pub fn policy_information_fixture() -> (PolicyInformationSnapshotV1, RecoveryAuthorizationV1) {
    let chain = authorization_fixture(ControlAction::Restore, AssuranceLevel::HardwareBoundStepUp);
    let coverage = coverage_fixture();
    let window = |target: &str| PostureAssertionV1 {
        target: target.to_owned(),
        state: PolicyPostureState::Trusted,
        observed_at: "2026-08-01T00:01:00.000Z".to_owned(),
        valid_until: "2026-08-01T00:05:00.000Z".to_owned(),
    };
    let mut snapshot = PolicyInformationSnapshotV1 {
        schema: POLICY_INFORMATION_SNAPSHOT_SCHEMA_V1.to_owned(),
        snapshot_id: "snapshot.1".to_owned(),
        identity_context_id: chain.identity.context_id.clone(),
        pairwise_subject: chain.identity.pairwise_subject.clone(),
        device_posture: window(&chain.identity.device),
        workload_posture: window(&chain.identity.workload),
        incident: IncidentAssertionV1 {
            incident_id: "incident.1".to_owned(),
            resource: chain.intent.binding.resource.clone(),
            state: PolicyIncidentState::RecoveryAuthorized,
            observed_at: "2026-08-01T00:01:00.000Z".to_owned(),
            valid_until: "2026-08-01T00:05:00.000Z".to_owned(),
        },
        management_authority: ManagementAuthorityAssertionV1 {
            state: PolicyAuthorityState::Authorized,
            identity_context_id: chain.identity.context_id.clone(),
            authorization_grant_id: chain.identity.authorization_grant_id.clone(),
            revocation_epoch: chain.identity.revocation_epoch,
            binding: chain.intent.binding.clone(),
            observed_at: "2026-08-01T00:01:00.000Z".to_owned(),
            valid_until: "2026-08-01T00:05:00.000Z".to_owned(),
        },
        authoritative_revocation_epoch: chain.identity.revocation_epoch,
        risk_score: 10,
        coverage_assertion_id: coverage.assertion_id.clone(),
        coverage_digest: coverage.payload_digest(),
        policy_digest: digest(),
        issued_at: "2026-08-01T00:01:30.000Z".to_owned(),
        expires_at: "2026-08-01T00:02:30.000Z".to_owned(),
        signed: signed(),
    };
    snapshot.signed.digest = snapshot.payload_digest();
    let mut recovery = RecoveryAuthorizationV1 {
        schema: RECOVERY_AUTHORIZATION_SCHEMA_V1.to_owned(),
        authorization_id: "recovery.1".to_owned(),
        jti: "jti.recovery.1".to_owned(),
        identity_context_id: chain.identity.context_id,
        pairwise_subject: chain.identity.pairwise_subject,
        binding: chain.intent.binding,
        incident_id: snapshot.incident.incident_id.clone(),
        policy_snapshot_id: snapshot.snapshot_id.clone(),
        policy_snapshot_digest: snapshot.payload_digest(),
        authoritative_revocation_epoch: snapshot.authoritative_revocation_epoch,
        issued_at: "2026-08-01T00:01:30.000Z".to_owned(),
        expires_at: "2026-08-01T00:02:30.000Z".to_owned(),
        use_limit: 1,
        signed: signed(),
    };
    recovery.signed.digest = recovery.payload_digest();
    (snapshot, recovery)
}
