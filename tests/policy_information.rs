mod support;

use crowsi_control_contracts::{CanonicalPayloadV1, ControlAction, Validate};

use support::policy_information_fixture;

#[test]
fn signed_policy_information_and_recovery_are_current_and_closed() {
    let (snapshot, recovery) = policy_information_fixture();
    assert!(snapshot.validate_at("2026-08-01T00:02:00.000Z").is_ok());
    assert!(recovery.validate_at("2026-08-01T00:02:00.000Z").is_ok());
    assert!(snapshot.payload_digest_matches());
    assert!(recovery.payload_digest_matches());
}

#[test]
fn stale_snapshot_and_recovery_fail_against_trusted_time() {
    let (snapshot, recovery) = policy_information_fixture();
    assert!(snapshot.validate_at("2026-08-01T00:02:30.000Z").is_err());
    assert!(recovery.validate_at("2026-08-01T00:02:30.000Z").is_err());
}

#[test]
fn posture_or_epoch_substitution_breaks_the_canonical_digest() {
    let (mut snapshot, _) = policy_information_fixture();
    snapshot.device_posture.target = "attacker-device".to_owned();
    assert!(!snapshot.payload_digest_matches());
    assert!(snapshot.validate().is_err());
    let (mut snapshot, _) = policy_information_fixture();
    snapshot.authoritative_revocation_epoch += 1;
    assert!(!snapshot.payload_digest_matches());
    assert!(snapshot.validate().is_err());
}

#[test]
fn recovery_authorization_is_restore_only_and_one_use() {
    let (_, mut recovery) = policy_information_fixture();
    recovery.binding.action = ControlAction::Quarantine;
    recovery.signed.digest = recovery.payload_digest();
    assert!(recovery.validate().is_err());
    let (_, mut recovery) = policy_information_fixture();
    recovery.use_limit = 2;
    recovery.signed.digest = recovery.payload_digest();
    assert!(recovery.validate().is_err());
}

#[test]
fn snapshot_rejects_internally_conflicting_authority() {
    let (mut snapshot, _) = policy_information_fixture();
    snapshot.management_authority.revocation_epoch += 1;
    snapshot.signed.digest = snapshot.payload_digest();
    assert!(snapshot.validate().is_err());
}
