mod support;

use crowsi_control_contracts::{AssuranceLevel, CanonicalPayloadV1, ControlAction, Validate};

use support::{authorization_fixture, coverage_fixture, receipt_fixture};

#[test]
fn every_fixture_digest_covers_its_current_fields() {
    let chain = authorization_fixture(ControlAction::Quarantine, AssuranceLevel::PhishingResistant);
    assert!(chain.identity.payload_digest_matches());
    assert!(chain.intent.payload_digest_matches());
    assert!(chain.decision.payload_digest_matches());
    assert!(chain.grant.payload_digest_matches());
    assert!(chain.command.payload_digest_matches());
    assert!(coverage_fixture().payload_digest_matches());
    assert!(receipt_fixture().payload_digest_matches());
}

#[test]
fn changing_any_covered_field_invalidates_the_claimed_digest() {
    let chain = authorization_fixture(ControlAction::Quarantine, AssuranceLevel::PhishingResistant);
    let mut command = chain.command;
    let original_payload = command.signing_payload();
    let original_digest = command.signed.digest.clone();
    command.binding.purpose = "credential-recovery".to_owned();
    assert_ne!(command.signing_payload(), original_payload);
    assert_ne!(command.payload_digest(), original_digest);
    assert!(!command.payload_digest_matches());
    assert!(command.validate().is_err());
}

#[test]
fn signed_envelope_is_excluded_to_avoid_self_reference() {
    let chain = authorization_fixture(ControlAction::Quarantine, AssuranceLevel::PhishingResistant);
    let mut command = chain.command;
    let payload = command.signing_payload();
    command.signed.signature = "b".repeat(86);
    assert_eq!(command.signing_payload(), payload);
    assert!(command.payload_digest_matches());
}
