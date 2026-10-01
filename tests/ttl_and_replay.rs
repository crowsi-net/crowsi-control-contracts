mod support;

use crowsi_control_contracts::{
    AssuranceLevel, CanonicalPayloadV1, ControlAction, Validate, validate_authorization_chain,
};

use support::authorization_fixture;

const NOW: &str = "2026-08-01T00:01:45.000Z";

#[test]
fn intent_grant_and_command_enforce_short_ttl() {
    let mut intent =
        authorization_fixture(ControlAction::Quarantine, AssuranceLevel::PhishingResistant);
    intent.intent.expires_at = "2026-08-01T00:06:00.001Z".to_owned();
    intent.intent.signed.digest = intent.intent.payload_digest();
    assert!(intent.intent.validate().is_err());
    let mut grant =
        authorization_fixture(ControlAction::Quarantine, AssuranceLevel::PhishingResistant);
    grant.grant.expires_at = "2026-08-01T00:03:20.001Z".to_owned();
    grant.grant.signed.digest = grant.grant.payload_digest();
    assert!(grant.grant.validate().is_err());
    let mut command =
        authorization_fixture(ControlAction::Quarantine, AssuranceLevel::PhishingResistant);
    command.command.expires_at = "2026-08-01T00:02:30.001Z".to_owned();
    command.command.signed.digest = command.command.payload_digest();
    assert!(command.command.validate().is_err());
}

#[test]
fn grant_is_structurally_one_use_and_jtis_are_distinct() {
    let mut limit =
        authorization_fixture(ControlAction::Quarantine, AssuranceLevel::PhishingResistant);
    limit.grant.use_limit = 2;
    limit.grant.signed.digest = limit.grant.payload_digest();
    assert!(limit.grant.validate().is_err());
    let mut duplicate =
        authorization_fixture(ControlAction::Quarantine, AssuranceLevel::PhishingResistant);
    duplicate.command.jti.clone_from(&duplicate.grant.jti);
    duplicate.command.signed.digest = duplicate.command.payload_digest();
    assert!(validate(&duplicate).is_err());
}

#[test]
fn expired_chain_is_rejected_using_caller_time() {
    let fixture =
        authorization_fixture(ControlAction::Quarantine, AssuranceLevel::PhishingResistant);
    assert!(
        validate_authorization_chain(
            &fixture.identity,
            &fixture.intent,
            &fixture.decision,
            &fixture.grant,
            &fixture.command,
            7,
            "2026-08-01T00:02:30.000Z",
        )
        .is_err()
    );
}

fn validate(fixture: &support::AuthorizationFixture) -> Result<(), impl std::error::Error> {
    validate_authorization_chain(
        &fixture.identity,
        &fixture.intent,
        &fixture.decision,
        &fixture.grant,
        &fixture.command,
        7,
        NOW,
    )
}
