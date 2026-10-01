mod support;

use crowsi_control_contracts::{
    AssuranceLevel, CanonicalPayloadV1, ControlAction, ControlChannel, DecisionEffect, Validate,
    validate_authorization_chain,
};

use support::authorization_fixture;

const NOW: &str = "2026-08-01T00:01:45.000Z";

#[test]
fn accepts_current_quarantine_and_hardware_bound_restore() {
    let quarantine =
        authorization_fixture(ControlAction::Quarantine, AssuranceLevel::PhishingResistant);
    validate(&quarantine).expect("valid quarantine chain");
    let restore =
        authorization_fixture(ControlAction::Restore, AssuranceLevel::HardwareBoundStepUp);
    validate(&restore).expect("valid restore chain");
    assert!(
        ControlAction::Restore.required_assurance()
            > ControlAction::Quarantine.required_assurance()
    );
}

#[test]
fn restore_rejects_weaker_step_up() {
    let fixture = authorization_fixture(ControlAction::Restore, AssuranceLevel::PhishingResistant);
    assert!(fixture.grant.validate().is_err());
    assert!(validate(&fixture).is_err());
}

#[test]
fn revocation_epoch_and_deny_decision_fail_closed() {
    let mut revoked =
        authorization_fixture(ControlAction::Quarantine, AssuranceLevel::PhishingResistant);
    assert!(
        validate_authorization_chain(
            &revoked.identity,
            &revoked.intent,
            &revoked.decision,
            &revoked.grant,
            &revoked.command,
            8,
            NOW,
        )
        .is_err()
    );
    revoked.decision.effect = DecisionEffect::Deny;
    revoked.decision.signed.digest = revoked.decision.payload_digest();
    assert!(validate(&revoked).is_err());
}

#[test]
fn audience_resource_action_purpose_and_channel_are_exactly_bound() {
    let base = authorization_fixture(ControlAction::Quarantine, AssuranceLevel::PhishingResistant);
    let mut audience = base.command.clone();
    audience.binding.audience = "crowsi-enforcer-linux".to_owned();
    audience.provider = audience.binding.audience.clone();
    audience.signed.digest = audience.payload_digest();
    assert!(validate_command(&base, &audience).is_err());
    let mut resource = base.command.clone();
    resource.binding.resource = "incus://project/default/instance/other".to_owned();
    resource.signed.digest = resource.payload_digest();
    assert!(validate_command(&base, &resource).is_err());
    let mut action = base.command.clone();
    action.binding.action = ControlAction::RestrictEgress;
    action.signed.digest = action.payload_digest();
    assert!(validate_command(&base, &action).is_err());
    let mut purpose = base.command.clone();
    purpose.binding.purpose = "routine-maintenance".to_owned();
    purpose.signed.digest = purpose.payload_digest();
    assert!(validate_command(&base, &purpose).is_err());
    let mut channel = base.command.clone();
    channel.binding.channel = ControlChannel::ServiceAutomation;
    channel.signed.digest = channel.payload_digest();
    assert!(validate_command(&base, &channel).is_err());
}

#[test]
fn profile_and_proof_key_binding_cannot_be_substituted() {
    let mut profile =
        authorization_fixture(ControlAction::Quarantine, AssuranceLevel::PhishingResistant);
    profile.grant.profile = "profile-other".to_owned();
    profile.grant.signed.digest = profile.grant.payload_digest();
    assert!(validate(&profile).is_err());
    let mut proof =
        authorization_fixture(ControlAction::Quarantine, AssuranceLevel::PhishingResistant);
    proof.command.proof_key_ref = "jkt:attacker-key".to_owned();
    proof.command.signed.digest = proof.command.payload_digest();
    assert!(validate(&proof).is_err());
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

fn validate_command(
    fixture: &support::AuthorizationFixture,
    command: &crowsi_control_contracts::IsolationCommandV1,
) -> Result<(), impl std::error::Error> {
    validate_authorization_chain(
        &fixture.identity,
        &fixture.intent,
        &fixture.decision,
        &fixture.grant,
        command,
        7,
        NOW,
    )
}
