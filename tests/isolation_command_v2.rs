mod support;

use crowsi_control_contracts::{
    ActionBindingV1, AssuranceLevel, CanonicalPayloadV1, ControlAction, ControlChannel,
    ISOLATION_COMMAND_SCHEMA_V2, IsolationCommandV2, SignatureAlgorithm, SignedDigestV1, Validate,
    validate_authorization_chain_v2,
};
use support::authorization_fixture;

fn command() -> IsolationCommandV2 {
    let mut value = IsolationCommandV2 {
        schema: ISOLATION_COMMAND_SCHEMA_V2.into(),
        command_id: "command.v2.1".into(),
        jti: "jti.command.v2.1".into(),
        security_domain: "customer-hat".into(),
        deployment_id: "deployment.production.1".into(),
        incident_id: "incident.1".into(),
        target_id: "incus://project/default/instance/worker-a".into(),
        release_id: "release.1".into(),
        release_digest: digest('b'),
        checkpoint_id: "checkpoint.1".into(),
        checkpoint_digest: digest('c'),
        checkpoint_sequence: 42,
        release_reservation_id: "release-reservation.1".into(),
        enforcement_grant_jti: "jti.grant.1".into(),
        decision_id: "decision.1".into(),
        pairwise_subject: "subject-a".into(),
        actor: "operator-a".into(),
        device: "device-a".into(),
        workload: "spiffe://crowsi.local/rescue-console/a".into(),
        profile: "security-operator".into(),
        proof_key_ref: "proof-key-a".into(),
        revocation_epoch: 7,
        binding: ActionBindingV1 {
            audience: "crowsi-enforcer-incus".into(),
            resource: "incus://project/default/instance/worker-a".into(),
            action: ControlAction::Quarantine,
            purpose: "incident-containment".into(),
            channel: ControlChannel::EmergencyConsole,
        },
        provider: "crowsi-enforcer-incus".into(),
        previous_fence_epoch: 8,
        fence_epoch: 9,
        expected_resource_version: "incus-etag-7".into(),
        issued_at: "2026-07-29T00:01:30.000Z".into(),
        expires_at: "2026-07-29T00:02:30.000Z".into(),
        signed: placeholder(),
    };
    value.signed.digest = value.payload_digest();
    value
}

#[test]
fn complete_v2_binding_is_accepted() {
    command().validate().expect("closed v2 contract");
}

#[test]
fn every_security_boundary_is_in_the_signed_payload() {
    let original = command();
    let original_digest = original.payload_digest();
    let mutations: [fn(&mut IsolationCommandV2); 15] = [
        |v| v.security_domain.push_str("-other"),
        |v| v.deployment_id.push_str("-other"),
        |v| v.incident_id.push_str("-other"),
        |v| v.target_id.push_str("-other"),
        |v| v.release_id.push_str("-other"),
        |v| v.release_digest = digest('d'),
        |v| v.checkpoint_id.push_str("-other"),
        |v| v.checkpoint_digest = digest('e'),
        |v| v.checkpoint_sequence += 1,
        |v| v.release_reservation_id.push_str("-other"),
        |v| v.previous_fence_epoch += 1,
        |v| v.fence_epoch += 1,
        |v| v.expected_resource_version.push_str("-other"),
        |v| v.expires_at = "2026-07-29T00:02:29.000Z".into(),
        |v| v.revocation_epoch += 1,
    ];
    for mutate in mutations {
        let mut changed = original.clone();
        mutate(&mut changed);
        assert_ne!(changed.payload_digest(), original_digest);
        assert!(changed.validate().is_err());
    }
}

#[test]
fn fence_and_target_are_exact_compare_and_swap_bindings() {
    let mut stale = command();
    stale.previous_fence_epoch = stale.fence_epoch;
    stale.signed.digest = stale.payload_digest();
    assert!(stale.validate().is_err());

    let mut wrong_target = command();
    wrong_target.target_id.push_str("/other");
    wrong_target.signed.digest = wrong_target.payload_digest();
    assert!(wrong_target.validate().is_err());
}

#[test]
fn v2_chain_rejects_identity_or_revocation_substitution() {
    let fixture =
        authorization_fixture(ControlAction::Quarantine, AssuranceLevel::PhishingResistant);
    let mut value = command();
    value.enforcement_grant_jti = fixture.grant.jti.clone();
    value.decision_id = fixture.decision.decision_id.clone();
    value.pairwise_subject = fixture.identity.pairwise_subject.clone();
    value.actor = fixture.identity.actor.clone();
    value.device = fixture.identity.device.clone();
    value.workload = fixture.identity.workload.clone();
    value.profile = fixture.identity.profile.clone();
    value.proof_key_ref = fixture.identity.proof_key_ref.clone();
    value.revocation_epoch = fixture.identity.revocation_epoch;
    value.binding = fixture.grant.binding.clone();
    value.provider = fixture.grant.binding.audience.clone();
    value.target_id = fixture.grant.binding.resource.clone();
    value.issued_at = "2026-08-01T00:01:30.000Z".into();
    value.expires_at = "2026-08-01T00:02:30.000Z".into();
    value.signed.digest = value.payload_digest();
    validate_authorization_chain_v2(
        &fixture.identity,
        &fixture.intent,
        &fixture.decision,
        &fixture.grant,
        &value,
        fixture.identity.revocation_epoch,
        "2026-08-01T00:02:00.000Z",
    )
    .expect("exact v2 chain");
    value.revocation_epoch += 1;
    value.signed.digest = value.payload_digest();
    assert!(
        validate_authorization_chain_v2(
            &fixture.identity,
            &fixture.intent,
            &fixture.decision,
            &fixture.grant,
            &value,
            fixture.identity.revocation_epoch,
            "2026-08-01T00:02:00.000Z",
        )
        .is_err()
    );
}

fn digest(value: char) -> String {
    format!("sha256:{}", value.to_string().repeat(64))
}

fn placeholder() -> SignedDigestV1 {
    SignedDigestV1 {
        algorithm: SignatureAlgorithm::Ed25519,
        key_id: "command.control.1".into(),
        digest: digest('a'),
        signature: "a".repeat(86),
    }
}
