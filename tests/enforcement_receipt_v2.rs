use crowsi_control_contracts::{
    ActionBindingV1, CanonicalPayloadV1, ControlAction, ControlChannel,
    ENFORCEMENT_RECEIPT_SCHEMA_V2, EnforcementOutcome, EnforcementReceiptV2, SignatureAlgorithm,
    SignedDigestV1, Validate,
};

fn receipt() -> EnforcementReceiptV2 {
    let mut value = EnforcementReceiptV2 {
        schema: ENFORCEMENT_RECEIPT_SCHEMA_V2.into(),
        receipt_id: "receipt.v2.1".into(),
        command_jti: "jti.command.v2.1".into(),
        command_digest: digest('a'),
        security_domain: "customer-hat".into(),
        deployment_id: "deployment.production.1".into(),
        incident_id: "incident.1".into(),
        target_id: "incus://project/default/instance/worker-a".into(),
        release_reservation_id: "release-reservation.1".into(),
        fence_epoch: 9,
        binding: ActionBindingV1 {
            audience: "crowsi-enforcer-incus".into(),
            resource: "incus://project/default/instance/worker-a".into(),
            action: ControlAction::Quarantine,
            purpose: "incident-containment".into(),
            channel: ControlChannel::EmergencyConsole,
        },
        provider: "crowsi-enforcer-incus".into(),
        outcome: EnforcementOutcome::Applied,
        authorization_consumed: true,
        applied_at: "2026-07-29T00:02:00.000Z".into(),
        expected_resource_version: "incus-etag-7".into(),
        resulting_resource_version: Some("incus-etag-8".into()),
        residual_exposures: Vec::new(),
        evidence_digest: digest('b'),
        signed: placeholder(),
    };
    value.signed.digest = value.payload_digest();
    value
}

#[test]
fn v2_receipt_carries_exact_fence_and_resource_cas_evidence() {
    receipt().validate().expect("closed v2 receipt");
}

#[test]
fn receipt_tampering_is_detected() {
    let mut value = receipt();
    value.fence_epoch += 1;
    assert!(value.validate().is_err());
}

#[test]
fn every_reported_resource_version_is_bounded() {
    let mut value = receipt();
    value.outcome = EnforcementOutcome::Rejected;
    value.resulting_resource_version = Some("\n".into());
    value.signed.digest = value.payload_digest();
    assert!(value.validate().is_err());
}

fn digest(value: char) -> String {
    format!("sha256:{}", value.to_string().repeat(64))
}

fn placeholder() -> SignedDigestV1 {
    SignedDigestV1 {
        algorithm: SignatureAlgorithm::Ed25519,
        key_id: "receipt.control.1".into(),
        digest: digest('c'),
        signature: "a".repeat(86),
    }
}
