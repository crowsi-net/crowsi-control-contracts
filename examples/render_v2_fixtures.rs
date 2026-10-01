use crowsi_control_contracts::{
    ActionBindingV1, CanonicalPayloadV1, ControlAction, ControlChannel,
    ENFORCEMENT_RECEIPT_SCHEMA_V2, EnforcementOutcome, EnforcementReceiptV2,
    ISOLATION_COMMAND_SCHEMA_V2, IsolationCommandV2, PEP_EXECUTION_LEASE_SCHEMA_V2,
    PepExecutionLeaseV2, SignatureAlgorithm, SignedDigestV1,
};

fn main() {
    let binding = ActionBindingV1 {
        audience: "crowsi-enforcer-incus".into(),
        resource: "incus://project/default/instance/worker-a".into(),
        action: ControlAction::Quarantine,
        purpose: "incident-containment".into(),
        channel: ControlChannel::EmergencyConsole,
    };
    let mut command = IsolationCommandV2 {
        schema: ISOLATION_COMMAND_SCHEMA_V2.into(),
        command_id: "command.v2.sample".into(),
        jti: "jti.command.v2.sample".into(),
        security_domain: "customer-sample".into(),
        deployment_id: "deployment.sample.1".into(),
        incident_id: "incident.sample.1".into(),
        target_id: binding.resource.clone(),
        release_id: "release.sample.1".into(),
        release_digest: digest('b'),
        checkpoint_id: "checkpoint.sample.1".into(),
        checkpoint_digest: digest('c'),
        checkpoint_sequence: 42,
        release_reservation_id: "release-reservation.sample.1".into(),
        enforcement_grant_jti: "jti.grant.sample.1".into(),
        decision_id: "decision.sample.1".into(),
        pairwise_subject: "subject-sample".into(),
        actor: "operator-sample".into(),
        device: "device-sample".into(),
        workload: "spiffe://crowsi.local/rescue-console/sample".into(),
        profile: "security-operator".into(),
        proof_key_ref: "proof-key-sample".into(),
        revocation_epoch: 7,
        binding: binding.clone(),
        provider: binding.audience.clone(),
        previous_fence_epoch: 8,
        fence_epoch: 9,
        expected_resource_version: "incus-etag-7".into(),
        issued_at: "2026-07-29T00:01:30.000Z".into(),
        expires_at: "2026-07-29T00:02:30.000Z".into(),
        signed: placeholder("command.sample.1"),
    };
    command.signed.digest = command.payload_digest();
    let lease = PepExecutionLeaseV2 {
        schema: PEP_EXECUTION_LEASE_SCHEMA_V2.into(),
        reservation_id: command.release_reservation_id.clone(),
        command: command.clone(),
        command_digest: command.payload_digest(),
        reserved_at: "2026-07-29T00:01:45.000Z".into(),
    };
    let mut receipt = EnforcementReceiptV2 {
        schema: ENFORCEMENT_RECEIPT_SCHEMA_V2.into(),
        receipt_id: "receipt.v2.sample".into(),
        command_jti: command.jti.clone(),
        command_digest: command.payload_digest(),
        security_domain: command.security_domain.clone(),
        deployment_id: command.deployment_id.clone(),
        incident_id: command.incident_id.clone(),
        target_id: command.target_id.clone(),
        release_reservation_id: command.release_reservation_id.clone(),
        fence_epoch: command.fence_epoch,
        binding,
        provider: command.provider.clone(),
        outcome: EnforcementOutcome::Applied,
        authorization_consumed: true,
        applied_at: "2026-07-29T00:02:00.000Z".into(),
        expected_resource_version: command.expected_resource_version.clone(),
        resulting_resource_version: Some("incus-etag-8".into()),
        residual_exposures: Vec::new(),
        evidence_digest: digest('e'),
        signed: placeholder("receipt.sample.1"),
    };
    receipt.signed.digest = receipt.payload_digest();
    println!(
        "COMMAND\n{}\nLEASE\n{}\nRECEIPT\n{}",
        serde_json::to_string_pretty(&command).expect("command"),
        serde_json::to_string_pretty(&lease).expect("lease"),
        serde_json::to_string_pretty(&receipt).expect("receipt")
    );
}

fn digest(value: char) -> String {
    format!("sha256:{}", value.to_string().repeat(64))
}

fn placeholder(key_id: &str) -> SignedDigestV1 {
    SignedDigestV1 {
        algorithm: SignatureAlgorithm::Ed25519,
        key_id: key_id.into(),
        digest: digest('a'),
        signature: "a".repeat(86),
    }
}
