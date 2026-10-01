mod support;

use crowsi_control_contracts::*;
use serde_json::json;

use support::certificate_chain;

struct ExactVerifier;

impl CertificateLeaseSignatureVerifierV2 for ExactVerifier {
    fn verify_lease_digest(
        &self,
        key_id: &str,
        algorithm: CertificateSignatureAlgorithmV2,
        digest: &str,
        signature: &str,
    ) -> bool {
        key_id == "key.policy.administrator"
            && algorithm == CertificateSignatureAlgorithmV2::Ed25519
            && digest.len() == 64
            && signature == "c2lnbmF0dXJl"
    }
}

fn lease(action: CertificateActionV2) -> CertificateExecutionLeaseV2 {
    let (_, _, command) = certificate_chain(action);
    CertificateExecutionLeaseV2 {
        schema: CERTIFICATE_EXECUTION_LEASE_SCHEMA_V2.into(),
        pa_reservation_id: command.pa_reservation_id.clone(),
        authorization_command_digest_sha256: command.certificate_digest_sha256(),
        reserved_at_epoch_s: 10_000,
        command,
        one_use: true,
    }
}

#[test]
fn closed_chain_bridges_to_the_certificate_manager_shape() {
    let (decision, grant, command) = certificate_chain(CertificateActionV2::Issue);
    validate_certificate_authorization_chain_v2(&decision, &grant, &command, 10_000)
        .expect("closed certificate chain");
    let lease = lease(CertificateActionV2::Issue);
    let signed = package_signed_certificate_authorization_v2(&lease, "c2lnbmF0dXJl")
        .expect("package signed lease");
    let verified =
        verify_signed_certificate_authorization_v2(&signed, &ExactVerifier).expect("verified");
    assert_eq!(verified.action, CertificateActionV2::Issue);
    assert_eq!(verified.command_digest_sha256, "10".repeat(32));
    assert_eq!(verified.previous_identity_revocation_epoch, 8);
    assert_eq!(verified.revocation_snapshot_epoch, 9);
    assert_eq!(
        verified.target_resource_id,
        "resource.certificate.nerp.worker"
    );
    assert!(verified.one_use && verified.signature_verified);
}

#[test]
fn operation_status_cannot_be_relabelled_as_reconciliation() {
    let (decision, grant, mut command) = certificate_chain(CertificateActionV2::OperationStatus);
    validate_certificate_authorization_chain_v2(&decision, &grant, &command, 10_000)
        .expect("operation status is valid");
    command.action = CertificateActionV2::ReconcileUnknown;
    command.binding.identity.approver_pairwise_subject = Some("subject.approver.security".into());
    assert!(
        validate_certificate_authorization_chain_v2(&decision, &grant, &command, 10_000).is_err()
    );
}

#[test]
fn mutating_actions_require_separate_requester_and_approver() {
    let (decision, _, _) = certificate_chain(CertificateActionV2::Issue);
    let mut value = decision;
    value.binding.identity.approver_pairwise_subject =
        Some(value.binding.identity.requester_pairwise_subject.clone());
    value.signed.digest_sha256 = value.certificate_digest_sha256();
    assert!(value.validate().is_err());
}

#[test]
fn unknown_fields_and_fence_drift_fail_closed() {
    let mut value = serde_json::to_value(lease(CertificateActionV2::CertificateStatus)).unwrap();
    value
        .as_object_mut()
        .unwrap()
        .insert("ambient_authority".into(), json!(true));
    assert!(serde_json::from_value::<CertificateExecutionLeaseV2>(value).is_err());
    let (_, _, mut command) = certificate_chain(CertificateActionV2::Issue);
    command.binding.target.current_fence += 1;
    assert!(command.validate().is_err());
}

#[test]
fn wrapper_digest_and_signature_are_both_required() {
    let lease = lease(CertificateActionV2::CertificateStatus);
    let signed =
        package_signed_certificate_authorization_v2(&lease, "c2lnbmF0dXJl").expect("package");
    let mut value = serde_json::to_value(signed).unwrap();
    value["lease_digest_sha256"] = json!("ff".repeat(32));
    let tampered: SignedCertificateExecutionAuthorizationV2 =
        serde_json::from_value(value).unwrap();
    assert!(verify_signed_certificate_authorization_v2(&tampered, &ExactVerifier).is_err());
}

#[test]
fn six_actions_have_distinct_wire_names_and_scopes() {
    let actions = [
        CertificateActionV2::Issue,
        CertificateActionV2::Renew,
        CertificateActionV2::Revoke,
        CertificateActionV2::CertificateStatus,
        CertificateActionV2::OperationStatus,
        CertificateActionV2::ReconcileUnknown,
    ];
    let names = actions.map(CertificateActionV2::as_str);
    assert_eq!(
        names,
        [
            "issue",
            "renew",
            "revoke",
            "certificate-status",
            "operation-status",
            "reconcile-unknown"
        ]
    );
    assert_ne!(
        CertificateActionV2::OperationStatus.fence_scope(),
        CertificateActionV2::ReconcileUnknown.fence_scope()
    );
}
