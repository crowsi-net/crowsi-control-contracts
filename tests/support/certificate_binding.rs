use crowsi_control_contracts::*;

pub(super) fn binding(action: CertificateActionV2) -> CertificateAuthorizationBindingV2 {
    let same = !action.requires_separation_of_duties();
    CertificateAuthorizationBindingV2 {
        issuer: "https://ihat.online/pa".into(),
        audience: "service://crowsi/certificate-manager".into(),
        channel: "channel.service.automation".into(),
        approval_id: (!same).then(|| "approval.certificate.0001".into()),
        approval_evidence_digest_sha256: (!same).then(|| "39".repeat(32)),
        approval_method: (!same).then_some(CertificateApprovalMethodV2::LocalUserPresence),
        approval_assurance: (!same).then_some(CertificateApprovalAssuranceV2::Aal2),
        approval_issued_at_epoch_s: (!same).then_some(9_930),
        approval_expires_at_epoch_s: (!same).then_some(9_980),
        approval_verified_at_epoch_s: (!same).then_some(9_940),
        policy_id: "policy.certificate.lifecycle".into(),
        policy_digest_sha256: "20".repeat(32),
        identity: identity(same),
        deployment: CertificateDeploymentBindingV2 {
            security_domain: "security.crowsi".into(),
            deployment_id: "deployment.local".into(),
            release_id: "release.certificate.0001".into(),
            release_digest_sha256: "31".repeat(32),
            checkpoint_id: "checkpoint.certificate.0001".into(),
            checkpoint_digest_sha256: "32".repeat(32),
            checkpoint_sequence: 3,
            deployment_provenance_ref: "provenance.certificate.0001".into(),
            trust_revision: 7,
        },
        revocation: CertificateRevocationBindingV2 {
            snapshot_id: "revocation.snapshot.0009".into(),
            snapshot_digest_sha256: "36".repeat(32),
            previous_identity_revocation_epoch: 8,
            snapshot_epoch: 9,
            snapshot_verified_at_epoch_s: 9_940,
            authoritative: true,
        },
        target: target(action),
        operation: operation(action),
    }
}

fn identity(same: bool) -> CertificateIdentityBindingV2 {
    CertificateIdentityBindingV2 {
        pairwise_subject: "subject.pairwise.nerp".into(),
        requester_pairwise_subject: "subject.requester.nerp".into(),
        requester_actor: "actor.nerp.operator".into(),
        requester_device: "device.local.0001".into(),
        requester_profile: "profile.workload.operator".into(),
        requester_proof_key_ref: "proof.key.local.0001".into(),
        approver_pairwise_subject: (!same).then(|| "subject.approver.security".into()),
        approver_actor: (!same).then(|| "actor.security.approver".into()),
        approver_device: (!same).then(|| "device.security.0001".into()),
        approver_profile: (!same).then(|| "profile.security.approver".into()),
        approver_proof_key_ref: (!same).then(|| "proof.key.security.0001".into()),
        workload: "spiffe://crowsi.test/local/nerp".into(),
        identity_revocation_epoch: 9,
    }
}

fn target(action: CertificateActionV2) -> CertificateTargetBindingV2 {
    let read = matches!(
        action,
        CertificateActionV2::CertificateStatus | CertificateActionV2::OperationStatus
    );
    CertificateTargetBindingV2 {
        service_id: "service.nerp.local".into(),
        provider: "provider.policy.administrator".into(),
        target_resource_id: "resource.certificate.nerp.worker".into(),
        target_resource_normalizer_id: "normalizer.certificate.target".into(),
        target_resource_normalizer_version: "version.0001".into(),
        target_resource_normalization_digest_sha256: certificate_target_normalization_digest_v2(
            "provider.policy.administrator",
            "resource.certificate.nerp.worker",
            "resource.certificate.nerp.worker",
            "normalizer.certificate.target",
            "version.0001",
        ),
        target_resource_normalization_verified: true,
        previous_fence: 4,
        current_fence: if read { 4 } else { 5 },
        expected_resource_version: u64::from(action != CertificateActionV2::Issue),
        previous_lifecycle_revocation_epoch: u64::from(action != CertificateActionV2::Issue) * 3,
        lifecycle_revocation_epoch: match action {
            CertificateActionV2::Issue => 0,
            CertificateActionV2::Revoke => 4,
            _ => 3,
        },
    }
}

fn operation(action: CertificateActionV2) -> Option<CertificateOperationBindingV2> {
    match action {
        CertificateActionV2::OperationStatus => {
            Some(CertificateOperationBindingV2::OperationStatus {
                target_operation_id: "request.certificate.original".into(),
            })
        }
        CertificateActionV2::ReconcileUnknown => {
            Some(CertificateOperationBindingV2::ReconcileUnknown {
                original_action: CertificateLifecycleActionV2::Renew,
                target_operation_id: "request.certificate.original".into(),
                lifecycle_reservation_id: "reservation.certificate.original".into(),
                authority_command_digest_sha256: "42".repeat(32),
                unknown_evidence_digest_sha256: "43".repeat(32),
                locked_previous_fence: 2,
                locked_current_fence: 3,
                locked_previous_lifecycle_revocation_epoch: 3,
                locked_lifecycle_revocation_epoch: 3,
            })
        }
        _ => None,
    }
}
