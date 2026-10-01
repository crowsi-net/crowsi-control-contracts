use crate::certificate_v2::{
    CertificateExecutionLeaseV2, CertificateOperationBindingV2, CertificatePayloadV2,
    VerifiedCertificateExecutionAuthorizationV2,
};

impl VerifiedCertificateExecutionAuthorizationV2 {
    #[allow(clippy::too_many_lines)]
    pub(crate) fn from_lease(value: &CertificateExecutionLeaseV2) -> Self {
        let command = &value.command;
        let binding = &command.binding;
        let identity = &binding.identity;
        let deployment = &binding.deployment;
        let revocation = &binding.revocation;
        let target = &binding.target;
        let operation = binding.operation.as_ref();
        let (locked_previous_fence, locked_current_fence) =
            operation.map_or((None, None), CertificateOperationBindingV2::locked_fences);
        let (locked_previous_lifecycle_revocation_epoch, locked_lifecycle_revocation_epoch) =
            operation.map_or((None, None), |value| {
                value.locked_lifecycle_revocation_epochs()
            });
        Self {
            authorization_id: command.authorization_id.clone(),
            jti: command.jti.clone(),
            pa_reservation_id: command.pa_reservation_id.clone(),
            operation_id: command.operation_id.clone(),
            lease_digest_sha256: value.certificate_digest_sha256(),
            command_digest_sha256: command.request_digest_sha256.clone(),
            action: command.action,
            issuer: binding.issuer.clone(),
            audience: binding.audience.clone(),
            signature_key_id: command.signature_key_id.clone(),
            signature_key_version: command.signature_key_version.clone(),
            signature_public_key_spki_sha256: command.signature_public_key_spki_sha256.clone(),
            signature_key_purpose: command.signature_key_purpose.clone(),
            signature_algorithm: command.signature_algorithm.as_str().into(),
            trust_revision: deployment.trust_revision,
            channel: binding.channel.clone(),
            approval_id: binding.approval_id.clone(),
            approval_evidence_digest_sha256: binding.approval_evidence_digest_sha256.clone(),
            approval_method: binding.approval_method,
            approval_assurance: binding.approval_assurance,
            approval_issued_at_epoch_s: binding.approval_issued_at_epoch_s,
            approval_expires_at_epoch_s: binding.approval_expires_at_epoch_s,
            approval_verified_at_epoch_s: binding.approval_verified_at_epoch_s,
            security_domain: deployment.security_domain.clone(),
            deployment_id: deployment.deployment_id.clone(),
            release_id: deployment.release_id.clone(),
            release_digest_sha256: deployment.release_digest_sha256.clone(),
            checkpoint_id: deployment.checkpoint_id.clone(),
            checkpoint_digest_sha256: deployment.checkpoint_digest_sha256.clone(),
            checkpoint_sequence: deployment.checkpoint_sequence,
            deployment_provenance_ref: deployment.deployment_provenance_ref.clone(),
            policy_id: binding.policy_id.clone(),
            policy_digest_sha256: binding.policy_digest_sha256.clone(),
            decision_id: command.decision_id.clone(),
            decision_digest_sha256: command.decision_digest_sha256.clone(),
            grant_id: command.grant_id.clone(),
            grant_digest_sha256: command.grant_digest_sha256.clone(),
            pairwise_subject: identity.pairwise_subject.clone(),
            requester_pairwise_subject: identity.requester_pairwise_subject.clone(),
            requester_actor: identity.requester_actor.clone(),
            requester_device: identity.requester_device.clone(),
            requester_profile: identity.requester_profile.clone(),
            requester_proof_key_ref: identity.requester_proof_key_ref.clone(),
            approver_pairwise_subject: identity.approver_pairwise_subject.clone(),
            approver_actor: identity.approver_actor.clone(),
            approver_device: identity.approver_device.clone(),
            approver_profile: identity.approver_profile.clone(),
            approver_proof_key_ref: identity.approver_proof_key_ref.clone(),
            workload: identity.workload.clone(),
            identity_revocation_epoch: identity.identity_revocation_epoch,
            revocation_snapshot_id: revocation.snapshot_id.clone(),
            revocation_snapshot_digest_sha256: revocation.snapshot_digest_sha256.clone(),
            previous_identity_revocation_epoch: revocation.previous_identity_revocation_epoch,
            revocation_snapshot_epoch: revocation.snapshot_epoch,
            revocation_snapshot_verified_at_epoch_s: revocation.snapshot_verified_at_epoch_s,
            authoritative_revocation_snapshot: revocation.authoritative,
            service_id: target.service_id.clone(),
            provider: target.provider.clone(),
            target_resource_id: target.target_resource_id.clone(),
            target_resource_normalizer_id: target.target_resource_normalizer_id.clone(),
            target_resource_normalizer_version: target.target_resource_normalizer_version.clone(),
            target_resource_normalization_digest_sha256: target
                .target_resource_normalization_digest_sha256
                .clone(),
            target_resource_normalization_verified: target.target_resource_normalization_verified,
            previous_fence: target.previous_fence,
            current_fence: target.current_fence,
            expected_resource_version: target.expected_resource_version,
            previous_lifecycle_revocation_epoch: target.previous_lifecycle_revocation_epoch,
            lifecycle_revocation_epoch: target.lifecycle_revocation_epoch,
            target_operation_id: operation.map(|value| value.target_operation_id().into()),
            original_action: operation.and_then(CertificateOperationBindingV2::original_action),
            lifecycle_reservation_id: operation
                .and_then(|value| value.lifecycle_reservation_id().map(Into::into)),
            authority_command_digest_sha256: operation
                .and_then(|value| value.authority_command_digest_sha256().map(Into::into)),
            unknown_evidence_digest_sha256: operation
                .and_then(|value| value.unknown_evidence_digest_sha256().map(Into::into)),
            locked_previous_fence,
            locked_current_fence,
            locked_previous_lifecycle_revocation_epoch,
            locked_lifecycle_revocation_epoch,
            issued_at_epoch_s: command.issued_at_epoch_s,
            expires_at_epoch_s: command.expires_at_epoch_s,
            one_use: command.one_use && value.one_use,
            signature_verified: true,
        }
    }
}
