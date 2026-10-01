use crate::{
    ValidationError,
    certificate_v2::{
        CertificateActionV2, CertificateLifecycleActionV2, CertificateOperationBindingV2,
        digest::DigestBuilder,
        rules::{bare_digest, id},
    },
};

impl CertificateOperationBindingV2 {
    pub(crate) fn validate_for(
        action: CertificateActionV2,
        value: Option<&Self>,
    ) -> Result<(), ValidationError> {
        match (action, value) {
            (
                CertificateActionV2::OperationStatus,
                Some(Self::OperationStatus {
                    target_operation_id,
                }),
            ) => id("operation.target_operation_id", target_operation_id),
            (
                CertificateActionV2::ReconcileUnknown,
                Some(Self::ReconcileUnknown {
                    original_action,
                    target_operation_id,
                    lifecycle_reservation_id,
                    authority_command_digest_sha256,
                    unknown_evidence_digest_sha256,
                    locked_previous_fence,
                    locked_current_fence,
                    locked_previous_lifecycle_revocation_epoch,
                    locked_lifecycle_revocation_epoch,
                }),
            ) => {
                id("operation.target_operation_id", target_operation_id)?;
                id(
                    "operation.lifecycle_reservation_id",
                    lifecycle_reservation_id,
                )?;
                bare_digest(
                    "operation.authority_command_digest_sha256",
                    authority_command_digest_sha256,
                )?;
                bare_digest(
                    "operation.unknown_evidence_digest_sha256",
                    unknown_evidence_digest_sha256,
                )?;
                if locked_previous_fence.checked_add(1) != Some(*locked_current_fence)
                    || !valid_lifecycle(
                        *original_action,
                        *locked_previous_lifecycle_revocation_epoch,
                        *locked_lifecycle_revocation_epoch,
                    )
                {
                    return Err(ValidationError::new(
                        "operation.locked_transition",
                        "does not match the original lifecycle action",
                    ));
                }
                Ok(())
            }
            (
                CertificateActionV2::Issue
                | CertificateActionV2::Renew
                | CertificateActionV2::Revoke
                | CertificateActionV2::CertificateStatus,
                None,
            ) => Ok(()),
            _ => Err(ValidationError::new(
                "operation",
                "operation binding does not match the authorized action",
            )),
        }
    }

    pub(crate) fn add_optional_to_digest(value: Option<&Self>, out: &mut DigestBuilder) {
        match value {
            None => out.text("none"),
            Some(Self::OperationStatus {
                target_operation_id,
            }) => {
                out.text("operation-status");
                out.text(target_operation_id);
            }
            Some(Self::ReconcileUnknown {
                original_action,
                target_operation_id,
                lifecycle_reservation_id,
                authority_command_digest_sha256,
                unknown_evidence_digest_sha256,
                locked_previous_fence,
                locked_current_fence,
                locked_previous_lifecycle_revocation_epoch,
                locked_lifecycle_revocation_epoch,
            }) => {
                for value in [
                    "reconcile-unknown",
                    original_action.as_str(),
                    target_operation_id,
                    lifecycle_reservation_id,
                    authority_command_digest_sha256,
                    unknown_evidence_digest_sha256,
                ] {
                    out.text(value);
                }
                for value in [
                    *locked_previous_fence,
                    *locked_current_fence,
                    *locked_previous_lifecycle_revocation_epoch,
                    *locked_lifecycle_revocation_epoch,
                ] {
                    out.number(value);
                }
            }
        }
    }
}

fn valid_lifecycle(action: CertificateLifecycleActionV2, previous: u64, current: u64) -> bool {
    match action {
        CertificateLifecycleActionV2::Issue => previous == 0 && current == 0,
        CertificateLifecycleActionV2::Renew => previous == current,
        CertificateLifecycleActionV2::Revoke => previous.checked_add(1) == Some(current),
    }
}
