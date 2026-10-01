use crate::{
    ValidationError,
    certificate_v2::{
        CertificateActionV2, CertificateAuthorizationBindingV2, CertificateLifecycleActionV2,
        CertificateOperationBindingV2,
        rules::{bare_digest, id},
    },
};

pub(super) fn validate_approval(
    value: &CertificateAuthorizationBindingV2,
    action: CertificateActionV2,
) -> Result<(), ValidationError> {
    let approval = match (
        value.approval_id.as_deref(),
        value.approval_evidence_digest_sha256.as_deref(),
        value.approval_method,
        value.approval_assurance,
        value.approval_issued_at_epoch_s,
        value.approval_expires_at_epoch_s,
        value.approval_verified_at_epoch_s,
    ) {
        (
            Some(id_value),
            Some(digest),
            Some(method),
            Some(assurance),
            Some(issued),
            Some(expires),
            Some(verified),
        ) => {
            id("approval_id", id_value)?;
            bare_digest("approval_evidence_digest_sha256", digest)?;
            Some((method, assurance, issued, expires, verified))
        }
        (None, None, None, None, None, None, None) => None,
        _ => {
            return Err(ValidationError::new(
                "approval",
                "approval evidence fields must be wholly present or absent",
            ));
        }
    };
    match (action.requires_separation_of_duties(), approval) {
        (true, Some((method, _, issued, expires, verified)))
            if method.proves_user_presence()
                && issued > 0
                && issued <= verified
                && verified < expires =>
        {
            Ok(())
        }
        (false, None) => Ok(()),
        _ => Err(ValidationError::new(
            "approval",
            "mutations require presence evidence and reads require its absence",
        )),
    }
}

pub(super) fn validate_reconciliation(
    value: &CertificateAuthorizationBindingV2,
    action: CertificateActionV2,
) -> Result<(), ValidationError> {
    let Some(CertificateOperationBindingV2::ReconcileUnknown {
        original_action,
        locked_previous_lifecycle_revocation_epoch,
        locked_lifecycle_revocation_epoch,
        ..
    }) = value.operation.as_ref()
    else {
        return Ok(());
    };
    if action != CertificateActionV2::ReconcileUnknown
        || value.target.previous_lifecycle_revocation_epoch
            != *locked_previous_lifecycle_revocation_epoch
        || value.target.lifecycle_revocation_epoch != *locked_lifecycle_revocation_epoch
    {
        return Err(ValidationError::new(
            "operation.lifecycle_revocation_epoch",
            "must match the locked certificate lifecycle",
        ));
    }
    let version_valid = match original_action {
        CertificateLifecycleActionV2::Issue => value.target.expected_resource_version == 0,
        CertificateLifecycleActionV2::Renew | CertificateLifecycleActionV2::Revoke => {
            (1..u64::MAX).contains(&value.target.expected_resource_version)
        }
    };
    version_valid.then_some(()).ok_or(ValidationError::new(
        "expected_resource_version",
        "does not match the reconciled lifecycle action",
    ))
}
