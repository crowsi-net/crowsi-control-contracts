use crate::{
    Validate, ValidationError,
    certificate_v2::{
        CertificateExecutionCommandV2, CertificateExecutionGrantV2, CertificatePayloadV2,
        CertificatePolicyDecisionV2,
        rules::{child_window, current},
    },
};

const MAX_REVOCATION_SNAPSHOT_AGE_SECONDS: u64 = 60;
const MAX_APPROVAL_AGE_SECONDS: u64 = 60;

/// Validates certificate decision, grant, and PA command ancestry at one epoch.
///
/// # Errors
///
/// Rejects stale, cross-bound, replay-shaped, or privilege-substituted artifacts.
pub fn validate_certificate_authorization_chain_v2(
    decision: &CertificatePolicyDecisionV2,
    grant: &CertificateExecutionGrantV2,
    command: &CertificateExecutionCommandV2,
    at_epoch_s: u64,
) -> Result<(), ValidationError> {
    decision.validate()?;
    grant.validate()?;
    command.validate()?;
    validate_links(decision, grant, command)?;
    let current_chain = current(
        decision.issued_at_epoch_s,
        decision.expires_at_epoch_s,
        at_epoch_s,
    ) && current(
        grant.issued_at_epoch_s,
        grant.expires_at_epoch_s,
        at_epoch_s,
    ) && current(
        command.issued_at_epoch_s,
        command.expires_at_epoch_s,
        at_epoch_s,
    );
    if !current_chain {
        return Err(ValidationError::new(
            "at_epoch_s",
            "authorization chain is not current",
        ));
    }
    let nested = child_window(
        decision.issued_at_epoch_s,
        decision.expires_at_epoch_s,
        grant.issued_at_epoch_s,
        grant.expires_at_epoch_s,
    ) && child_window(
        grant.issued_at_epoch_s,
        grant.expires_at_epoch_s,
        command.issued_at_epoch_s,
        command.expires_at_epoch_s,
    );
    if !nested {
        return Err(ValidationError::new(
            "expires_at_epoch_s",
            "child validity must stay inside its parent",
        ));
    }
    let snapshot = &command.binding.revocation;
    if snapshot.snapshot_verified_at_epoch_s > command.issued_at_epoch_s
        || at_epoch_s.saturating_sub(snapshot.snapshot_verified_at_epoch_s)
            > MAX_REVOCATION_SNAPSHOT_AGE_SECONDS
    {
        return Err(ValidationError::new(
            "revocation.snapshot_verified_at_epoch_s",
            "snapshot is future-dated or stale",
        ));
    }
    if let Some(approval_at) = command.binding.approval_verified_at_epoch_s
        && (approval_at > decision.issued_at_epoch_s
            || approval_at > at_epoch_s
            || at_epoch_s.saturating_sub(approval_at) > MAX_APPROVAL_AGE_SECONDS)
    {
        return Err(ValidationError::new(
            "approval_verified_at_epoch_s",
            "approval evidence is future-dated or stale",
        ));
    }
    Ok(())
}

fn validate_links(
    decision: &CertificatePolicyDecisionV2,
    grant: &CertificateExecutionGrantV2,
    command: &CertificateExecutionCommandV2,
) -> Result<(), ValidationError> {
    let decision_digest = decision.certificate_digest_sha256();
    let grant_digest = grant.certificate_digest_sha256();
    let grant_matches = grant.decision_id == decision.decision_id
        && grant.decision_digest_sha256 == decision_digest
        && grant.request_digest_sha256 == decision.request_digest_sha256
        && grant.action == decision.action
        && grant.binding == decision.binding;
    let command_matches = command.decision_id == decision.decision_id
        && command.decision_digest_sha256 == decision.certificate_digest_sha256()
        && command.grant_id == grant.grant_id
        && command.grant_digest_sha256 == grant_digest
        && command.request_digest_sha256 == grant.request_digest_sha256
        && command.action == grant.action
        && command.binding == grant.binding;
    if !grant_matches || !command_matches {
        return Err(ValidationError::new(
            "authorization_binding",
            "decision, grant, command, action, and target must match exactly",
        ));
    }
    if grant.jti == command.jti
        || command.related_authorization_jti.as_deref() == Some(grant.jti.as_str())
    {
        return Err(ValidationError::new(
            "jti",
            "grant and command JTIs must be distinct",
        ));
    }
    Ok(())
}
