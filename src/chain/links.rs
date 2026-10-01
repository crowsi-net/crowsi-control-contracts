use crate::{
    EnforcementGrantV1, IsolationCommandV1, PolicyDecisionV1, SecurityIntentV1, ValidationError,
    VerifiedIdentityContextV1,
};

pub(super) fn validate_links(
    identity: &VerifiedIdentityContextV1,
    intent: &SecurityIntentV1,
    decision: &PolicyDecisionV1,
    grant: &EnforcementGrantV1,
    command: &IsolationCommandV1,
) -> Result<(), ValidationError> {
    if identity.context_id != intent.identity_context_id
        || identity.pairwise_subject != intent.pairwise_subject
        || identity.actor != intent.actor
        || identity.device != intent.device
        || identity.workload != intent.workload
        || identity.profile != intent.profile
        || identity.proof_key_ref != intent.proof_key_ref
        || identity.revocation_epoch != intent.revocation_epoch
    {
        return Err(ValidationError::new(
            "intent.identity",
            "does not match the verified identity",
        ));
    }
    if decision.intent_jti != intent.jti
        || decision.identity_context_id != identity.context_id
        || decision.pairwise_subject != identity.pairwise_subject
        || decision.actor != identity.actor
        || decision.device != identity.device
        || decision.workload != identity.workload
        || decision.profile != identity.profile
        || decision.proof_key_ref != identity.proof_key_ref
        || decision.revocation_epoch != identity.revocation_epoch
    {
        return Err(ValidationError::new(
            "decision.identity",
            "does not match the intent and identity",
        ));
    }
    if grant.decision_id != decision.decision_id
        || grant.intent_jti != intent.jti
        || grant.identity_context_id != identity.context_id
        || grant.pairwise_subject != identity.pairwise_subject
        || grant.actor != identity.actor
        || grant.device != identity.device
        || grant.workload != identity.workload
        || grant.profile != identity.profile
        || grant.proof_key_ref != identity.proof_key_ref
        || grant.revocation_epoch != identity.revocation_epoch
    {
        return Err(ValidationError::new(
            "grant.identity",
            "does not match the authorization chain",
        ));
    }
    if command.enforcement_grant_jti != grant.jti
        || command.decision_id != decision.decision_id
        || command.pairwise_subject != identity.pairwise_subject
        || command.actor != identity.actor
        || command.device != identity.device
        || command.workload != identity.workload
        || command.profile != identity.profile
        || command.proof_key_ref != identity.proof_key_ref
        || command.revocation_epoch != identity.revocation_epoch
    {
        return Err(ValidationError::new(
            "command.identity",
            "does not match the enforcement grant",
        ));
    }
    Ok(())
}
