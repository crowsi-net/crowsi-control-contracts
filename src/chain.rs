mod links;

use crate::{
    DecisionEffect, EnforcementGrantV1, IsolationCommandV1, PolicyDecisionV1, SecurityIntentV1,
    Validate, ValidationError, VerifiedIdentityContextV1,
    time::unix_millis,
    validation::{timestamp, valid_at},
};
use links::validate_links;

/// Validates one complete, already signature-verified authorization chain.
///
/// `current_revocation_epoch` must come from the identity authority and `at`
/// from a trusted caller clock.
///
/// # Errors
///
/// Rejects malformed, expired, revoked, downgraded, or cross-bound artifacts.
pub fn validate_authorization_chain(
    identity: &VerifiedIdentityContextV1,
    intent: &SecurityIntentV1,
    decision: &PolicyDecisionV1,
    grant: &EnforcementGrantV1,
    command: &IsolationCommandV1,
    current_revocation_epoch: u64,
    at: &str,
) -> Result<(), ValidationError> {
    identity.validate()?;
    intent.validate()?;
    decision.validate()?;
    grant.validate()?;
    command.validate()?;
    timestamp("at", at)?;
    if identity.revocation_epoch != current_revocation_epoch {
        return Err(ValidationError::new(
            "revocation_epoch",
            "identity authority epoch has advanced",
        ));
    }
    validate_links(identity, intent, decision, grant, command)?;
    if intent.binding != decision.binding
        || intent.binding != grant.binding
        || intent.binding != command.binding
    {
        return Err(ValidationError::new(
            "binding",
            "audience, resource, and action must match exactly",
        ));
    }
    if decision.effect != DecisionEffect::Permit {
        return Err(ValidationError::new(
            "decision.effect",
            "a deny decision cannot mint enforcement",
        ));
    }
    if !identity.assurance.meets(decision.required_assurance)
        || grant.assurance != identity.assurance
    {
        return Err(ValidationError::new(
            "assurance",
            "verified assurance does not satisfy the chain",
        ));
    }
    if grant.policy_digest != decision.policy_digest {
        return Err(ValidationError::new(
            "policy_digest",
            "grant is not bound to the decision policy",
        ));
    }
    if intent.jti == grant.jti || intent.jti == command.jti || grant.jti == command.jti {
        return Err(ValidationError::new(
            "jti",
            "artifact JTIs must be distinct",
        ));
    }
    let current = valid_at(&identity.authenticated_at, &identity.expires_at, at)
        && valid_at(&intent.requested_at, &intent.expires_at, at)
        && valid_at(&decision.issued_at, &decision.expires_at, at)
        && valid_at(&grant.issued_at, &grant.expires_at, at)
        && valid_at(&command.issued_at, &command.expires_at, at);
    if !current {
        return Err(ValidationError::new(
            "at",
            "authorization chain is not current",
        ));
    }
    let nested = contained(
        &identity.authenticated_at,
        &identity.expires_at,
        &intent.requested_at,
        &intent.expires_at,
    ) && contained(
        &intent.requested_at,
        &intent.expires_at,
        &decision.issued_at,
        &decision.expires_at,
    ) && contained(
        &decision.issued_at,
        &decision.expires_at,
        &grant.issued_at,
        &grant.expires_at,
    ) && contained(
        &grant.issued_at,
        &grant.expires_at,
        &command.issued_at,
        &command.expires_at,
    );
    if nested {
        Ok(())
    } else {
        Err(ValidationError::new(
            "expires_at",
            "child validity must stay inside its parent",
        ))
    }
}

fn contained(parent_start: &str, parent_end: &str, child_start: &str, child_end: &str) -> bool {
    unix_millis(parent_start)
        .zip(unix_millis(parent_end))
        .zip(unix_millis(child_start))
        .zip(unix_millis(child_end))
        .is_some_and(|(((parent_start, parent_end), child_start), child_end)| {
            parent_start <= child_start && child_end <= parent_end
        })
}
