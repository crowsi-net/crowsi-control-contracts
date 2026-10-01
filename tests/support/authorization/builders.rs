use crowsi_control_contracts::{
    ActionBindingV1, AssuranceLevel, DecisionEffect, ENFORCEMENT_GRANT_SCHEMA_V1,
    EnforcementGrantV1, ISOLATION_COMMAND_SCHEMA_V1, IsolationCommandV1, POLICY_DECISION_SCHEMA_V1,
    PolicyDecisionV1, SECURITY_INTENT_SCHEMA_V1, SecurityIntentV1,
    VERIFIED_IDENTITY_CONTEXT_SCHEMA_V1, VerifiedIdentityContextV1,
};

use super::super::common::{digest, signed};

pub(super) fn identity(assurance: AssuranceLevel) -> VerifiedIdentityContextV1 {
    VerifiedIdentityContextV1 {
        schema: VERIFIED_IDENTITY_CONTEXT_SCHEMA_V1.to_owned(),
        context_id: "ctx.1".to_owned(),
        issuer: "https://identity.example.test".to_owned(),
        pairwise_subject: "pairwise-subject-a".to_owned(),
        actor: "user-a".to_owned(),
        device: "device-a".to_owned(),
        workload: "spiffe://crowsi.local/hatter/session-a".to_owned(),
        profile: "profile-private".to_owned(),
        proof_key_ref: "jkt:proof-key-a".to_owned(),
        assurance,
        authorization_grant_id: "identity-grant-a".to_owned(),
        revocation_epoch: 7,
        authenticated_at: "2026-08-01T00:00:00.000Z".to_owned(),
        expires_at: "2026-08-01T00:10:00.000Z".to_owned(),
        audience: "crowsi-control-plane".to_owned(),
        signed: signed(),
    }
}

pub(super) fn intent(
    identity: &VerifiedIdentityContextV1,
    binding: ActionBindingV1,
) -> SecurityIntentV1 {
    SecurityIntentV1 {
        schema: SECURITY_INTENT_SCHEMA_V1.to_owned(),
        intent_id: "intent.1".to_owned(),
        jti: "jti.intent.1".to_owned(),
        identity_context_id: identity.context_id.clone(),
        pairwise_subject: identity.pairwise_subject.clone(),
        actor: identity.actor.clone(),
        device: identity.device.clone(),
        workload: identity.workload.clone(),
        profile: identity.profile.clone(),
        proof_key_ref: identity.proof_key_ref.clone(),
        revocation_epoch: identity.revocation_epoch,
        binding,
        requested_at: "2026-08-01T00:01:00.000Z".to_owned(),
        expires_at: "2026-08-01T00:05:00.000Z".to_owned(),
        reason: "contain a confirmed incident".to_owned(),
        signed: signed(),
    }
}

pub(super) fn decision(
    identity: &VerifiedIdentityContextV1,
    intent: &SecurityIntentV1,
    binding: ActionBindingV1,
) -> PolicyDecisionV1 {
    PolicyDecisionV1 {
        schema: POLICY_DECISION_SCHEMA_V1.to_owned(),
        decision_id: "decision.1".to_owned(),
        intent_jti: intent.jti.clone(),
        identity_context_id: identity.context_id.clone(),
        pairwise_subject: identity.pairwise_subject.clone(),
        actor: identity.actor.clone(),
        device: identity.device.clone(),
        workload: identity.workload.clone(),
        profile: identity.profile.clone(),
        proof_key_ref: identity.proof_key_ref.clone(),
        revocation_epoch: identity.revocation_epoch,
        effect: DecisionEffect::Permit,
        binding,
        required_assurance: intent.binding.action.required_assurance(),
        issued_at: "2026-08-01T00:01:10.000Z".to_owned(),
        expires_at: "2026-08-01T00:04:30.000Z".to_owned(),
        policy_digest: digest(),
        signed: signed(),
    }
}

pub(super) fn grant(
    identity: &VerifiedIdentityContextV1,
    intent: &SecurityIntentV1,
    decision: &PolicyDecisionV1,
    binding: ActionBindingV1,
) -> EnforcementGrantV1 {
    EnforcementGrantV1 {
        schema: ENFORCEMENT_GRANT_SCHEMA_V1.to_owned(),
        grant_id: "grant.1".to_owned(),
        jti: "jti.grant.1".to_owned(),
        decision_id: decision.decision_id.clone(),
        intent_jti: intent.jti.clone(),
        identity_context_id: identity.context_id.clone(),
        pairwise_subject: identity.pairwise_subject.clone(),
        actor: identity.actor.clone(),
        device: identity.device.clone(),
        workload: identity.workload.clone(),
        profile: identity.profile.clone(),
        proof_key_ref: identity.proof_key_ref.clone(),
        revocation_epoch: identity.revocation_epoch,
        binding,
        assurance: identity.assurance,
        issued_at: "2026-08-01T00:01:20.000Z".to_owned(),
        expires_at: "2026-08-01T00:03:20.000Z".to_owned(),
        use_limit: 1,
        policy_digest: decision.policy_digest.clone(),
        signed: signed(),
    }
}

pub(super) fn command(
    identity: &VerifiedIdentityContextV1,
    decision: &PolicyDecisionV1,
    grant: &EnforcementGrantV1,
    binding: ActionBindingV1,
) -> IsolationCommandV1 {
    IsolationCommandV1 {
        schema: ISOLATION_COMMAND_SCHEMA_V1.to_owned(),
        command_id: "command.1".to_owned(),
        jti: "jti.command.1".to_owned(),
        enforcement_grant_jti: grant.jti.clone(),
        decision_id: decision.decision_id.clone(),
        pairwise_subject: identity.pairwise_subject.clone(),
        actor: identity.actor.clone(),
        device: identity.device.clone(),
        workload: identity.workload.clone(),
        profile: identity.profile.clone(),
        proof_key_ref: identity.proof_key_ref.clone(),
        revocation_epoch: identity.revocation_epoch,
        binding,
        provider: "crowsi-enforcer-incus".to_owned(),
        expected_resource_version: "incus-etag-7".to_owned(),
        issued_at: "2026-08-01T00:01:30.000Z".to_owned(),
        expires_at: "2026-08-01T00:02:30.000Z".to_owned(),
        signed: signed(),
    }
}
