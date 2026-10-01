mod builders;

use crowsi_control_contracts::{
    AssuranceLevel, CanonicalPayloadV1, ControlAction, EnforcementGrantV1, IsolationCommandV1,
    PolicyDecisionV1, SecurityIntentV1, VerifiedIdentityContextV1,
};

use super::common::binding;

pub struct AuthorizationFixture {
    pub identity: VerifiedIdentityContextV1,
    pub intent: SecurityIntentV1,
    pub decision: PolicyDecisionV1,
    pub grant: EnforcementGrantV1,
    pub command: IsolationCommandV1,
}

pub fn authorization_fixture(
    action: ControlAction,
    assurance: AssuranceLevel,
) -> AuthorizationFixture {
    let binding = binding(action);
    let mut identity = builders::identity(assurance);
    identity.signed.digest = identity.payload_digest();
    let mut intent = builders::intent(&identity, binding.clone());
    intent.signed.digest = intent.payload_digest();
    let mut decision = builders::decision(&identity, &intent, binding.clone());
    decision.signed.digest = decision.payload_digest();
    let mut grant = builders::grant(&identity, &intent, &decision, binding.clone());
    grant.signed.digest = grant.payload_digest();
    let mut command = builders::command(&identity, &decision, &grant, binding);
    command.signed.digest = command.payload_digest();
    AuthorizationFixture {
        identity,
        intent,
        decision,
        grant,
        command,
    }
}
