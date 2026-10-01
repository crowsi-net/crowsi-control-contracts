use crate::{DecisionEffect, PolicyDecisionV1};

use super::{CanonicalPayloadV1, Encoder, assurance, binding, claimed};

impl CanonicalPayloadV1 for PolicyDecisionV1 {
    fn signing_payload(&self) -> Vec<u8> {
        let mut value = Encoder::new("policy-decision-v1");
        value.text("schema", &self.schema);
        value.text("decision_id", &self.decision_id);
        value.text("intent_jti", &self.intent_jti);
        value.text("identity_context_id", &self.identity_context_id);
        value.text("pairwise_subject", &self.pairwise_subject);
        value.text("actor", &self.actor);
        value.text("device", &self.device);
        value.text("workload", &self.workload);
        value.text("profile", &self.profile);
        value.text("proof_key_ref", &self.proof_key_ref);
        value.number("revocation_epoch", self.revocation_epoch);
        value.text(
            "effect",
            match self.effect {
                DecisionEffect::Permit => "permit",
                DecisionEffect::Deny => "deny",
            },
        );
        binding(&mut value, &self.binding);
        value.text("required_assurance", assurance(self.required_assurance));
        value.text("issued_at", &self.issued_at);
        value.text("expires_at", &self.expires_at);
        value.text("policy_digest", &self.policy_digest);
        value.finish()
    }

    fn claimed_payload_digest(&self) -> &str {
        claimed(&self.signed)
    }
}
