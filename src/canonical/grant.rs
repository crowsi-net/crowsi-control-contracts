use crate::EnforcementGrantV1;

use super::{CanonicalPayloadV1, Encoder, assurance, binding, claimed};

impl CanonicalPayloadV1 for EnforcementGrantV1 {
    fn signing_payload(&self) -> Vec<u8> {
        let mut value = Encoder::new("enforcement-grant-v1");
        value.text("schema", &self.schema);
        value.text("grant_id", &self.grant_id);
        value.text("jti", &self.jti);
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
        binding(&mut value, &self.binding);
        value.text("assurance", assurance(self.assurance));
        value.text("issued_at", &self.issued_at);
        value.text("expires_at", &self.expires_at);
        value.number("use_limit", u64::from(self.use_limit));
        value.text("policy_digest", &self.policy_digest);
        value.finish()
    }

    fn claimed_payload_digest(&self) -> &str {
        claimed(&self.signed)
    }
}
