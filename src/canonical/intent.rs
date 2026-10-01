use crate::SecurityIntentV1;

use super::{CanonicalPayloadV1, Encoder, binding, claimed};

impl CanonicalPayloadV1 for SecurityIntentV1 {
    fn signing_payload(&self) -> Vec<u8> {
        let mut value = Encoder::new("security-intent-v1");
        value.text("schema", &self.schema);
        value.text("intent_id", &self.intent_id);
        value.text("jti", &self.jti);
        value.text("identity_context_id", &self.identity_context_id);
        value.text("pairwise_subject", &self.pairwise_subject);
        value.text("actor", &self.actor);
        value.text("device", &self.device);
        value.text("workload", &self.workload);
        value.text("profile", &self.profile);
        value.text("proof_key_ref", &self.proof_key_ref);
        value.number("revocation_epoch", self.revocation_epoch);
        binding(&mut value, &self.binding);
        value.text("requested_at", &self.requested_at);
        value.text("expires_at", &self.expires_at);
        value.text("reason", &self.reason);
        value.finish()
    }

    fn claimed_payload_digest(&self) -> &str {
        claimed(&self.signed)
    }
}
