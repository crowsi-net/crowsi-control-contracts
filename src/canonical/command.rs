use crate::IsolationCommandV1;

use super::{CanonicalPayloadV1, Encoder, binding, claimed};

impl CanonicalPayloadV1 for IsolationCommandV1 {
    fn signing_payload(&self) -> Vec<u8> {
        let mut value = Encoder::new("isolation-command-v1");
        value.text("schema", &self.schema);
        value.text("command_id", &self.command_id);
        value.text("jti", &self.jti);
        value.text("enforcement_grant_jti", &self.enforcement_grant_jti);
        value.text("decision_id", &self.decision_id);
        value.text("pairwise_subject", &self.pairwise_subject);
        value.text("actor", &self.actor);
        value.text("device", &self.device);
        value.text("workload", &self.workload);
        value.text("profile", &self.profile);
        value.text("proof_key_ref", &self.proof_key_ref);
        value.number("revocation_epoch", self.revocation_epoch);
        binding(&mut value, &self.binding);
        value.text("provider", &self.provider);
        value.text("expected_resource_version", &self.expected_resource_version);
        value.text("issued_at", &self.issued_at);
        value.text("expires_at", &self.expires_at);
        value.finish()
    }

    fn claimed_payload_digest(&self) -> &str {
        claimed(&self.signed)
    }
}
