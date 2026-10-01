use crate::VerifiedIdentityContextV1;

use super::{CanonicalPayloadV1, Encoder, assurance, claimed};

impl CanonicalPayloadV1 for VerifiedIdentityContextV1 {
    fn signing_payload(&self) -> Vec<u8> {
        let mut value = Encoder::new("verified-identity-context-v1");
        value.text("schema", &self.schema);
        value.text("context_id", &self.context_id);
        value.text("issuer", &self.issuer);
        value.text("pairwise_subject", &self.pairwise_subject);
        value.text("actor", &self.actor);
        value.text("device", &self.device);
        value.text("workload", &self.workload);
        value.text("profile", &self.profile);
        value.text("proof_key_ref", &self.proof_key_ref);
        value.text("assurance", assurance(self.assurance));
        value.text("authorization_grant_id", &self.authorization_grant_id);
        value.number("revocation_epoch", self.revocation_epoch);
        value.text("authenticated_at", &self.authenticated_at);
        value.text("expires_at", &self.expires_at);
        value.text("audience", &self.audience);
        value.finish()
    }

    fn claimed_payload_digest(&self) -> &str {
        claimed(&self.signed)
    }
}
