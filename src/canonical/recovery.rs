use crate::RecoveryAuthorizationV1;

use super::{CanonicalPayloadV1, Encoder, binding, claimed};

impl CanonicalPayloadV1 for RecoveryAuthorizationV1 {
    fn signing_payload(&self) -> Vec<u8> {
        let mut value = Encoder::new("recovery-authorization-v1");
        value.text("schema", &self.schema);
        value.text("authorization_id", &self.authorization_id);
        value.text("jti", &self.jti);
        value.text("identity_context_id", &self.identity_context_id);
        value.text("pairwise_subject", &self.pairwise_subject);
        binding(&mut value, &self.binding);
        value.text("incident_id", &self.incident_id);
        value.text("policy_snapshot_id", &self.policy_snapshot_id);
        value.text("policy_snapshot_digest", &self.policy_snapshot_digest);
        value.number(
            "authoritative_revocation_epoch",
            self.authoritative_revocation_epoch,
        );
        value.text("issued_at", &self.issued_at);
        value.text("expires_at", &self.expires_at);
        value.number("use_limit", u64::from(self.use_limit));
        value.finish()
    }

    fn claimed_payload_digest(&self) -> &str {
        claimed(&self.signed)
    }
}
