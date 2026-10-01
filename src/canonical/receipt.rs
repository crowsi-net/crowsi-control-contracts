use crate::{EnforcementOutcome, EnforcementReceiptV1};

use super::{CanonicalPayloadV1, Encoder, binding, claimed};

impl CanonicalPayloadV1 for EnforcementReceiptV1 {
    fn signing_payload(&self) -> Vec<u8> {
        let mut value = Encoder::new("enforcement-receipt-v1");
        value.text("schema", &self.schema);
        value.text("receipt_id", &self.receipt_id);
        value.text("command_jti", &self.command_jti);
        value.text("enforcement_grant_jti", &self.enforcement_grant_jti);
        binding(&mut value, &self.binding);
        value.text("provider", &self.provider);
        value.text(
            "outcome",
            match self.outcome {
                EnforcementOutcome::Applied => "applied",
                EnforcementOutcome::Rejected => "rejected",
                EnforcementOutcome::Failed => "failed",
                EnforcementOutcome::Partial => "partial",
            },
        );
        value.boolean("grant_consumed", self.grant_consumed);
        value.text("applied_at", &self.applied_at);
        value.optional_text(
            "resulting_resource_version",
            self.resulting_resource_version.as_deref(),
        );
        value.strings("residual_exposures", &self.residual_exposures);
        value.text("evidence_digest", &self.evidence_digest);
        value.finish()
    }

    fn claimed_payload_digest(&self) -> &str {
        claimed(&self.signed)
    }
}
