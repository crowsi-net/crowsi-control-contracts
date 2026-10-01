use crate::{
    Validate, ValidationError,
    certificate_v2::{
        CertificateActionV2, CertificateAuthorizationBindingV2, CertificateOperationBindingV2,
        authorization_rules,
        digest::DigestBuilder,
        rules::{bare_digest, id},
    },
};

impl CertificateAuthorizationBindingV2 {
    pub(crate) fn validate_for(&self, action: CertificateActionV2) -> Result<(), ValidationError> {
        for (field, value) in [
            ("issuer", self.issuer.as_str()),
            ("audience", &self.audience),
            ("channel", &self.channel),
            ("policy_id", &self.policy_id),
        ] {
            id(field, value)?;
        }
        bare_digest("policy_digest_sha256", &self.policy_digest_sha256)?;
        self.identity.validate_for(action)?;
        self.deployment.validate()?;
        self.revocation.validate_for(&self.identity)?;
        self.target.validate_for(action)?;
        CertificateOperationBindingV2::validate_for(action, self.operation.as_ref())?;
        authorization_rules::validate_approval(self, action)?;
        authorization_rules::validate_reconciliation(self, action)
    }

    pub(crate) fn add_to_digest(&self, out: &mut DigestBuilder) {
        for value in [
            &self.issuer,
            &self.audience,
            &self.channel,
            &self.policy_id,
            &self.policy_digest_sha256,
        ] {
            out.text(value);
        }
        match (
            self.approval_id.as_deref(),
            self.approval_evidence_digest_sha256.as_deref(),
            self.approval_method,
            self.approval_assurance,
            self.approval_issued_at_epoch_s,
            self.approval_expires_at_epoch_s,
            self.approval_verified_at_epoch_s,
        ) {
            (
                Some(id),
                Some(digest),
                Some(method),
                Some(assurance),
                Some(issued),
                Some(expires),
                Some(verified),
            ) => {
                for value in [id, digest, method.as_str(), assurance.as_str()] {
                    out.text(value);
                }
                for value in [issued, expires, verified] {
                    out.number(value);
                }
            }
            _ => out.text("approval-absent"),
        }
        self.identity.add_to_digest(out);
        self.deployment.add_to_digest(out);
        self.revocation.add_to_digest(out);
        self.target.add_to_digest(out);
        CertificateOperationBindingV2::add_optional_to_digest(self.operation.as_ref(), out);
    }
}
