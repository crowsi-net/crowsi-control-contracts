use crate::{
    Validate, ValidationError,
    certificate_v2::{
        CertificateDeploymentBindingV2, CertificateIdentityBindingV2,
        CertificateRevocationBindingV2,
        digest::DigestBuilder,
        rules::{bare_digest, id},
    },
};

impl Validate for CertificateDeploymentBindingV2 {
    fn validate(&self) -> Result<(), ValidationError> {
        for (field, value) in [
            ("security_domain", self.security_domain.as_str()),
            ("deployment_id", &self.deployment_id),
            ("release_id", &self.release_id),
            ("checkpoint_id", &self.checkpoint_id),
            ("deployment_provenance_ref", &self.deployment_provenance_ref),
        ] {
            id(field, value)?;
        }
        bare_digest("release_digest_sha256", &self.release_digest_sha256)?;
        bare_digest("checkpoint_digest_sha256", &self.checkpoint_digest_sha256)?;
        if self.checkpoint_sequence == 0 || self.trust_revision == 0 {
            return Err(ValidationError::new(
                "deployment_revision",
                "checkpoint sequence and trust revision must be positive",
            ));
        }
        Ok(())
    }
}

impl CertificateDeploymentBindingV2 {
    pub(crate) fn add_to_digest(&self, out: &mut DigestBuilder) {
        for value in [
            &self.security_domain,
            &self.deployment_id,
            &self.release_id,
            &self.release_digest_sha256,
            &self.checkpoint_id,
            &self.checkpoint_digest_sha256,
        ] {
            out.text(value);
        }
        out.number(self.checkpoint_sequence);
        out.text(&self.deployment_provenance_ref);
        out.number(self.trust_revision);
    }
}

impl CertificateRevocationBindingV2 {
    pub(crate) fn validate_for(
        &self,
        identity: &CertificateIdentityBindingV2,
    ) -> Result<(), ValidationError> {
        id("revocation.snapshot_id", &self.snapshot_id)?;
        bare_digest(
            "revocation.snapshot_digest_sha256",
            &self.snapshot_digest_sha256,
        )?;
        if !self.authoritative
            || self.previous_identity_revocation_epoch > self.snapshot_epoch
            || self.snapshot_epoch != identity.identity_revocation_epoch
        {
            return Err(ValidationError::new(
                "revocation",
                "snapshot must be authoritative and match the identity epoch",
            ));
        }
        Ok(())
    }

    pub(crate) fn add_to_digest(&self, out: &mut DigestBuilder) {
        out.text(&self.snapshot_id);
        out.text(&self.snapshot_digest_sha256);
        out.number(self.previous_identity_revocation_epoch);
        out.number(self.snapshot_epoch);
        out.number(self.snapshot_verified_at_epoch_s);
        out.boolean(self.authoritative);
    }
}
