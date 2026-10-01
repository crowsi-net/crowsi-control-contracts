use crate::{
    Validate, ValidationError,
    certificate_v2::{
        CertificateActionV2, CertificateTargetBindingV2,
        digest::DigestBuilder,
        rules::{bare_digest, id},
    },
};

impl Validate for CertificateTargetBindingV2 {
    fn validate(&self) -> Result<(), ValidationError> {
        id("service_id", &self.service_id)?;
        id("provider", &self.provider)?;
        id("target_resource_id", &self.target_resource_id)?;
        id(
            "target_resource_normalizer_id",
            &self.target_resource_normalizer_id,
        )?;
        id(
            "target_resource_normalizer_version",
            &self.target_resource_normalizer_version,
        )?;
        bare_digest(
            "target_resource_normalization_digest_sha256",
            &self.target_resource_normalization_digest_sha256,
        )?;
        self.target_resource_normalization_verified
            .then_some(())
            .ok_or(ValidationError::new(
                "target_resource_normalization_verified",
                "PA normalization verification is required",
            ))
    }
}

impl CertificateTargetBindingV2 {
    pub(crate) fn validate_for(&self, action: CertificateActionV2) -> Result<(), ValidationError> {
        self.validate()?;
        let fence_valid = match action {
            CertificateActionV2::CertificateStatus | CertificateActionV2::OperationStatus => {
                self.previous_fence == self.current_fence
            }
            CertificateActionV2::Issue
            | CertificateActionV2::Renew
            | CertificateActionV2::Revoke
            | CertificateActionV2::ReconcileUnknown => {
                self.previous_fence.checked_add(1) == Some(self.current_fence)
            }
        };
        if !fence_valid {
            return Err(ValidationError::new(
                "current_fence",
                "does not match the action-specific fence transition",
            ));
        }
        if !self.valid_lifecycle(action) {
            return Err(ValidationError::new(
                "lifecycle_revocation_epoch",
                "does not match the certificate action transition",
            ));
        }
        let safe_version = match action {
            CertificateActionV2::Issue => self.expected_resource_version == 0,
            CertificateActionV2::Renew | CertificateActionV2::Revoke => {
                (1..u64::MAX).contains(&self.expected_resource_version)
            }
            CertificateActionV2::ReconcileUnknown
            | CertificateActionV2::CertificateStatus
            | CertificateActionV2::OperationStatus => true,
        };
        safe_version.then_some(()).ok_or(ValidationError::new(
            "expected_resource_version",
            "is invalid for the authorized certificate action",
        ))
    }

    fn valid_lifecycle(&self, action: CertificateActionV2) -> bool {
        match action {
            CertificateActionV2::Issue => {
                self.previous_lifecycle_revocation_epoch == 0
                    && self.lifecycle_revocation_epoch == 0
            }
            CertificateActionV2::Revoke => {
                self.previous_lifecycle_revocation_epoch.checked_add(1)
                    == Some(self.lifecycle_revocation_epoch)
            }
            CertificateActionV2::Renew
            | CertificateActionV2::CertificateStatus
            | CertificateActionV2::OperationStatus => {
                self.previous_lifecycle_revocation_epoch == self.lifecycle_revocation_epoch
            }
            CertificateActionV2::ReconcileUnknown => true,
        }
    }

    pub(crate) fn add_to_digest(&self, out: &mut DigestBuilder) {
        for value in [
            &self.service_id,
            &self.provider,
            &self.target_resource_id,
            &self.target_resource_normalizer_id,
            &self.target_resource_normalizer_version,
            &self.target_resource_normalization_digest_sha256,
        ] {
            out.text(value);
        }
        out.boolean(self.target_resource_normalization_verified);
        for value in [
            self.previous_fence,
            self.current_fence,
            self.expected_resource_version,
            self.previous_lifecycle_revocation_epoch,
            self.lifecycle_revocation_epoch,
        ] {
            out.number(value);
        }
    }
}
