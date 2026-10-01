use crate::{
    ValidationError,
    certificate_v2::{
        CertificateActionV2, CertificateIdentityBindingV2,
        digest::DigestBuilder,
        rules::{id, workload},
    },
};

impl CertificateIdentityBindingV2 {
    pub(crate) fn validate_for(&self, action: CertificateActionV2) -> Result<(), ValidationError> {
        for (field, value) in [
            ("pairwise_subject", self.pairwise_subject.as_str()),
            (
                "requester_pairwise_subject",
                &self.requester_pairwise_subject,
            ),
            ("requester_actor", &self.requester_actor),
            ("requester_device", &self.requester_device),
            ("requester_profile", &self.requester_profile),
            ("requester_proof_key_ref", &self.requester_proof_key_ref),
        ] {
            id(field, value)?;
        }
        workload("workload", &self.workload)?;
        let approver = match (
            self.approver_pairwise_subject.as_deref(),
            self.approver_actor.as_deref(),
            self.approver_device.as_deref(),
            self.approver_profile.as_deref(),
            self.approver_proof_key_ref.as_deref(),
        ) {
            (Some(subject), Some(actor), Some(device), Some(profile), Some(proof)) => {
                for (field, value) in [
                    ("approver_pairwise_subject", subject),
                    ("approver_actor", actor),
                    ("approver_device", device),
                    ("approver_profile", profile),
                    ("approver_proof_key_ref", proof),
                ] {
                    id(field, value)?;
                }
                Some(subject)
            }
            (None, None, None, None, None) => None,
            _ => {
                return Err(ValidationError::new(
                    "approver_identity",
                    "approver fields must be wholly present or absent",
                ));
            }
        };
        match (action.requires_separation_of_duties(), approver) {
            (true, Some(subject)) if subject != self.requester_pairwise_subject => Ok(()),
            (false, None) => Ok(()),
            _ => Err(ValidationError::new(
                "separation_of_duties",
                "mutations require a distinct approver; reads require none",
            )),
        }
    }

    pub(crate) fn add_to_digest(&self, out: &mut DigestBuilder) {
        for value in [
            &self.pairwise_subject,
            &self.requester_pairwise_subject,
            &self.requester_actor,
            &self.requester_device,
            &self.requester_profile,
            &self.requester_proof_key_ref,
            &self.workload,
        ] {
            out.text(value);
        }
        match (
            self.approver_pairwise_subject.as_deref(),
            self.approver_actor.as_deref(),
            self.approver_device.as_deref(),
            self.approver_profile.as_deref(),
            self.approver_proof_key_ref.as_deref(),
        ) {
            (Some(subject), Some(actor), Some(device), Some(profile), Some(proof)) => {
                for value in [subject, actor, device, profile, proof] {
                    out.text(value);
                }
            }
            _ => out.text("approver-absent"),
        }
        out.number(self.identity_revocation_epoch);
    }
}
