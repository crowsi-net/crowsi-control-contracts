use crate::{
    IncidentAssertionV1, ManagementAuthorityAssertionV1, PolicyAuthorityState, PolicyIncidentState,
    PolicyInformationSnapshotV1, PolicyPostureState, PostureAssertionV1,
};

use super::{CanonicalPayloadV1, Encoder, binding, claimed};

impl CanonicalPayloadV1 for PolicyInformationSnapshotV1 {
    fn signing_payload(&self) -> Vec<u8> {
        let mut value = Encoder::new("policy-information-snapshot-v1");
        value.text("schema", &self.schema);
        value.text("snapshot_id", &self.snapshot_id);
        value.text("identity_context_id", &self.identity_context_id);
        value.text("pairwise_subject", &self.pairwise_subject);
        posture(&mut value, "device_posture", &self.device_posture);
        posture(&mut value, "workload_posture", &self.workload_posture);
        incident(&mut value, &self.incident);
        authority(&mut value, &self.management_authority);
        value.number(
            "authoritative_revocation_epoch",
            self.authoritative_revocation_epoch,
        );
        value.number("risk_score", u64::from(self.risk_score));
        value.text("coverage_assertion_id", &self.coverage_assertion_id);
        value.text("coverage_digest", &self.coverage_digest);
        value.text("policy_digest", &self.policy_digest);
        value.text("issued_at", &self.issued_at);
        value.text("expires_at", &self.expires_at);
        value.finish()
    }

    fn claimed_payload_digest(&self) -> &str {
        claimed(&self.signed)
    }
}

fn posture(encoder: &mut Encoder, prefix: &str, value: &PostureAssertionV1) {
    encoder.text(&format!("{prefix}.target"), &value.target);
    encoder.text(&format!("{prefix}.state"), posture_state(value.state));
    encoder.text(&format!("{prefix}.observed_at"), &value.observed_at);
    encoder.text(&format!("{prefix}.valid_until"), &value.valid_until);
}

fn incident(encoder: &mut Encoder, value: &IncidentAssertionV1) {
    encoder.text("incident.incident_id", &value.incident_id);
    encoder.text("incident.resource", &value.resource);
    encoder.text("incident.state", incident_state(value.state));
    encoder.text("incident.observed_at", &value.observed_at);
    encoder.text("incident.valid_until", &value.valid_until);
}

fn authority(encoder: &mut Encoder, value: &ManagementAuthorityAssertionV1) {
    encoder.text("management_authority.state", authority_state(value.state));
    encoder.text(
        "management_authority.identity_context_id",
        &value.identity_context_id,
    );
    encoder.text(
        "management_authority.authorization_grant_id",
        &value.authorization_grant_id,
    );
    encoder.number(
        "management_authority.revocation_epoch",
        value.revocation_epoch,
    );
    binding(encoder, &value.binding);
    encoder.text("management_authority.observed_at", &value.observed_at);
    encoder.text("management_authority.valid_until", &value.valid_until);
}

const fn posture_state(value: PolicyPostureState) -> &'static str {
    match value {
        PolicyPostureState::Trusted => "trusted",
        PolicyPostureState::Untrusted => "untrusted",
        PolicyPostureState::Unknown => "unknown",
    }
}

const fn authority_state(value: PolicyAuthorityState) -> &'static str {
    match value {
        PolicyAuthorityState::Authorized => "authorized",
        PolicyAuthorityState::Denied => "denied",
        PolicyAuthorityState::Unknown => "unknown",
    }
}

const fn incident_state(value: PolicyIncidentState) -> &'static str {
    match value {
        PolicyIncidentState::Normal => "normal",
        PolicyIncidentState::Detected => "detected",
        PolicyIncidentState::ContainmentRequested => "containment-requested",
        PolicyIncidentState::Contained => "contained",
        PolicyIncidentState::RecoveryPending => "recovery-pending",
        PolicyIncidentState::RecoveryAuthorized => "recovery-authorized",
        PolicyIncidentState::Restoring => "restoring",
        PolicyIncidentState::Monitoring => "monitoring",
        PolicyIncidentState::Closed => "closed",
        PolicyIncidentState::Unknown => "unknown",
    }
}
