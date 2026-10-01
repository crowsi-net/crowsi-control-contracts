use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CertificateLifecycleActionV2 {
    Issue,
    Renew,
    Revoke,
}

impl CertificateLifecycleActionV2 {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Issue => "issue",
            Self::Renew => "renew",
            Self::Revoke => "revoke",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum CertificateOperationBindingV2 {
    OperationStatus {
        target_operation_id: String,
    },
    ReconcileUnknown {
        original_action: CertificateLifecycleActionV2,
        target_operation_id: String,
        lifecycle_reservation_id: String,
        authority_command_digest_sha256: String,
        unknown_evidence_digest_sha256: String,
        locked_previous_fence: u64,
        locked_current_fence: u64,
        locked_previous_lifecycle_revocation_epoch: u64,
        locked_lifecycle_revocation_epoch: u64,
    },
}

impl CertificateOperationBindingV2 {
    pub(crate) fn original_action(&self) -> Option<CertificateLifecycleActionV2> {
        match self {
            Self::OperationStatus { .. } => None,
            Self::ReconcileUnknown {
                original_action, ..
            } => Some(*original_action),
        }
    }

    pub(crate) fn target_operation_id(&self) -> &str {
        match self {
            Self::OperationStatus {
                target_operation_id,
            }
            | Self::ReconcileUnknown {
                target_operation_id,
                ..
            } => target_operation_id,
        }
    }

    pub(crate) fn lifecycle_reservation_id(&self) -> Option<&str> {
        match self {
            Self::OperationStatus { .. } => None,
            Self::ReconcileUnknown {
                lifecycle_reservation_id,
                ..
            } => Some(lifecycle_reservation_id),
        }
    }

    pub(crate) fn authority_command_digest_sha256(&self) -> Option<&str> {
        match self {
            Self::OperationStatus { .. } => None,
            Self::ReconcileUnknown {
                authority_command_digest_sha256,
                ..
            } => Some(authority_command_digest_sha256),
        }
    }

    pub(crate) fn unknown_evidence_digest_sha256(&self) -> Option<&str> {
        match self {
            Self::OperationStatus { .. } => None,
            Self::ReconcileUnknown {
                unknown_evidence_digest_sha256,
                ..
            } => Some(unknown_evidence_digest_sha256),
        }
    }

    pub(crate) fn locked_fences(&self) -> (Option<u64>, Option<u64>) {
        match self {
            Self::OperationStatus { .. } => (None, None),
            Self::ReconcileUnknown {
                locked_previous_fence,
                locked_current_fence,
                ..
            } => (Some(*locked_previous_fence), Some(*locked_current_fence)),
        }
    }

    pub(crate) fn locked_lifecycle_revocation_epochs(&self) -> (Option<u64>, Option<u64>) {
        match self {
            Self::OperationStatus { .. } => (None, None),
            Self::ReconcileUnknown {
                locked_previous_lifecycle_revocation_epoch,
                locked_lifecycle_revocation_epoch,
                ..
            } => (
                Some(*locked_previous_lifecycle_revocation_epoch),
                Some(*locked_lifecycle_revocation_epoch),
            ),
        }
    }
}
