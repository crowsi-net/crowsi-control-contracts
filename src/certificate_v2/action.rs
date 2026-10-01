use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CertificateActionV2 {
    Issue,
    Renew,
    Revoke,
    CertificateStatus,
    OperationStatus,
    ReconcileUnknown,
}

impl CertificateActionV2 {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Issue => "issue",
            Self::Renew => "renew",
            Self::Revoke => "revoke",
            Self::CertificateStatus => "certificate-status",
            Self::OperationStatus => "operation-status",
            Self::ReconcileUnknown => "reconcile-unknown",
        }
    }

    #[must_use]
    pub const fn requires_separation_of_duties(self) -> bool {
        matches!(
            self,
            Self::Issue | Self::Renew | Self::Revoke | Self::ReconcileUnknown
        )
    }

    #[must_use]
    pub const fn fence_scope(self) -> &'static str {
        match self {
            Self::CertificateStatus => "certificate-status",
            Self::OperationStatus => "operation-status",
            Self::ReconcileUnknown => "reconciliation",
            Self::Issue | Self::Renew | Self::Revoke => "lifecycle-mutation",
        }
    }
}
