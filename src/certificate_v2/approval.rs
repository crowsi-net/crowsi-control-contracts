use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CertificateApprovalMethodV2 {
    AuthenticatedSession,
    LocalUserPresence,
    HardwareBackedUserPresence,
}

impl CertificateApprovalMethodV2 {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AuthenticatedSession => "authenticated-session",
            Self::LocalUserPresence => "local-user-presence",
            Self::HardwareBackedUserPresence => "hardware-backed-user-presence",
        }
    }

    pub(crate) const fn proves_user_presence(self) -> bool {
        matches!(
            self,
            Self::LocalUserPresence | Self::HardwareBackedUserPresence
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CertificateApprovalAssuranceV2 {
    Aal2,
    Aal3,
}

impl CertificateApprovalAssuranceV2 {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Aal2 => "aal2",
            Self::Aal3 => "aal3",
        }
    }
}
