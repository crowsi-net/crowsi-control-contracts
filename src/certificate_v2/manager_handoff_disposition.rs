use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CertificateManagerHandoffDispositionV2 {
    Accepted,
    NotAccepted,
}

impl CertificateManagerHandoffDispositionV2 {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::NotAccepted => "not-accepted",
        }
    }
}
