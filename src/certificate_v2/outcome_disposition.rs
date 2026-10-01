use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CertificateExecutionDispositionV2 {
    Completed,
    NotExecuted,
    StillUnknown,
}

impl CertificateExecutionDispositionV2 {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::NotExecuted => "not-executed",
            Self::StillUnknown => "still-unknown",
        }
    }
}
