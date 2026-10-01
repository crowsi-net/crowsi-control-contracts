use serde::{Deserialize, Serialize};

use crate::validation::{Validate, ValidationError, digest, identifier, opaque, signature};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AssuranceLevel {
    Baseline,
    PhishingResistant,
    HardwareBoundStepUp,
}

impl AssuranceLevel {
    #[must_use]
    pub const fn meets(self, required: Self) -> bool {
        self as u8 >= required as u8
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ControlAction {
    Quarantine,
    RestrictEgress,
    RevokeAccess,
    Restore,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ControlChannel {
    HatterInteractive,
    EmergencyConsole,
    ServiceAutomation,
}

impl ControlAction {
    #[must_use]
    pub const fn required_assurance(self) -> AssuranceLevel {
        match self {
            Self::Restore => AssuranceLevel::HardwareBoundStepUp,
            Self::Quarantine | Self::RestrictEgress | Self::RevokeAccess => {
                AssuranceLevel::PhishingResistant
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionBindingV1 {
    pub audience: String,
    pub resource: String,
    pub action: ControlAction,
    pub purpose: String,
    pub channel: ControlChannel,
}

impl Validate for ActionBindingV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        identifier("binding.audience", &self.audience)?;
        opaque("binding.resource", &self.resource, 256)?;
        identifier("binding.purpose", &self.purpose)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SignatureAlgorithm {
    Ed25519,
    EcdsaP256Sha256,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedDigestV1 {
    pub algorithm: SignatureAlgorithm,
    pub key_id: String,
    pub digest: String,
    pub signature: String,
}

impl Validate for SignedDigestV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        identifier("signed.key_id", &self.key_id)?;
        digest("signed.digest", &self.digest)?;
        signature("signed.signature", &self.signature)
    }
}
