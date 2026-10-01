mod command;
mod command_v2;
mod coverage;
mod decision;
mod grant;
mod identity;
mod intent;
mod policy_information;
mod receipt;
mod receipt_v2;
mod recovery;

use sha2::{Digest, Sha256};

use crate::{
    ActionBindingV1, AssuranceLevel, ControlAction, ControlChannel, SignedDigestV1, ValidationError,
};

const DOMAIN: &[u8] = b"crowsi-control-canonical-v1\0";

pub trait CanonicalPayloadV1 {
    /// Returns the versioned, length-prefixed payload covered by `signed.digest`.
    #[must_use]
    fn signing_payload(&self) -> Vec<u8>;

    #[doc(hidden)]
    fn claimed_payload_digest(&self) -> &str;

    #[must_use]
    fn payload_digest(&self) -> String {
        let hash = Sha256::digest(self.signing_payload());
        let alphabet = b"0123456789abcdef";
        let mut value = String::with_capacity(71);
        value.push_str("sha256:");
        for byte in hash {
            value.push(alphabet[usize::from(byte >> 4)] as char);
            value.push(alphabet[usize::from(byte & 0x0f)] as char);
        }
        value
    }

    #[must_use]
    fn payload_digest_matches(&self) -> bool {
        self.payload_digest() == self.claimed_payload_digest()
    }

    /// Verifies that the claimed digest covers the current artifact fields.
    ///
    /// # Errors
    ///
    /// Returns an error when any covered field differs from the claimed digest.
    fn validate_payload_digest(&self) -> Result<(), ValidationError> {
        if self.payload_digest_matches() {
            Ok(())
        } else {
            Err(ValidationError::new(
                "signed.digest",
                "does not cover the canonical payload",
            ))
        }
    }
}

struct Encoder {
    bytes: Vec<u8>,
}

impl Encoder {
    fn new(artifact: &str) -> Self {
        let mut value = Self {
            bytes: DOMAIN.to_vec(),
        };
        value.text("artifact", artifact);
        value
    }

    fn text(&mut self, name: &str, value: &str) {
        self.bytes(name, value.as_bytes());
    }

    fn number(&mut self, name: &str, value: u64) {
        self.bytes(name, &value.to_be_bytes());
    }

    fn boolean(&mut self, name: &str, value: bool) {
        self.bytes(name, &[u8::from(value)]);
    }

    fn optional_text(&mut self, name: &str, value: Option<&str>) {
        self.boolean(&format!("{name}.present"), value.is_some());
        if let Some(value) = value {
            self.text(name, value);
        }
    }

    fn strings(&mut self, name: &str, values: &[String]) {
        self.number(&format!("{name}.count"), values.len() as u64);
        for (index, value) in values.iter().enumerate() {
            self.text(&format!("{name}.{index}"), value);
        }
    }

    fn bytes(&mut self, name: &str, value: &[u8]) {
        let name = name.as_bytes();
        let name_length = u16::try_from(name.len()).expect("canonical field name fits u16");
        let value_length = u64::try_from(value.len()).expect("canonical field value fits u64");
        self.bytes.extend_from_slice(&name_length.to_be_bytes());
        self.bytes.extend_from_slice(name);
        self.bytes.extend_from_slice(&value_length.to_be_bytes());
        self.bytes.extend_from_slice(value);
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

fn binding(encoder: &mut Encoder, value: &ActionBindingV1) {
    encoder.text("binding.audience", &value.audience);
    encoder.text("binding.resource", &value.resource);
    encoder.text("binding.action", action(value.action));
    encoder.text("binding.purpose", &value.purpose);
    encoder.text("binding.channel", channel(value.channel));
}

const fn assurance(value: AssuranceLevel) -> &'static str {
    match value {
        AssuranceLevel::Baseline => "baseline",
        AssuranceLevel::PhishingResistant => "phishing-resistant",
        AssuranceLevel::HardwareBoundStepUp => "hardware-bound-step-up",
    }
}

const fn action(value: ControlAction) -> &'static str {
    match value {
        ControlAction::Quarantine => "quarantine",
        ControlAction::RestrictEgress => "restrict-egress",
        ControlAction::RevokeAccess => "revoke-access",
        ControlAction::Restore => "restore",
    }
}

const fn channel(value: ControlChannel) -> &'static str {
    match value {
        ControlChannel::HatterInteractive => "hatter-interactive",
        ControlChannel::EmergencyConsole => "emergency-console",
        ControlChannel::ServiceAutomation => "service-automation",
    }
}

fn claimed(value: &SignedDigestV1) -> &str {
    &value.digest
}
