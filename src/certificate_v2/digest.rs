use sha2::{Digest, Sha256};

pub trait CertificatePayloadV2 {
    /// Returns the domain-separated bytes covered by the bare SHA-256 digest.
    #[must_use]
    fn certificate_signing_payload(&self) -> Vec<u8>;

    #[must_use]
    fn certificate_digest_sha256(&self) -> String {
        format!("{:x}", Sha256::digest(self.certificate_signing_payload()))
    }
}

pub(crate) struct DigestBuilder(Vec<u8>);

impl DigestBuilder {
    pub(crate) fn new(domain: &str) -> Self {
        let mut value = Self(Vec::new());
        value.text(domain);
        value
    }

    pub(crate) fn text(&mut self, value: &str) {
        self.0
            .extend_from_slice(&u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
        self.0.extend_from_slice(value.as_bytes());
    }

    pub(crate) fn optional(&mut self, value: Option<&str>) {
        self.0.push(u8::from(value.is_some()));
        if let Some(value) = value {
            self.text(value);
        }
    }

    pub(crate) fn number(&mut self, value: u64) {
        self.0.extend_from_slice(&value.to_be_bytes());
    }

    pub(crate) fn optional_number(&mut self, value: Option<u64>) {
        self.0.push(u8::from(value.is_some()));
        if let Some(value) = value {
            self.number(value);
        }
    }

    pub(crate) fn boolean(&mut self, value: bool) {
        self.0.push(u8::from(value));
    }

    pub(crate) fn bytes(&mut self, value: &[u8]) {
        self.0
            .extend_from_slice(&u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
        self.0.extend_from_slice(value);
    }

    pub(crate) fn finish(self) -> Vec<u8> {
        self.0
    }
}
