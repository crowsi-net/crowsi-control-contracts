use sha2::{Digest, Sha256};

use crate::certificate_v2::digest::DigestBuilder;

/// Computes the signed proof binding raw provider input to one canonical target.
#[must_use]
pub fn certificate_target_normalization_digest_v2(
    provider: &str,
    raw_provider_scoped_target: &str,
    canonical_target_resource_id: &str,
    normalizer_id: &str,
    normalizer_version: &str,
) -> String {
    let mut payload = DigestBuilder::new("crowsi-certificate-target-normalization-v2");
    for value in [
        provider,
        raw_provider_scoped_target,
        canonical_target_resource_id,
        normalizer_id,
        normalizer_version,
    ] {
        payload.text(value);
    }
    format!("{:x}", Sha256::digest(payload.finish()))
}
