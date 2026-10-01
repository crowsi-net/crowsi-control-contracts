use base64::{Engine, engine::general_purpose::STANDARD};

use crate::{
    Validate, ValidationError,
    certificate_v2::{
        CertificateExecutionLeaseV2, CertificatePayloadV2, CertificateSignatureAlgorithmV2,
        SignedCertificateExecutionAuthorizationV2, VerifiedCertificateExecutionAuthorizationV2,
        rules::encoded,
    },
};

pub trait CertificateLeaseSignatureVerifierV2 {
    /// Verifies the detached PA signature over the bare lease digest.
    fn verify_lease_digest(
        &self,
        key_id: &str,
        algorithm: CertificateSignatureAlgorithmV2,
        lease_digest_sha256: &str,
        signature_base64: &str,
    ) -> bool;
}

/// Packages an already-produced detached signature with the canonical lease.
///
/// # Errors
///
/// Rejects an invalid lease, signature encoding, or serialization failure.
pub fn package_signed_certificate_authorization_v2(
    lease: &CertificateExecutionLeaseV2,
    signature_base64: &str,
) -> Result<SignedCertificateExecutionAuthorizationV2, ValidationError> {
    lease.validate()?;
    encoded("signature_base64", signature_base64, 16_384)?;
    let payload = serde_json::to_vec(lease)
        .map_err(|_| ValidationError::new("pa_pep_lease", "serialization failed"))?;
    let value = SignedCertificateExecutionAuthorizationV2::new(
        &lease.command.signature_key_id,
        STANDARD.encode(payload),
        lease.certificate_digest_sha256(),
        signature_base64,
    );
    value.validate()?;
    Ok(value)
}

/// Decodes, structurally validates, and cryptographically gates manager claims.
///
/// # Errors
///
/// Rejects non-canonical base64, unknown JSON fields, digest drift, or signature
/// verification failure. The returned shape matches the certificate manager's
/// `VerifiedCertificateExecutionAuthorizationV2`.
pub fn verify_signed_certificate_authorization_v2<V: CertificateLeaseSignatureVerifierV2>(
    signed: &SignedCertificateExecutionAuthorizationV2,
    verifier: &V,
) -> Result<VerifiedCertificateExecutionAuthorizationV2, ValidationError> {
    signed.validate()?;
    let bytes = STANDARD.decode(signed.pa_pep_lease_base64()).map_err(|_| {
        ValidationError::new("pa_pep_lease_base64", "must use canonical standard base64")
    })?;
    if STANDARD.encode(&bytes) != signed.pa_pep_lease_base64() {
        return Err(ValidationError::new(
            "pa_pep_lease_base64",
            "must use canonical standard base64",
        ));
    }
    let lease: CertificateExecutionLeaseV2 = serde_json::from_slice(&bytes)
        .map_err(|_| ValidationError::new("pa_pep_lease", "closed lease decoding failed"))?;
    lease.validate()?;
    let digest = lease.certificate_digest_sha256();
    let command = &lease.command;
    let exact = digest == signed.lease_digest_sha256()
        && command.signature_key_id == signed.verifier_key_id();
    if !exact
        || !verifier.verify_lease_digest(
            signed.verifier_key_id(),
            command.signature_algorithm,
            &digest,
            signed.signature_base64(),
        )
    {
        return Err(ValidationError::new(
            "authorization_signature",
            "lease digest, key, or signature was rejected",
        ));
    }
    Ok(VerifiedCertificateExecutionAuthorizationV2::from_lease(
        &lease,
    ))
}
