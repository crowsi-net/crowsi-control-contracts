use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

use crate::{ValidationError, validate_spiffe_workload};

pub(crate) fn id(field: &'static str, value: &str) -> Result<(), ValidationError> {
    let valid = (8..=256).contains(&value.len())
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'-')
        });
    valid.then_some(()).ok_or(ValidationError::new(
        field,
        "must be a bounded protocol identifier",
    ))
}

pub(crate) fn version(field: &'static str, value: &str) -> Result<(), ValidationError> {
    let valid = (8..=160).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'));
    valid.then_some(()).ok_or(ValidationError::new(
        field,
        "must be a canonical printable version token",
    ))
}

pub(crate) fn workload(field: &'static str, value: &str) -> Result<(), ValidationError> {
    validate_spiffe_workload(value).map_err(|_| {
        ValidationError::new(
            field,
            "must be a canonical, bounded SPIFFE workload identifier",
        )
    })
}

pub(crate) fn bare_digest(field: &'static str, value: &str) -> Result<(), ValidationError> {
    let valid = value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'));
    valid.then_some(()).ok_or(ValidationError::new(
        field,
        "must be a bare lowercase SHA-256 digest",
    ))
}

pub(crate) fn encoded(
    field: &'static str,
    value: &str,
    maximum: usize,
) -> Result<(), ValidationError> {
    let valid = !value.is_empty()
        && value.len() <= maximum
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'-' | b'_' | b'=')
        });
    valid
        .then_some(())
        .ok_or(ValidationError::new(field, "must be bounded base64 text"))
}

pub(crate) fn canonical_nonce(
    field: &'static str,
    value: &str,
    minimum_bytes: usize,
    maximum_bytes: usize,
) -> Result<(), ValidationError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| ValidationError::new(field, "must be canonical base64url without padding"))?;
    let valid = (minimum_bytes..=maximum_bytes).contains(&bytes.len())
        && URL_SAFE_NO_PAD.encode(&bytes) == value;
    valid.then_some(()).ok_or(ValidationError::new(
        field,
        "must carry sufficient canonical nonce entropy",
    ))
}

pub(crate) fn epoch_window(
    issued: u64,
    expires: u64,
    maximum_seconds: u64,
) -> Result<(), ValidationError> {
    (issued < expires && expires - issued <= maximum_seconds)
        .then_some(())
        .ok_or(ValidationError::new(
            "expires_at_epoch_s",
            "invalid or excessive TTL",
        ))
}

pub(crate) fn current(issued: u64, expires: u64, now: u64) -> bool {
    issued <= now && now < expires
}

pub(crate) fn child_window(
    parent_issued: u64,
    parent_expires: u64,
    child_issued: u64,
    child_expires: u64,
) -> bool {
    parent_issued <= child_issued && child_expires <= parent_expires
}
