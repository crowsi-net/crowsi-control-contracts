use crate::validation::{ValidationError, opaque};

const MAX_WORKLOAD_ID_BYTES: usize = 256;
const MAX_TRUST_DOMAIN_BYTES: usize = 253;
const MAX_LABEL_BYTES: usize = 63;
const MAX_PATH_SEGMENT_BYTES: usize = 64;

pub const SPIFFE_WORKLOAD_SCHEMA_PATTERN: &str = concat!(
    "^spiffe://",
    "[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?",
    "(?:\\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*",
    "/[A-Za-z0-9_-][A-Za-z0-9._-]{0,63}",
    "(?:/[A-Za-z0-9_-][A-Za-z0-9._-]{0,63})*$"
);

/// Validates the canonical workload identity accepted by every control contract.
///
/// # Errors
///
/// Rejects non-SPIFFE, ambiguous, non-canonical, or oversized identities.
pub fn validate_spiffe_workload(value: &str) -> Result<(), ValidationError> {
    spiffe_workload("workload", value)
}

pub(crate) fn spiffe_workload(field: &'static str, value: &str) -> Result<(), ValidationError> {
    opaque(field, value, MAX_WORKLOAD_ID_BYTES)?;
    let remainder = value
        .strip_prefix("spiffe://")
        .ok_or_else(|| invalid(field))?;
    let (trust_domain, path) = remainder.split_once('/').ok_or_else(|| invalid(field))?;
    if !valid_trust_domain(trust_domain) || !valid_path(path) {
        return Err(invalid(field));
    }
    Ok(())
}

fn valid_trust_domain(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_TRUST_DOMAIN_BYTES && value.split('.').all(valid_label)
}

fn valid_label(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= MAX_LABEL_BYTES
        && bytes.first().is_some_and(u8::is_ascii_alphanumeric)
        && bytes.last().is_some_and(u8::is_ascii_alphanumeric)
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
}

fn valid_path(value: &str) -> bool {
    !value.is_empty() && value.split('/').all(valid_segment)
}

fn valid_segment(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= MAX_PATH_SEGMENT_BYTES
        && bytes
            .first()
            .is_some_and(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(byte))
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(byte))
}

const fn invalid(field: &'static str) -> ValidationError {
    ValidationError::new(field, "must be a canonical SPIFFE workload ID")
}
