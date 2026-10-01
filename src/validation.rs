use std::{error::Error, fmt};

use crate::time::{normalized_utc, unix_millis};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationError {
    field: &'static str,
    reason: &'static str,
}

impl ValidationError {
    #[must_use]
    pub const fn new(field: &'static str, reason: &'static str) -> Self {
        Self { field, reason }
    }
}

impl fmt::Display for ValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.field, self.reason)
    }
}

impl Error for ValidationError {}

pub trait Validate {
    /// Validates the closed representation and local invariants.
    ///
    /// # Errors
    ///
    /// Returns the first stable field-level contract error.
    fn validate(&self) -> Result<(), ValidationError>;
}

pub(crate) fn schema(actual: &str, expected: &'static str) -> Result<(), ValidationError> {
    if actual == expected {
        Ok(())
    } else {
        Err(ValidationError::new("schema", "unsupported schema"))
    }
}

pub(crate) fn identifier(field: &'static str, value: &str) -> Result<(), ValidationError> {
    let valid = !value.is_empty()
        && value.len() <= 128
        && value.starts_with(|character: char| character.is_ascii_lowercase())
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._:-".contains(&byte)
        });
    if valid {
        Ok(())
    } else {
        Err(ValidationError::new(field, "must be a closed identifier"))
    }
}

pub(crate) fn opaque(
    field: &'static str,
    value: &str,
    maximum: usize,
) -> Result<(), ValidationError> {
    if !value.is_empty()
        && value.len() <= maximum
        && !value.chars().any(char::is_control)
        && value.trim() == value
    {
        Ok(())
    } else {
        Err(ValidationError::new(field, "must be bounded opaque text"))
    }
}

pub(crate) fn https_uri(field: &'static str, value: &str) -> Result<(), ValidationError> {
    opaque(field, value, 512)?;
    if value.starts_with("https://") {
        Ok(())
    } else {
        Err(ValidationError::new(field, "must be an HTTPS URI"))
    }
}

pub(crate) fn timestamp(field: &'static str, value: &str) -> Result<(), ValidationError> {
    if normalized_utc(value) {
        Ok(())
    } else {
        Err(ValidationError::new(
            field,
            "must use normalized UTC milliseconds",
        ))
    }
}

pub(crate) fn short_window(
    start_field: &'static str,
    start: &str,
    end: &str,
    maximum_millis: i64,
) -> Result<(), ValidationError> {
    timestamp(start_field, start)?;
    timestamp("expires_at", end)?;
    let window = unix_millis(end)
        .zip(unix_millis(start))
        .map(|(expires, issued)| expires - issued);
    if window.is_some_and(|value| value > 0 && value <= maximum_millis) {
        Ok(())
    } else {
        Err(ValidationError::new(
            "expires_at",
            "invalid or excessive TTL",
        ))
    }
}

pub(crate) fn digest(field: &'static str, value: &str) -> Result<(), ValidationError> {
    let valid = value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase());
    if valid {
        Ok(())
    } else {
        Err(ValidationError::new(
            field,
            "must be a lowercase SHA-256 digest",
        ))
    }
}

pub(crate) fn signature(field: &'static str, value: &str) -> Result<(), ValidationError> {
    let valid = (43..=2048).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_".contains(&byte));
    if valid {
        Ok(())
    } else {
        Err(ValidationError::new(field, "must be unpadded base64url"))
    }
}

pub(crate) fn valid_at(start: &str, end: &str, at: &str) -> bool {
    unix_millis(start)
        .zip(unix_millis(end))
        .zip(unix_millis(at))
        .is_some_and(|((start, end), at)| start <= at && at < end)
}
