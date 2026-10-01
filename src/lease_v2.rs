use serde::{Deserialize, Serialize};

use crate::{
    CanonicalPayloadV1, IsolationCommandV2, PEP_EXECUTION_LEASE_SCHEMA_V2,
    validation::{Validate, ValidationError, digest, identifier, schema, timestamp},
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PepExecutionLeaseV2 {
    pub schema: String,
    pub reservation_id: String,
    pub command: IsolationCommandV2,
    pub command_digest: String,
    pub reserved_at: String,
}

impl Validate for PepExecutionLeaseV2 {
    fn validate(&self) -> Result<(), ValidationError> {
        schema(&self.schema, PEP_EXECUTION_LEASE_SCHEMA_V2)?;
        identifier("reservation_id", &self.reservation_id)?;
        digest("command_digest", &self.command_digest)?;
        timestamp("reserved_at", &self.reserved_at)?;
        self.command.validate()?;
        let exact = self.reservation_id == self.command.release_reservation_id
            && self.command_digest == self.command.payload_digest()
            && self.command.issued_at.as_str() <= self.reserved_at.as_str()
            && self.reserved_at.as_str() < self.command.expires_at.as_str();
        if exact {
            Ok(())
        } else {
            Err(ValidationError::new(
                "lease_binding",
                "reservation, command digest, and validity must match",
            ))
        }
    }
}
