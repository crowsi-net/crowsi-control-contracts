use crowsi_control_contracts::{
    CanonicalPayloadV1, ENFORCEMENT_RECEIPT_SCHEMA_V1, EnforcementOutcome, EnforcementReceiptV1,
};

use super::common::{binding, digest, signed};
use crowsi_control_contracts::ControlAction;

pub fn receipt_fixture() -> EnforcementReceiptV1 {
    let mut value = EnforcementReceiptV1 {
        schema: ENFORCEMENT_RECEIPT_SCHEMA_V1.to_owned(),
        receipt_id: "receipt.1".to_owned(),
        command_jti: "jti.command.1".to_owned(),
        enforcement_grant_jti: "jti.grant.1".to_owned(),
        binding: binding(ControlAction::Quarantine),
        provider: "crowsi-enforcer-incus".to_owned(),
        outcome: EnforcementOutcome::Applied,
        grant_consumed: true,
        applied_at: "2026-08-01T00:01:40.000Z".to_owned(),
        resulting_resource_version: Some("incus-etag-8".to_owned()),
        residual_exposures: Vec::new(),
        evidence_digest: digest(),
        signed: signed(),
    };
    value.signed.digest = value.payload_digest();
    value
}
