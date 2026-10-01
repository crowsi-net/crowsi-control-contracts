mod support;

use crowsi_control_contracts::{CanonicalPayloadV1, EnforcementOutcome, Validate};

use support::receipt_fixture;

#[test]
fn applied_receipt_is_an_executor_claim_with_consumed_grant() {
    let receipt = receipt_fixture();
    assert!(receipt.validate().is_ok());
    assert!(receipt.grant_consumed);
}

#[test]
fn unconsumed_grant_and_false_applied_claims_are_rejected() {
    let mut unconsumed = receipt_fixture();
    unconsumed.grant_consumed = false;
    unconsumed.signed.digest = unconsumed.payload_digest();
    assert!(unconsumed.validate().is_err());
    let mut exposed = receipt_fixture();
    exposed
        .residual_exposures
        .push("public ingress remains".to_owned());
    exposed.signed.digest = exposed.payload_digest();
    assert!(exposed.validate().is_err());
}

#[test]
fn partial_receipt_must_name_residual_exposure() {
    let mut partial = receipt_fixture();
    partial.outcome = EnforcementOutcome::Partial;
    partial.resulting_resource_version = None;
    partial.signed.digest = partial.payload_digest();
    assert!(partial.validate().is_err());
    partial
        .residual_exposures
        .push("provider firewall update pending".to_owned());
    partial.signed.digest = partial.payload_digest();
    assert!(partial.validate().is_ok());
}
