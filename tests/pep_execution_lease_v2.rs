use crowsi_control_contracts::{PEP_EXECUTION_LEASE_SCHEMA_V2, PepExecutionLeaseV2, Validate};

fn lease() -> PepExecutionLeaseV2 {
    let command =
        serde_json::from_str(include_str!("../fixtures/isolation-command-v2.sample.json"))
            .expect("command fixture");
    PepExecutionLeaseV2 {
        schema: PEP_EXECUTION_LEASE_SCHEMA_V2.into(),
        reservation_id: "release-reservation.sample.1".into(),
        command_digest: "sha256:61b5d2b62d62e8d780afae31a150d51b560c42d833a0437f18b497f2d2e27164"
            .into(),
        command,
        reserved_at: "2026-07-29T00:02:00.000Z".into(),
    }
}

#[test]
fn lease_is_the_closed_pa_to_pep_v2_wire_contract() {
    lease().validate().expect("lease");
}

#[test]
fn lease_cannot_substitute_a_reservation_or_command_digest() {
    let mut value = lease();
    value.reservation_id.push_str("-other");
    assert!(value.validate().is_err());
    let mut value = lease();
    value.command_digest = format!("sha256:{}", "f".repeat(64));
    assert!(value.validate().is_err());
}
