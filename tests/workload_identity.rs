use crowsi_control_contracts::validate_spiffe_workload;

#[test]
fn accepts_closed_spiffe_workload_ids() {
    for value in [
        "spiffe://example.org/service/hatter",
        "spiffe://a/workload_1",
        "spiffe://trust-domain.example/Team-A/process.v2",
    ] {
        validate_spiffe_workload(value).expect(value);
    }
}

#[test]
fn rejects_ambiguous_or_unsafe_spiffe_workload_ids() {
    for value in [
        "",
        "workload-a",
        "spiffe://Example.org/service",
        "spiffe://-example.org/service",
        "spiffe://example-.org/service",
        "spiffe://example..org/service",
        "spiffe://example.org",
        "spiffe://example.org/",
        "spiffe://example.org/service//worker",
        "spiffe://example.org/./worker",
        "spiffe://example.org/../worker",
        "spiffe://example.org/.hidden",
        "spiffe://user@example.org/service",
        "spiffe://example.org:443/service",
        "spiffe://example.org/service%2fworker",
        "spiffe://example.org/service?role=worker",
        "spiffe://example.org/service#worker",
        "spiffe://example.org/service worker",
    ] {
        assert!(validate_spiffe_workload(value).is_err(), "{value}");
    }
}

#[test]
fn enforces_global_domain_and_segment_bounds() {
    let oversized_id = format!("spiffe://example.org/{}", "a".repeat(245));
    let oversized_label = format!("spiffe://{}.org/service", "a".repeat(64));
    let oversized_segment = format!("spiffe://example.org/{}", "a".repeat(65));
    assert!(validate_spiffe_workload(&oversized_id).is_err());
    assert!(validate_spiffe_workload(&oversized_label).is_err());
    assert!(validate_spiffe_workload(&oversized_segment).is_err());
}
