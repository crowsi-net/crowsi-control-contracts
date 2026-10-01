use std::{collections::BTreeSet, fs, path::Path};

use crowsi_control_contracts::SPIFFE_WORKLOAD_SCHEMA_PATTERN;
use serde_json::Value;

const CONTRACTS: [(&str, &str); 6] = [
    ("identity.rs", "verified-identity-context-v1.schema.json"),
    ("intent.rs", "security-intent-v1.schema.json"),
    ("decision.rs", "policy-decision-v1.schema.json"),
    ("grant.rs", "enforcement-grant-v1.schema.json"),
    ("command.rs", "isolation-command-v1.schema.json"),
    ("command_v2.rs", "isolation-command-v2.schema.json"),
];

#[test]
fn every_rust_workload_field_uses_the_shared_validator() {
    let source_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let actual = workload_sources(&source_root);
    let expected = CONTRACTS
        .iter()
        .map(|(source, _)| (*source).to_owned())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        actual, expected,
        "new workload fields require shared validation"
    );
    for (source, _) in CONTRACTS {
        let text = fs::read_to_string(source_root.join(source)).expect("contract source");
        assert!(
            text.contains("spiffe_workload(\"workload\", &self.workload)?;"),
            "{source} bypasses the common workload validator"
        );
    }
}

#[test]
fn every_workload_schema_references_the_same_closed_definition() {
    let schema_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("schemas");
    let actual = workload_schemas(&schema_root);
    let expected = CONTRACTS
        .iter()
        .map(|(_, schema)| (*schema).to_owned())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        actual, expected,
        "new workload schemas require the shared definition"
    );
    for (_, schema) in CONTRACTS {
        let text = fs::read_to_string(schema_root.join(schema)).expect("schema source");
        let value: Value = serde_json::from_str(&text).expect("schema JSON");
        assert_eq!(
            value["properties"]["workload"]["$ref"], "#/$defs/workload",
            "{schema}"
        );
        assert_eq!(
            value["$defs"]["workload"]["pattern"], SPIFFE_WORKLOAD_SCHEMA_PATTERN,
            "{schema}"
        );
        assert_eq!(value["$defs"]["workload"]["maxLength"], 256, "{schema}");
    }
}

fn workload_schemas(root: &Path) -> BTreeSet<String> {
    fs::read_dir(root)
        .expect("schema directory")
        .filter_map(Result::ok)
        .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "json"))
        .filter_map(|entry| {
            let text = fs::read_to_string(entry.path()).ok()?;
            let value: Value = serde_json::from_str(&text).ok()?;
            (!value["properties"]["workload"].is_null())
                .then(|| entry.file_name().to_string_lossy().into_owned())
        })
        .collect()
}

fn workload_sources(root: &Path) -> BTreeSet<String> {
    fs::read_dir(root)
        .expect("source directory")
        .filter_map(Result::ok)
        .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "rs"))
        .filter_map(|entry| {
            let text = fs::read_to_string(entry.path()).ok()?;
            text.contains("pub workload: String")
                .then(|| entry.file_name().to_string_lossy().into_owned())
        })
        .collect()
}
