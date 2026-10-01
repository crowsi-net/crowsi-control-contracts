use crowsi_control_contracts::{
    ActionBindingV1, ControlAction, ControlChannel, SignatureAlgorithm, SignedDigestV1,
};

pub fn digest() -> String {
    format!("sha256:{}", "a".repeat(64))
}

pub fn signed() -> SignedDigestV1 {
    SignedDigestV1 {
        algorithm: SignatureAlgorithm::Ed25519,
        key_id: "key.control.1".to_owned(),
        digest: digest(),
        signature: "a".repeat(86),
    }
}

pub fn binding(action: ControlAction) -> ActionBindingV1 {
    ActionBindingV1 {
        audience: "crowsi-enforcer-incus".to_owned(),
        resource: "incus://project/default/instance/worker-a".to_owned(),
        action,
        purpose: "incident-containment".to_owned(),
        channel: ControlChannel::EmergencyConsole,
    }
}
