use crowsi_control_contracts::*;

pub fn certificate_chain(
    action: CertificateActionV2,
) -> (
    CertificatePolicyDecisionV2,
    CertificateExecutionGrantV2,
    CertificateExecutionCommandV2,
) {
    let binding = super::certificate_binding::binding(action);
    let mut decision = CertificatePolicyDecisionV2 {
        schema: CERTIFICATE_POLICY_DECISION_SCHEMA_V2.into(),
        decision_id: "decision.certificate.0001".into(),
        request_digest_sha256: "10".repeat(32),
        action,
        binding: binding.clone(),
        effect: CertificateDecisionEffectV2::Permit,
        issued_at_epoch_s: 9_950,
        expires_at_epoch_s: 10_200,
        signed: signature("decision.key.0001"),
    };
    decision.signed.digest_sha256 = decision.certificate_digest_sha256();
    let mut grant = CertificateExecutionGrantV2 {
        schema: CERTIFICATE_EXECUTION_GRANT_SCHEMA_V2.into(),
        grant_id: "grant.certificate.0001".into(),
        jti: "grant.jti.certificate.0001".into(),
        decision_id: decision.decision_id.clone(),
        decision_digest_sha256: decision.certificate_digest_sha256(),
        request_digest_sha256: decision.request_digest_sha256.clone(),
        action,
        binding: binding.clone(),
        issued_at_epoch_s: 9_960,
        expires_at_epoch_s: 10_070,
        use_limit: 1,
        signed: signature("grant.key.0001"),
    };
    grant.signed.digest_sha256 = grant.certificate_digest_sha256();
    let relation = matches!(
        action,
        CertificateActionV2::OperationStatus | CertificateActionV2::ReconcileUnknown
    )
    .then(|| "authorization.related.0001".into());
    let command = CertificateExecutionCommandV2 {
        schema: CERTIFICATE_EXECUTION_COMMAND_SCHEMA_V2.into(),
        authorization_id: "authorization.certificate.0001".into(),
        jti: "authorization.jti.0001".into(),
        pa_reservation_id: "pa.reservation.certificate.0001".into(),
        operation_id: "operation.certificate.0001".into(),
        request_digest_sha256: decision.request_digest_sha256.clone(),
        action,
        binding,
        decision_id: decision.decision_id.clone(),
        decision_digest_sha256: decision.certificate_digest_sha256(),
        grant_id: grant.grant_id.clone(),
        grant_digest_sha256: grant.certificate_digest_sha256(),
        signature_key_id: "key.policy.administrator".into(),
        signature_key_version: "version.0001".into(),
        signature_public_key_spki_sha256: "44".repeat(32),
        signature_key_purpose: "certificate-execution-authorization".into(),
        signature_algorithm: CertificateSignatureAlgorithmV2::Ed25519,
        related_authorization_jti: relation,
        issued_at_epoch_s: 9_970,
        expires_at_epoch_s: 10_050,
        one_use: true,
    };
    (decision, grant, command)
}

fn signature(key_id: &str) -> CertificateDetachedSignatureV2 {
    CertificateDetachedSignatureV2 {
        key_id: key_id.into(),
        algorithm: CertificateSignatureAlgorithmV2::Ed25519,
        digest_sha256: "00".repeat(32),
        signature_base64: "c2lnbmF0dXJl".into(),
    }
}
