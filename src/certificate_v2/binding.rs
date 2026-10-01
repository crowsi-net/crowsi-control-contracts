use serde::{Deserialize, Serialize};

use crate::certificate_v2::{
    approval::{CertificateApprovalAssuranceV2, CertificateApprovalMethodV2},
    operation_binding::CertificateOperationBindingV2,
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CertificateIdentityBindingV2 {
    pub pairwise_subject: String,
    pub requester_pairwise_subject: String,
    pub requester_actor: String,
    pub requester_device: String,
    pub requester_profile: String,
    pub requester_proof_key_ref: String,
    pub approver_pairwise_subject: Option<String>,
    pub approver_actor: Option<String>,
    pub approver_device: Option<String>,
    pub approver_profile: Option<String>,
    pub approver_proof_key_ref: Option<String>,
    pub workload: String,
    pub identity_revocation_epoch: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CertificateDeploymentBindingV2 {
    pub security_domain: String,
    pub deployment_id: String,
    pub release_id: String,
    pub release_digest_sha256: String,
    pub checkpoint_id: String,
    pub checkpoint_digest_sha256: String,
    pub checkpoint_sequence: u64,
    pub deployment_provenance_ref: String,
    pub trust_revision: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CertificateRevocationBindingV2 {
    pub snapshot_id: String,
    pub snapshot_digest_sha256: String,
    pub previous_identity_revocation_epoch: u64,
    pub snapshot_epoch: u64,
    pub snapshot_verified_at_epoch_s: u64,
    pub authoritative: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CertificateTargetBindingV2 {
    pub service_id: String,
    pub provider: String,
    pub target_resource_id: String,
    pub target_resource_normalizer_id: String,
    pub target_resource_normalizer_version: String,
    pub target_resource_normalization_digest_sha256: String,
    pub target_resource_normalization_verified: bool,
    pub previous_fence: u64,
    pub current_fence: u64,
    pub expected_resource_version: u64,
    pub previous_lifecycle_revocation_epoch: u64,
    pub lifecycle_revocation_epoch: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CertificateAuthorizationBindingV2 {
    pub issuer: String,
    pub audience: String,
    pub channel: String,
    pub approval_id: Option<String>,
    pub approval_evidence_digest_sha256: Option<String>,
    pub approval_method: Option<CertificateApprovalMethodV2>,
    pub approval_assurance: Option<CertificateApprovalAssuranceV2>,
    pub approval_issued_at_epoch_s: Option<u64>,
    pub approval_expires_at_epoch_s: Option<u64>,
    pub approval_verified_at_epoch_s: Option<u64>,
    pub policy_id: String,
    pub policy_digest_sha256: String,
    pub identity: CertificateIdentityBindingV2,
    pub deployment: CertificateDeploymentBindingV2,
    pub revocation: CertificateRevocationBindingV2,
    pub target: CertificateTargetBindingV2,
    pub operation: Option<CertificateOperationBindingV2>,
}
