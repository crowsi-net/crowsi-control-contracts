#![doc = "Pure, closed Zero Trust control contracts for Crowsi."]

mod canonical;
mod certificate_v2;
mod chain;
mod chain_v2;
mod command;
mod command_v2;
mod common;
mod coverage;
mod decision;
mod grant;
mod identity;
mod intent;
mod lease_v2;
mod policy_information;
mod readiness;
mod receipt;
mod receipt_v2;
mod recovery;
mod snapshot_context;
mod time;
mod validation;
mod workload;

pub use canonical::CanonicalPayloadV1;
pub use certificate_v2::{
    CertificateActionV2, CertificateApprovalAssuranceV2, CertificateApprovalEvidenceV2,
    CertificateApprovalMethodV2, CertificateAuthorityOutcomeEvidenceV2,
    CertificateAuthorizationBindingV2, CertificateDecisionEffectV2, CertificateDeploymentBindingV2,
    CertificateDetachedSignatureV2, CertificateExecutionCommandV2,
    CertificateExecutionDispositionV2, CertificateExecutionGrantV2, CertificateExecutionLeaseV2,
    CertificateIdentityBindingV2, CertificateLeaseSignatureVerifierV2,
    CertificateLifecycleActionV2, CertificateManagerCommitEvidenceV2,
    CertificateManagerHandoffDispositionV2, CertificateManagerHandoffEvidenceV2,
    CertificateOperationBindingV2, CertificatePayloadV2, CertificatePolicyDecisionV2,
    CertificateReceiptSignatureAlgorithmV2, CertificateReceiptSignatureV2,
    CertificateRevocationBindingV2, CertificateRevocationEvidenceV2,
    CertificateSignatureAlgorithmV2, CertificateTargetBindingV2,
    SignedCertificateExecutionAuthorizationV2, VerifiedCertificateExecutionAuthorizationV2,
    certificate_target_normalization_digest_v2, package_signed_certificate_authorization_v2,
    validate_certificate_authorization_chain_v2, verify_signed_certificate_authorization_v2,
};
pub use chain::validate_authorization_chain;
pub use chain_v2::validate_authorization_chain_v2;
pub use command::IsolationCommandV1;
pub use command_v2::IsolationCommandV2;
pub use common::{
    ActionBindingV1, AssuranceLevel, ControlAction, ControlChannel, SignatureAlgorithm,
    SignedDigestV1,
};
pub use coverage::{
    CoverageAssertionV1, CoverageLevel, Freshness, Health, Management, Verification,
};
pub use decision::{DecisionEffect, PolicyDecisionV1};
pub use grant::EnforcementGrantV1;
pub use identity::VerifiedIdentityContextV1;
pub use intent::SecurityIntentV1;
pub use lease_v2::PepExecutionLeaseV2;
pub use policy_information::PolicyInformationSnapshotV1;
pub use readiness::{ActionCoverageV1, CapabilityStatus, EnforcementReadiness, ManagementLifeline};
pub use receipt::{EnforcementOutcome, EnforcementReceiptV1};
pub use receipt_v2::EnforcementReceiptV2;
pub use recovery::RecoveryAuthorizationV1;
pub use snapshot_context::{
    IncidentAssertionV1, ManagementAuthorityAssertionV1, PolicyAuthorityState, PolicyIncidentState,
    PolicyPostureState, PostureAssertionV1,
};
pub use validation::{Validate, ValidationError};
pub use workload::{SPIFFE_WORKLOAD_SCHEMA_PATTERN, validate_spiffe_workload};

pub const SECURITY_INTENT_SCHEMA_V1: &str = "crowsi://control/security-intent/v1";
pub const VERIFIED_IDENTITY_CONTEXT_SCHEMA_V1: &str =
    "crowsi://control/verified-identity-context/v1";
pub const POLICY_DECISION_SCHEMA_V1: &str = "crowsi://control/policy-decision/v1";
pub const ENFORCEMENT_GRANT_SCHEMA_V1: &str = "crowsi://control/enforcement-grant/v1";
pub const ISOLATION_COMMAND_SCHEMA_V1: &str = "crowsi://control/isolation-command/v1";
pub const ISOLATION_COMMAND_SCHEMA_V2: &str = "crowsi://control/isolation-command/v2";
pub const PEP_EXECUTION_LEASE_SCHEMA_V2: &str = "crowsi://control/pep-execution-lease/v2";
pub const ENFORCEMENT_RECEIPT_SCHEMA_V1: &str = "crowsi://control/enforcement-receipt/v1";
pub const ENFORCEMENT_RECEIPT_SCHEMA_V2: &str = "crowsi://control/enforcement-receipt/v2";
pub const COVERAGE_ASSERTION_SCHEMA_V1: &str = "crowsi://control/coverage-assertion/v1";
pub const POLICY_INFORMATION_SNAPSHOT_SCHEMA_V1: &str =
    "crowsi://control/policy-information-snapshot/v1";
pub const RECOVERY_AUTHORIZATION_SCHEMA_V1: &str = "crowsi://control/recovery-authorization/v1";
pub const CERTIFICATE_POLICY_DECISION_SCHEMA_V2: &str =
    "crowsi://control/certificate-policy-decision/v2";
pub const CERTIFICATE_EXECUTION_GRANT_SCHEMA_V2: &str =
    "crowsi://control/certificate-execution-grant/v2";
pub const CERTIFICATE_EXECUTION_COMMAND_SCHEMA_V2: &str =
    "crowsi://control/certificate-execution-command/v2";
pub const CERTIFICATE_EXECUTION_LEASE_SCHEMA_V2: &str =
    "crowsi://control/certificate-execution-lease/v2";
pub const SIGNED_CERTIFICATE_EXECUTION_AUTHORIZATION_SCHEMA_V2: &str =
    "crowsi://certificates/execution-authorization/v2";
pub const CERTIFICATE_REVOCATION_EVIDENCE_SCHEMA_V2: &str =
    "crowsi://control/certificate-identity-revocation-evidence/v2";
pub const CERTIFICATE_APPROVAL_EVIDENCE_SCHEMA_V2: &str =
    "crowsi://control/certificate-approval-evidence/v2";
pub const CERTIFICATE_AUTHORITY_OUTCOME_EVIDENCE_SCHEMA_V2: &str =
    "crowsi://control/certificate-authority-outcome-evidence/v2";
pub const CERTIFICATE_MANAGER_COMMIT_EVIDENCE_SCHEMA_V2: &str =
    "crowsi://control/certificate-manager-commit-evidence/v2";
pub const CERTIFICATE_MANAGER_HANDOFF_EVIDENCE_SCHEMA_V2: &str =
    "crowsi://control/certificate-manager-handoff-evidence/v2";
pub const CERTIFICATE_RECEIPT_SIGNATURE_SCHEMA_V2: &str =
    "crowsi://control/certificate-receipt-signature/v2";
