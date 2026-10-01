mod authority;
mod handoff;
mod manager;

use base64::{Engine, engine::general_purpose::STANDARD};
use crowsi_control_contracts::{
    CertificateReceiptSignatureAlgorithmV2, CertificateReceiptSignatureV2,
};

pub use authority::authority_evidence;
pub use handoff::handoff_evidence;
pub use manager::manager_commit_evidence;

pub(super) fn placeholder(
    key_id: &str,
    version: &str,
    spki: &str,
    purpose: &str,
) -> CertificateReceiptSignatureV2 {
    CertificateReceiptSignatureV2 {
        key_id: key_id.into(),
        key_version: version.into(),
        public_key_spki_sha256: spki.into(),
        key_purpose: purpose.into(),
        algorithm: CertificateReceiptSignatureAlgorithmV2::EcdsaP256Sha256P1363LowS,
        digest_sha256: "00".repeat(32),
        signature_base64: STANDARD.encode([0_u8; 64]),
    }
}
