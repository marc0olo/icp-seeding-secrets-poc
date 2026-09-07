//! Candid types on the wire.
//!
//! This interface is a starting proposal for discussion, not a frozen standard.

use candid::CandidType;
use serde::Deserialize;
use serde_bytes::ByteBuf;

/// One stored secret, as reported by `list`. Carries nothing derived from the
/// plaintext: a digest of the plaintext would be an offline guessing oracle for
/// low-entropy secrets, whereas a digest of a randomised ciphertext reveals
/// nothing.
#[derive(CandidType, Deserialize, Debug, Clone)]
pub struct SealedSecretEntry {
    /// The secret's name.
    pub name: String,
    /// Increments on every overwrite.
    pub revision: u64,
    /// SHA-256 of the ciphertext that was submitted, so a client can confirm the
    /// stored value is the one *it* uploaded.
    ///
    /// Not a way to check the value is correct: IBE is randomised, so sealing
    /// the same secret twice gives different digests. That question is
    /// `icp_sealed_secret_matches`.
    pub ciphertext_sha256: ByteBuf,
    /// Nanoseconds since the epoch when this name was first set.
    pub created_at_ns: u64,
    /// Nanoseconds since the epoch when it was last overwritten.
    pub updated_at_ns: u64,
}

/// Typed errors, so that tooling can branch on the cause rather than parsing prose.
#[derive(CandidType, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum SealedSecretsError {
    /// Caller is not a controller.
    Unauthorized,
    /// No secret by that name.
    NotFound,
    /// The name is empty, too long, or has characters outside `[A-Za-z0-9_.-]`.
    InvalidName(String),
    /// The blob is not a well-formed IBE ciphertext, or does not decrypt under
    /// this canister's key — most often a wrong key name or master key table.
    InvalidCiphertext(String),
    /// The subnet could not derive the key. Usually means this subnet does not
    /// hold an NI-DKG transcript for the requested vetKD key.
    VetKdUnavailable { key_name: String, detail: String },
    /// Anything else, with context.
    Internal(String),
}
