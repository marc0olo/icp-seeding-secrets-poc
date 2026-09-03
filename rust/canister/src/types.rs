//! Candid types on the wire.
//!
//! This interface is a starting proposal for discussion, not a frozen standard.

use candid::CandidType;
use serde::Deserialize;
use serde_bytes::ByteBuf;

/// Which table of hardcoded master public keys to check the subnet's answer
/// against.
///
/// This is a `self_test` *argument*, not configuration. The canister obtains its
/// public key from `vetkd_public_key`, which is authoritative; comparing that
/// against a constant compiled into this Wasm is an on-demand audit, and the
/// caller is the one who knows which network they believe they are on.
#[derive(CandidType, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeySource {
    /// IC mainnet master keys.
    Mainnet,
    /// PocketIC master keys, which local `icp network` also uses.
    PocketIc,
}

impl From<KeySource> for sealed_secrets_core::MasterKeySource {
    fn from(value: KeySource) -> Self {
        match value {
            KeySource::Mainnet => Self::Mainnet,
            KeySource::PocketIc => Self::PocketIc,
        }
    }
}

/// Everything a client needs in order to seal a secret for this canister, and
/// to check that it is sealing to the right key.
#[derive(CandidType, Deserialize, Debug, Clone)]
pub struct SealedSecretInfo {
    /// Version of this interface. Currently 1.
    pub standard_version: u32,
    /// The exact vetKD `context` bytes this canister derives under.
    pub context: ByteBuf,
    /// The exact IBE identity bytes for the current epoch.
    pub identity: ByteBuf,
    /// The current epoch. New seals must target this value.
    pub epoch: u32,
    /// The vetKD key name, e.g. `key_1`.
    pub key_name: String,
    /// The 96-byte derived public key to encrypt to.
    ///
    /// A client must treat this as a *cross-check* against its own offline
    /// derivation, never as the key to encrypt to: derive the key yourself from a
    /// master public key you ship, compare, and refuse to encrypt on a mismatch.
    /// This reply crosses boundary nodes, so trusting it would let anyone able to
    /// tamper with it substitute a key they control.
    pub public_key: ByteBuf,
    /// Largest ciphertext this canister will accept.
    pub max_ciphertext_len: u64,
    /// Largest number of secrets this canister will hold.
    pub max_secrets: u64,
}

/// One stored secret, as reported by `list`. Carries nothing derived from the
/// plaintext: a digest of the plaintext would be an offline guessing oracle for
/// low-entropy secrets, whereas a digest of a randomised ciphertext reveals
/// nothing.
#[derive(CandidType, Deserialize, Debug, Clone)]
pub struct SealedSecretEntry {
    /// The secret's name.
    pub name: String,
    /// The epoch its ciphertext was sealed under.
    pub epoch: u32,
    /// Increments on every overwrite. Also invalidates the plaintext cache.
    pub revision: u64,
    /// Ciphertext length in bytes.
    pub ciphertext_len: u64,
    /// SHA-256 of the ciphertext, so a client can confirm its upload landed.
    pub ciphertext_sha256: ByteBuf,
    /// Nanoseconds since the epoch when this name was first set.
    pub created_at_ns: u64,
    /// Nanoseconds since the epoch when it was last overwritten.
    pub updated_at_ns: u64,
}

/// The result of `self_test`: a deploy-time health check that exercises the
/// whole decryption path so that failures surface here rather than during a
/// production call.
#[derive(CandidType, Deserialize, Debug, Clone)]
pub struct SelfTestReport {
    /// Whether `vetkd_public_key` answered.
    pub vetkd_public_key_ok: bool,
    /// Whether `vetkd_derive_key` answered and verified.
    pub vetkd_derive_ok: bool,
    /// Whether the subnet's public key matched the master key compiled into this
    /// Wasm, for the `expected_source` the caller supplied. `None` when the
    /// caller supplied none, or when no master key is compiled in for this key
    /// name under that source.
    ///
    /// This is the one check in the design that is not the subnet vouching for
    /// itself, so a deployment should run it once with the source it expects.
    pub public_key_matches_master: Option<bool>,
    /// The key name actually in use, read from stable state rather than source.
    ///
    /// `StableCell::init` keeps an existing value, so editing a constant and
    /// upgrading is a silent no-op. Reporting the effective value is what makes
    /// that visible.
    pub effective_key_name: String,
    /// The context actually in use.
    pub effective_context: ByteBuf,
    /// The current epoch.
    pub epoch: u32,
    /// How many secrets are stored.
    pub num_secrets: u64,
    /// Names that failed to decrypt. Should always be empty.
    pub undecryptable: Vec<String>,
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
    /// this canister's key — most often a wrong context, epoch or key id.
    InvalidCiphertext(String),
    /// Ciphertext exceeds `max_ciphertext_len`.
    TooLarge { max: u64 },
    /// Storing this would exceed `max_secrets`.
    TooMany { max: u64 },
    /// The subnet could not derive the key. Usually means this subnet does not
    /// hold an NI-DKG transcript for the requested vetKD key.
    VetKdUnavailable { key_name: String, detail: String },
    /// Anything else, with context.
    Internal(String),
}
