//! Wire format and offline key derivation for the sealed-secrets PoC.
//!
//! Everything in this crate is pure computation: no canister APIs, no network.
//! It is shared by the canister (which decrypts) and by any client (which seals),
//! so that both sides derive byte-identical `context` and `key_label` values.
//!
//! See `README.md` for the protocol description and `tests/golden.rs` for the
//! vectors that pin the encodings down.

use ic_vetkeys::{DerivedPublicKey, MasterPublicKey};

pub use ic_cdk_management_canister::{VetKDCurve, VetKDKeyId};
pub use ic_vetkeys::{IbeCiphertext, IbeIdentity, IbeSeed, VetKey};

/// Builds a key id on the only curve vetKD currently supports.
///
/// `name` is the deployed key, e.g. `key_1` or `test_key_1`. Note that the name
/// alone does not identify a key: mainnet and PocketIC each have a `key_1` with
/// a *different* master public key, which is what [`MasterKeySource`] selects.
pub fn key_id(name: impl Into<String>) -> VetKDKeyId {
    VetKDKeyId {
        curve: VetKDCurve::Bls12_381_G2,
        name: name.into(),
    }
}

/// Ciphersuite label, and the version of this protocol. Bumping it is a hard
/// break: every previously sealed ciphertext becomes undecryptable, because it
/// changes both the vetKD context (and hence the keypair) and the key label.
pub const SUITE: &[u8] = b"icp-sealed-secrets-v1";

/// The vetKD `context`: which keypair this canister derives under.
///
/// A constant of the standard, not configuration. The derivation is master key
/// -> canister id -> context, so the canister id already separates canisters and
/// the suite already separates sealed secrets from any other use of vetKD in the
/// same canister. There is nothing left for a client to be told.
///
/// It carries no version byte and no length prefix. The version is in the string
/// — bumping `SUITE` is the format break — and length prefixes existed to keep
/// two variable-length fields from colliding, of which there are now none.
pub const CONTEXT: &[u8] = SUITE;

/// The `input` to `vetkd_derive_key`: which key to derive under that keypair.
///
/// In vetKD terms the IBE identity. Called a *label* because on ICP "identity"
/// means a caller's principal, and this is neither that nor a key.
///
/// Distinct from [`CONTEXT`] so the two cannot be confused at a call site, and
/// deliberately independent of the secret's name: one label serves every secret,
/// so a single `vetkd_derive_key` unlocks all of them. Per-secret labels would
/// multiply the cost by N and buy nothing — there is no privilege boundary
/// inside a canister, since its code can derive the key for any label at any
/// time.
pub const KEY_LABEL: &[u8] = b"icp-sealed-secrets-v1.keys";

/// Longest accepted secret name.
pub const MAX_NAME_LEN: usize = 64;

/// Errors from encoding or validation. All are caller mistakes, never I/O.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FormatError {
    /// The secret name is empty.
    EmptyName,
    /// The secret name exceeds [`MAX_NAME_LEN`].
    NameTooLong { len: usize },
    /// The secret name contains a character outside `[A-Za-z0-9_.-]`.
    InvalidNameChar { ch: char },
    /// No master public key is compiled in for this key id under the selected source.
    UnknownKeyId {
        source: MasterKeySource,
        key_name: String,
    },
}

impl core::fmt::Display for FormatError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::EmptyName => write!(f, "secret name must not be empty"),
            Self::NameTooLong { len } => {
                write!(f, "secret name is {len} bytes, maximum is {MAX_NAME_LEN}")
            }
            Self::InvalidNameChar { ch } => write!(
                f,
                "secret name contains {ch:?}; only A-Z a-z 0-9 _ . - are allowed"
            ),
            Self::UnknownKeyId { source, key_name } => write!(
                f,
                "no {source} master public key is compiled in for key {key_name:?}"
            ),
        }
    }
}

impl std::error::Error for FormatError {}

/// Which table of hardcoded master public keys to derive from.
///
/// This is deliberately explicit rather than inferred from the key *name*.
///
/// Mainnet and PocketIC both have a key called `key_1`, backed by different
/// master keys — necessarily, since a local environment cannot hold mainnet's
/// master secret. So a key name does not identify a key, and inferring the table
/// from it is guessing: guess wrong and encryption still succeeds, producing a
/// ciphertext the canister cannot open. `set` catches it — it decrypts before
/// storing — which is precisely why that check is not optional. `ic-vetkeys`'
/// `management_canister::compute_vrf` infers it today and is wrong under
/// PocketIC as a result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MasterKeySource {
    /// The IC mainnet master keys.
    Mainnet,
    /// The deterministic PocketIC master keys, used by local `icp network` too.
    PocketIc,
}

impl core::fmt::Display for MasterKeySource {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Mainnet => f.write_str("mainnet"),
            Self::PocketIc => f.write_str("pocketic"),
        }
    }
}

impl MasterKeySource {
    /// Looks up the master public key for `key_id` in this source's table.
    pub fn master_public_key(&self, key_id: &VetKDKeyId) -> Result<MasterPublicKey, FormatError> {
        let found = match self {
            Self::Mainnet => MasterPublicKey::for_mainnet_key(key_id),
            Self::PocketIc => MasterPublicKey::for_pocketic_key(key_id),
        };
        found.ok_or_else(|| FormatError::UnknownKeyId {
            source: *self,
            key_name: key_id.name.clone(),
        })
    }
}

/// Accepts `[A-Za-z0-9_.-]{1,64}`.
///
/// The charset matches environment-variable conventions and, more importantly,
/// sidesteps Unicode confusables and normalisation differences that an arbitrary
/// Candid `text` name would admit — two names that look identical must not be
/// two different entries.
pub fn validate_secret_name(name: &str) -> Result<(), FormatError> {
    if name.is_empty() {
        return Err(FormatError::EmptyName);
    }
    if name.len() > MAX_NAME_LEN {
        return Err(FormatError::NameTooLong { len: name.len() });
    }
    if let Some(ch) = name
        .chars()
        .find(|c| !(c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-')))
    {
        return Err(FormatError::InvalidNameChar { ch });
    }
    Ok(())
}

/// Derives a canister's sealed-secrets public key offline.
///
/// This performs no network call. It is the calculation a client runs on its own
/// machine before encrypting: master public key -> canister id -> context. The
/// canister never needs it — it asks `vetkd_public_key`, which is authoritative
/// for the subnet it is actually on.
pub fn derive_public_key(
    source: MasterKeySource,
    key_id: &VetKDKeyId,
    canister_id: &candid::Principal,
    context: &[u8],
) -> Result<DerivedPublicKey, FormatError> {
    Ok(source
        .master_public_key(key_id)?
        .derive_canister_key(canister_id.as_slice())
        .derive_sub_key(context))
}
