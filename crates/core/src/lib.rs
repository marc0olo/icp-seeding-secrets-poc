//! Wire format and offline key derivation for the sealed-secrets PoC.
//!
//! Everything in this crate is pure computation: no canister APIs, no network.
//! It is shared by the canister (which decrypts) and by any client (which seals),
//! so that both sides derive byte-identical `context` and `identity` values.
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

/// Ciphersuite label. Bumping this is a hard protocol break: every previously
/// sealed ciphertext becomes undecryptable, because it changes both the vetKD
/// context (and hence the keypair) and the IBE identity.
pub const SUITE: &[u8] = b"icp-sealed-secrets-v1";

/// Version byte prefixing the vetKD `context` encoding.
pub const CONTEXT_FORMAT_VERSION: u8 = 0x01;

/// Version byte prefixing the IBE `identity` encoding.
pub const IDENTITY_FORMAT_VERSION: u8 = 0x01;

/// Fixed overhead `IbeCiphertext` adds to the plaintext: an 8-byte header,
/// a 32-byte seed and a 96-byte G2 element.
pub const IBE_OVERHEAD: usize = 8 + 32 + 96;

/// Longest accepted secret name.
pub const MAX_NAME_LEN: usize = 64;

/// Longest accepted application domain separator.
pub const MAX_APP_SEPARATOR_LEN: usize = 255;

/// Errors from encoding or validation. All are caller mistakes, never I/O.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FormatError {
    /// The application domain separator exceeds [`MAX_APP_SEPARATOR_LEN`].
    AppSeparatorTooLong { len: usize },
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
    /// A public key could not be parsed.
    MalformedPublicKey,
    /// The canister reported a public key that differs from the one we derived.
    PublicKeyMismatch,
}

impl core::fmt::Display for FormatError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::AppSeparatorTooLong { len } => write!(
                f,
                "application domain separator is {len} bytes, maximum is {MAX_APP_SEPARATOR_LEN}"
            ),
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
            Self::MalformedPublicKey => write!(f, "public key is not a valid G2 point"),
            Self::PublicKeyMismatch => write!(
                f,
                "the canister reported a different public key than we derived; refusing to encrypt"
            ),
        }
    }
}

impl std::error::Error for FormatError {}

/// Which table of hardcoded master public keys to derive from.
///
/// This is deliberately explicit rather than inferred from the key *name*.
/// PocketIC and mainnet both have a key called `key_1`, and their master public
/// keys are different values — guessing wrong yields a ciphertext that nobody
/// can ever decrypt, with no error at seal time. `ic-vetkeys`'
/// `management_canister::compute_vrf` has exactly this bug today.
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

/// Encodes the vetKD `context`, the second-stage key derivation input.
///
/// ```text
/// context := 0x01 || u8(len(SUITE)) || SUITE || u8(len(app_separator)) || app_separator
/// ```
///
/// Both variable-length fields are length-prefixed so that no two distinct
/// `(SUITE, app_separator)` pairs can encode to the same bytes.
///
/// `app_separator` exists because one canister may use vetKD for several
/// unrelated purposes at once, and each must occupy a distinct context. The
/// empty separator is the default.
pub fn sealed_secrets_context(app_separator: &str) -> Result<Vec<u8>, FormatError> {
    let sep = app_separator.as_bytes();
    if sep.len() > MAX_APP_SEPARATOR_LEN {
        return Err(FormatError::AppSeparatorTooLong { len: sep.len() });
    }

    let mut out = Vec::with_capacity(3 + SUITE.len() + sep.len());
    out.push(CONTEXT_FORMAT_VERSION);
    out.push(SUITE.len() as u8);
    out.extend_from_slice(SUITE);
    out.push(sep.len() as u8);
    out.extend_from_slice(sep);
    Ok(out)
}

/// Encodes the IBE identity, which is also the `input` to `vetkd_derive_key`.
///
/// ```text
/// identity := 0x01 || u8(len(SUITE)) || SUITE || be_u32(epoch)
/// ```
///
/// Note what is *absent*: the secret's name. One identity serves every secret in
/// a canister, so a single `vetkd_derive_key` call unlocks all of them. Per-secret
/// identities would multiply that cost by N and buy nothing — there is no
/// privilege boundary inside a canister, since its code can derive the key for
/// any identity at any time.
pub fn sealed_secrets_identity(epoch: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + SUITE.len() + 4);
    out.push(IDENTITY_FORMAT_VERSION);
    out.push(SUITE.len() as u8);
    out.extend_from_slice(SUITE);
    out.extend_from_slice(&epoch.to_be_bytes());
    out
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
/// machine before encrypting, and the same calculation the canister runs against
/// the master key compiled into its own Wasm in order to check the subnet's
/// answer — see [`verify_reported_public_key`].
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

/// Checks a public key obtained over the network against one derived offline.
///
/// This is the Rust-side helper for the check every client must perform before
/// encrypting; the TypeScript client in `seed/` does the same comparison inline.
/// Trusting a public key the canister reports would let anyone able to tamper
/// with that response substitute a key they control and harvest the plaintext.
///
/// The reported value is only ever a cross-check. The key actually encrypted to
/// is the locally derived one, which is what this returns.
pub fn verify_reported_public_key(
    source: MasterKeySource,
    key_id: &VetKDKeyId,
    canister_id: &candid::Principal,
    context: &[u8],
    reported: &[u8],
) -> Result<DerivedPublicKey, FormatError> {
    let derived = derive_public_key(source, key_id, canister_id, context)?;
    // Compare the canonical serialisations rather than the parsed points, so a
    // non-canonical encoding of the right point is also rejected.
    if derived.serialize() != reported {
        return Err(FormatError::PublicKeyMismatch);
    }
    Ok(derived)
}

/// Recovers the plaintext length a ciphertext of this size must have had.
pub fn plaintext_len(ciphertext_len: usize) -> Option<usize> {
    ciphertext_len.checked_sub(IBE_OVERHEAD)
}
