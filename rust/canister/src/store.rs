//! Stable state: configuration and the sealed ciphertexts.
//!
//! Ciphertexts live here so that an upgrade never requires re-seeding. Plaintexts
//! never do — though see the README on why that buys less than it appears to:
//! the Wasm heap is replicated state too, and is checkpointed to disk.

use candid::{CandidType, Decode, Encode};
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::{
    storable::Bound, DefaultMemoryImpl, StableBTreeMap, StableCell, Storable,
};
use serde::Deserialize;
use std::borrow::Cow;
use std::cell::RefCell;

pub type Memory = VirtualMemory<DefaultMemoryImpl>;

const CONFIG_MEMORY: MemoryId = MemoryId::new(0);
const SECRETS_MEMORY: MemoryId = MemoryId::new(1);

/// Default ciphertext ceiling: 4 KiB, i.e. roughly 3.9 KiB of plaintext, which
/// comfortably covers API keys, tokens and small PEMs.
pub const DEFAULT_MAX_CIPHERTEXT_LEN: u64 = 4096;

/// Default cap on stored secrets. Bounds the cost of `self_test` and the size of
/// a `list` response.
pub const DEFAULT_MAX_SECRETS: u64 = 256;

/// Configuration pinned at first init.
///
/// Note this is written through `StableCell::init`, which *keeps* an existing
/// value. Editing a constant in source and upgrading is therefore a silent
/// no-op — which is exactly why `self_test` reports the effective config read
/// back from here rather than the compiled-in one.
#[derive(CandidType, Deserialize, Debug, Clone)]
pub struct Config {
    pub key_name: String,
    pub epoch: u32,
    pub max_ciphertext_len: u64,
    pub max_secrets: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            key_name: "key_1".to_string(),
            epoch: 0,
            max_ciphertext_len: DEFAULT_MAX_CIPHERTEXT_LEN,
            max_secrets: DEFAULT_MAX_SECRETS,
        }
    }
}

impl Storable for Config {
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Owned(Encode!(self).expect("failed to encode Config"))
    }
    fn into_bytes(self) -> Vec<u8> {
        Encode!(&self).expect("failed to encode Config")
    }
    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Decode!(&bytes, Self).expect("failed to decode Config")
    }
    const BOUND: Bound = Bound::Unbounded;
}

/// One secret at rest.
///
/// **Holds the plaintext, not the ciphertext.** The secret arrives sealed and is
/// decrypted once, at `set`, after which the ciphertext is discarded and only
/// its digest and length are kept.
///
/// Sealing protects the secret *in transit* — it never appears in an ingress
/// message, a Candid argument, shell history or a CI log. It was never what
/// protects it at rest: the plaintext reaches the heap the moment the canister
/// uses the secret, and the heap is replicated state, checkpointed to disk on
/// every node. Storing the ciphertext instead bought a narrow window before
/// first use, not confidentiality. Only SEV-SNP moves "node operators can read
/// this" to "cannot".
///
/// What storing the plaintext buys, in exchange: the secret survives the subnet
/// losing its vetKD key or the canister moving to one that never had it, where
/// a stored ciphertext would be unreadable forever. And it removes the plaintext
/// cache along with every staleness question that came with it.
#[derive(CandidType, Deserialize, Debug, Clone)]
pub struct SealedRecord {
    /// Epoch the secret was sealed under, recorded for `list`.
    pub epoch: u32,
    /// Increments on overwrite.
    pub revision: u64,
    pub created_at_ns: u64,
    pub updated_at_ns: u64,
    /// SHA-256 of the ciphertext that was submitted, kept so a client can still
    /// confirm its upload landed byte for byte.
    ///
    /// A digest of a *randomised* ciphertext reveals nothing about the
    /// plaintext, which is why this stays safe to expose while a digest of the
    /// plaintext would be an offline guessing oracle for a low-entropy secret.
    pub ciphertext_sha256: Vec<u8>,
    /// Length of the submitted ciphertext, for `list`.
    pub ciphertext_len: u64,
    /// The decrypted secret.
    pub plaintext: Vec<u8>,
}

impl Storable for SealedRecord {
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Owned(Encode!(self).expect("failed to encode SealedRecord"))
    }
    fn into_bytes(self) -> Vec<u8> {
        Encode!(&self).expect("failed to encode SealedRecord")
    }
    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Decode!(&bytes, Self).expect("failed to decode SealedRecord")
    }
    const BOUND: Bound = Bound::Unbounded;
}

thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));

    static CONFIG: RefCell<StableCell<Config, Memory>> = RefCell::new(StableCell::init(
        MEMORY_MANAGER.with_borrow(|m| m.get(CONFIG_MEMORY)),
        Config::default(),
    ));

    static SECRETS: RefCell<StableBTreeMap<String, SealedRecord, Memory>> =
        RefCell::new(StableBTreeMap::init(
            MEMORY_MANAGER.with_borrow(|m| m.get(SECRETS_MEMORY)),
        ));
}

/// Writes the configuration. Called from `init` only; `post_upgrade` deliberately
/// does not, so that an upgrade cannot silently change the derivation and orphan
/// every stored ciphertext.
pub fn set_config(config: Config) {
    CONFIG.with_borrow_mut(|c| {
        c.set(config);
    });
}

/// Reads the effective configuration.
pub fn config() -> Config {
    CONFIG.with_borrow(|c| c.get().clone())
}

pub fn get_record(name: &str) -> Option<SealedRecord> {
    SECRETS.with_borrow(|s| s.get(&name.to_string()))
}

pub fn put_record(name: &str, record: SealedRecord) {
    SECRETS.with_borrow_mut(|s| {
        s.insert(name.to_string(), record);
    });
}

pub fn remove_record(name: &str) -> Option<SealedRecord> {
    SECRETS.with_borrow_mut(|s| s.remove(&name.to_string()))
}

pub fn len() -> u64 {
    SECRETS.with_borrow(|s| s.len())
}

pub fn all_records() -> Vec<(String, SealedRecord)> {
    SECRETS.with_borrow(|s| {
        s.iter()
            .map(|e| (e.key().clone(), e.value().clone()))
            .collect()
    })
}
