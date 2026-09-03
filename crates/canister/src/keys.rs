//! Key derivation and the in-memory caches.
//!
//! Two rules govern everything here.
//!
//! First, a `RefCell` borrow must never be held across an `await`: the awaited
//! call re-enters the canister, and a second borrow panics. So every cache access
//! is read-then-drop or compute-then-insert, never wrapped around the await.
//!
//! Second, the canister's public key comes from `vetkd_public_key`, which is
//! authoritative for the subnet it is actually running on. Verifying the derived
//! key against it is admittedly circular — a subnet that would lie about its
//! public key already holds the master key and could decrypt everything anyway,
//! so the circularity costs little. The non-circular check lives in `self_test`,
//! which compares the subnet's answer against a master key compiled into this
//! Wasm for a source the *caller* nominates.
//!
//! The check that actually matters is on the client, which derives the key
//! offline and refuses to encrypt if the canister disagrees — because that
//! response travels over HTTP through boundary nodes, where the canister's
//! inter-canister call does not.

use ic_cdk_management_canister::{VetKDDeriveKeyArgs, VetKDPublicKeyArgs};
use ic_vetkeys::{DerivedPublicKey, EncryptedVetKey, TransportSecretKey, VetKey};
use sealed_secrets_core::{
    derive_public_key, key_id, sealed_secrets_context, sealed_secrets_identity, MasterKeySource,
};
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use zeroize::Zeroizing;

use crate::store::{self, SealedRecord};
use crate::types::SealedSecretsError;

/// A decrypted secret, shared by reference so callers do not copy it around.
pub type Plaintext = Rc<Zeroizing<Vec<u8>>>;

/// Plaintext cache key: the secret's name plus its revision, so an overwrite
/// invalidates the entry without an explicit purge.
type PlaintextCacheKey = (String, u64);

thread_local! {
    /// Derived public keys, keyed by context. Each miss costs one
    /// `vetkd_public_key` call, which is why `info` is an update; caching means
    /// only the first call after a cold start pays for it.
    static DPK_CACHE: RefCell<HashMap<Vec<u8>, DerivedPublicKey>> = RefCell::new(HashMap::new());

    /// vetKeys by epoch. Each entry costs one `vetkd_derive_key`:
    /// 26_153_846_153 cycles for `key_1`, 10_000_000_000 for `test_key_1`, the
    /// same locally and on mainnet. Hence the cache.
    static VETKEY_CACHE: RefCell<HashMap<u32, Rc<VetKey>>> = RefCell::new(HashMap::new());

    /// Decrypted secrets, keyed by (name, revision) so that overwriting a secret
    /// invalidates its cached plaintext without an explicit purge.
    static PLAINTEXT_CACHE: RefCell<HashMap<PlaintextCacheKey, Plaintext>> =
        RefCell::new(HashMap::new());
}

/// The vetKD context.
///
/// The application domain separator is always empty here. It stays in the wire
/// format (as a length-prefixed field) so a canister that later needs to use
/// vetKD for several purposes can adopt one without a format break, but this PoC
/// has no use for it and does not expose it as configuration.
pub fn context() -> Result<Vec<u8>, SealedSecretsError> {
    sealed_secrets_context("").map_err(|e| SealedSecretsError::Internal(e.to_string()))
}

/// The IBE identity for a given epoch.
pub fn identity(epoch: u32) -> Vec<u8> {
    sealed_secrets_identity(epoch)
}

/// This canister's public key, as reported by the subnet, cached after the first
/// call.
///
/// Asking the subnet rather than deriving from a compiled-in constant is what
/// lets one build run against both a local network and mainnet with no
/// configuration saying which. The trade is that answering costs an
/// inter-canister call, so `info` is an update rather than a query.
pub async fn public_key() -> Result<DerivedPublicKey, SealedSecretsError> {
    let context = context()?;

    if let Some(cached) = DPK_CACHE.with_borrow(|c| c.get(&context).cloned()) {
        return Ok(cached);
    }

    let bytes = reported_public_key().await?;
    let dpk = DerivedPublicKey::deserialize(&bytes)
        .map_err(|e| SealedSecretsError::Internal(format!("malformed public key: {e:?}")))?;

    DPK_CACHE.with_borrow_mut(|c| c.insert(context, dpk.clone()));
    Ok(dpk)
}

/// Derives the public key offline from a master key compiled into this Wasm.
///
/// Only `self_test` uses this, to audit the subnet's answer against an
/// expectation the caller supplies. Returns `None` when no master key is
/// compiled in for this key name under that source.
pub fn expected_public_key(source: MasterKeySource) -> Option<Vec<u8>> {
    let context = context().ok()?;
    let config = store::config();
    derive_public_key(
        source,
        &key_id(&config.key_name),
        &ic_cdk::api::canister_self(),
        &context,
    )
    .ok()
    .map(|k| k.serialize())
}

/// Obtains the vetKey for `epoch`, deriving it if it is not cached.
///
/// Two concurrent cold callers will both derive. That is accepted rather than
/// prevented: vetKD derivation is deterministic in
/// `(canister_id, context, input, key_id)`, so both get the identical key and the
/// only cost is a duplicate fee. The alternatives are worse — rejecting the
/// second caller is bad UX in a business path, and making it wait is not
/// implementable, since the two are separate message executions and neither can
/// await the other's future.
pub async fn vetkey(epoch: u32) -> Result<Rc<VetKey>, SealedSecretsError> {
    if let Some(cached) = VETKEY_CACHE.with_borrow(|c| c.get(&epoch).cloned()) {
        return Ok(cached);
    }

    // Everything synchronous happens before the first await, and no borrow is
    // held into it.
    let config = store::config();
    let context = context()?;
    let identity = identity(epoch);
    let dpk = public_key().await?;

    let seed = ic_cdk_management_canister::raw_rand()
        .await
        .map_err(|e| SealedSecretsError::Internal(format!("raw_rand failed: {e}")))?;

    // A real, single-use transport key. The alternative used by the timelock
    // example — an all-zero seed, or the G1 identity element — makes the derived
    // key readable by anyone who can read the subnet's messages, and skips the
    // verification below entirely.
    let tsk = TransportSecretKey::from_seed(seed)
        .map_err(|e| SealedSecretsError::Internal(format!("bad transport seed: {e}")))?;

    let reply = ic_cdk_management_canister::vetkd_derive_key(&VetKDDeriveKeyArgs {
        input: identity.clone(),
        context,
        key_id: key_id(&config.key_name),
        transport_public_key: tsk.public_key(),
    })
    .await
    .map_err(|e| classify_derive_error(&config.key_name, e))?;

    let vetkey = EncryptedVetKey::deserialize(&reply.encrypted_key)
        .map_err(|e| SealedSecretsError::Internal(format!("malformed encrypted vetkey: {e}")))?
        .decrypt_and_verify(&tsk, &dpk, &identity)
        .map_err(|e| {
            SealedSecretsError::Internal(format!(
                "the subnet returned a key that does not match our derived public key: {e}"
            ))
        })?;

    let vetkey = Rc::new(vetkey);
    VETKEY_CACHE.with_borrow_mut(|c| c.insert(epoch, vetkey.clone()));
    Ok(vetkey)
}

/// Decrypts a stored record, using and populating the plaintext cache.
pub async fn open(name: &str, record: &SealedRecord) -> Result<Plaintext, SealedSecretsError> {
    let cache_key = (name.to_string(), record.revision);

    if let Some(cached) = PLAINTEXT_CACHE.with_borrow(|c| c.get(&cache_key).cloned()) {
        return Ok(cached);
    }

    let plaintext = decrypt_with_epoch(&record.ciphertext, record.epoch).await?;
    let plaintext = Rc::new(plaintext);
    PLAINTEXT_CACHE.with_borrow_mut(|c| c.insert(cache_key, plaintext.clone()));
    Ok(plaintext)
}

/// Decrypts a ciphertext under a given epoch's key, without touching any cache.
///
/// This is what `set` uses to trial-decrypt before storing — the check that turns
/// a wrong context, epoch or key id into an error in front of the operator rather
/// than an accepted blob that nobody can decrypt months later.
pub async fn decrypt_with_epoch(
    ciphertext: &[u8],
    epoch: u32,
) -> Result<Zeroizing<Vec<u8>>, SealedSecretsError> {
    let vetkey = vetkey(epoch).await?;

    let parsed = ic_vetkeys::IbeCiphertext::deserialize(ciphertext).map_err(|e| {
        SealedSecretsError::InvalidCiphertext(format!("not an IBE ciphertext: {e}"))
    })?;

    parsed.decrypt(&vetkey).map(Zeroizing::new).map_err(|_| {
        SealedSecretsError::InvalidCiphertext(
            "ciphertext was not encrypted to this canister's key for this epoch \
                 (check the context, epoch and key name reported by info)"
                .to_string(),
        )
    })
}

/// Drops a name's cached plaintext, for every revision.
pub fn purge_plaintext(name: &str) {
    PLAINTEXT_CACHE.with_borrow_mut(|c| c.retain(|(n, _), _| n != name));
}

/// Asks the subnet for this canister's public key.
///
/// This is authoritative — it is what [`public_key`] caches and what
/// `decrypt_and_verify` checks against. `self_test` also calls it directly, to
/// compare against a master key compiled into this Wasm.
pub async fn reported_public_key() -> Result<Vec<u8>, SealedSecretsError> {
    let config = store::config();
    let context = context()?;
    ic_cdk_management_canister::vetkd_public_key(&VetKDPublicKeyArgs {
        canister_id: None,
        context,
        key_id: key_id(&config.key_name),
    })
    .await
    .map(|r| r.public_key)
    .map_err(|e| SealedSecretsError::Internal(format!("vetkd_public_key failed: {e}")))
}

/// Turns a derive failure into a typed error, singling out the case where the
/// subnet simply does not hold the key. That is a deployment problem, not a bug,
/// and it deserves to say so rather than surfacing as an opaque reject.
fn classify_derive_error(
    key_name: &str,
    err: ic_cdk_management_canister::SignCallError,
) -> SealedSecretsError {
    let detail = err.to_string();
    if detail.contains("NiDkgTranscript") || detail.contains("does not hold") {
        SealedSecretsError::VetKdUnavailable {
            key_name: key_name.to_string(),
            detail,
        }
    } else {
        SealedSecretsError::Internal(format!("vetkd_derive_key failed: {detail}"))
    }
}
