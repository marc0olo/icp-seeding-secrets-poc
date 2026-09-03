//! Key derivation and the in-memory caches.
//!
//! Two rules govern everything here.
//!
//! First, a `RefCell` borrow must never be held across an `await`: the awaited
//! call re-enters the canister, and a second borrow panics. So every cache access
//! is read-then-drop or compute-then-insert, never wrapped around the await.
//!
//! Second, the derived public key is computed *offline* from the master key
//! compiled into this Wasm, never taken from `vetkd_public_key`. Verifying the
//! subnet's derived key against a public key the same subnet just handed us
//! would be circular; verifying it against a constant covered by the module hash
//! is not.

use ic_cdk_management_canister::{VetKDDeriveKeyArgs, VetKDPublicKeyArgs};
use ic_vetkeys::{DerivedPublicKey, EncryptedVetKey, TransportSecretKey, VetKey};
use sealed_secrets_core::{
    derive_public_key, key_id, sealed_secrets_context, sealed_secrets_identity,
};
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use zeroize::Zeroizing;

use crate::store::{self, SealedRecord};

/// A decrypted secret, shared by reference so callers do not copy it around.
pub type Plaintext = Rc<Zeroizing<Vec<u8>>>;

/// Plaintext cache key: the secret's name plus its revision, so an overwrite
/// invalidates the entry without an explicit purge.
type PlaintextCacheKey = (String, u64);
use crate::types::SealedSecretsError;

thread_local! {
    /// Derived public keys, keyed by context. Pure computation, but two scalar
    /// multiplications is enough to be worth not repeating per call.
    static DPK_CACHE: RefCell<HashMap<Vec<u8>, DerivedPublicKey>> = RefCell::new(HashMap::new());

    /// vetKeys by epoch. Each entry costs one `vetkd_derive_key` — on the order
    /// of 10B cycles at a 13-node subnet, scaled by replication factor.
    static VETKEY_CACHE: RefCell<HashMap<u32, Rc<VetKey>>> = RefCell::new(HashMap::new());

    /// Decrypted secrets, keyed by (name, revision) so that overwriting a secret
    /// invalidates its cached plaintext without an explicit purge.
    static PLAINTEXT_CACHE: RefCell<HashMap<PlaintextCacheKey, Plaintext>> =
        RefCell::new(HashMap::new());
}

/// The vetKD context for the effective configuration.
pub fn context() -> Result<Vec<u8>, SealedSecretsError> {
    let config = store::config();
    sealed_secrets_context(&config.app_separator)
        .map_err(|e| SealedSecretsError::Internal(e.to_string()))
}

/// The IBE identity for a given epoch.
pub fn identity(epoch: u32) -> Vec<u8> {
    sealed_secrets_identity(epoch)
}

/// Derives this canister's public key offline. No network call.
pub fn public_key() -> Result<DerivedPublicKey, SealedSecretsError> {
    let context = context()?;

    if let Some(cached) = DPK_CACHE.with_borrow(|c| c.get(&context).cloned()) {
        return Ok(cached);
    }

    let config = store::config();
    let dpk = derive_public_key(
        config.key_source.into(),
        &key_id(&config.key_name),
        &ic_cdk::api::canister_self(),
        &context,
    )
    .map_err(|e| SealedSecretsError::Internal(e.to_string()))?;

    DPK_CACHE.with_borrow_mut(|c| c.insert(context, dpk.clone()));
    Ok(dpk)
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
    let dpk = public_key()?;

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

/// Asks the subnet for its own view of the public key.
///
/// Used only by `self_test`, to detect a mismatch against our compiled-in master
/// key. It is never used to choose the encryption key.
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
