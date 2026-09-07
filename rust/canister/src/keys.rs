//! Key derivation and the vetKey cache.
//!
//! There is no plaintext cache. Records hold the decrypted secret (see
//! `store::SealedRecord`), so reading one is a map lookup and decryption happens
//! only on the two paths that receive a ciphertext from a caller: `set`, which
//! decrypts before storing, and `matches`, which decrypts the candidate it
//! is asked to compare.
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
//! so the circularity costs little.
//!
//! The check that actually matters is on the client, which derives the key
//! offline and refuses to encrypt if the canister disagrees — because that
//! response travels over HTTP through boundary nodes, where the canister's
//! inter-canister call does not.

use ic_cdk_management_canister::{VetKDDeriveKeyArgs, VetKDPublicKeyArgs};
use ic_vetkeys::{DerivedPublicKey, EncryptedVetKey, TransportSecretKey, VetKey};
use sealed_secrets_core::{key_id, CONTEXT, KEY_LABEL};
use std::cell::RefCell;
use std::rc::Rc;
use zeroize::Zeroizing;

use crate::store;
use crate::types::SealedSecretsError;

thread_local! {
    /// The vetKey. One of them, because one label serves every secret — which is
    /// the point of the label being a constant. Filling it costs one
    /// `vetkd_derive_key`: 26_153_846_153 cycles for `key_1`, 10_000_000_000 for
    /// `test_key_1`, the same locally and on mainnet. Hence the cache.
    ///
    /// The public key is deliberately *not* cached alongside it. It is needed
    /// only to verify a freshly derived vetKey, so it is fetched on exactly the
    /// path that fills this cache and never read again once that path succeeds.
    static VETKEY_CACHE: RefCell<Option<Rc<VetKey>>> = const { RefCell::new(None) };
}

/// Obtains this canister's vetKey, deriving it if it is not cached.
///
/// Two concurrent cold callers will both derive. That is accepted rather than
/// prevented: vetKD derivation is deterministic in
/// `(canister_id, context, input, key_id)`, so both get the identical key and the
/// only cost is a duplicate fee. The alternatives are worse — rejecting the
/// second caller is bad UX in a business path, and making it wait is not
/// implementable, since the two are separate message executions and neither can
/// await the other's future.
pub async fn vetkey() -> Result<Rc<VetKey>, SealedSecretsError> {
    if let Some(cached) = VETKEY_CACHE.with_borrow(|c| c.clone()) {
        return Ok(cached);
    }

    // Everything synchronous happens before the first await, and no borrow is
    // held into it.
    let config = store::config();

    // The public key `decrypt_and_verify` checks the reply against. Asking the
    // subnet rather than deriving from a compiled-in constant is what lets one
    // build run against both a local network and mainnet with no configuration
    // saying which; see `reported_public_key` on why the circularity is cheap.
    let dpk = DerivedPublicKey::deserialize(&reported_public_key().await?)
        .map_err(|e| SealedSecretsError::Internal(format!("malformed public key: {e:?}")))?;

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
        input: KEY_LABEL.to_vec(),
        context: CONTEXT.to_vec(),
        key_id: key_id(&config.key_name),
        transport_public_key: tsk.public_key(),
    })
    .await
    .map_err(|e| classify_derive_error(&config.key_name, e))?;

    let vetkey = EncryptedVetKey::deserialize(&reply.encrypted_key)
        .map_err(|e| SealedSecretsError::Internal(format!("malformed encrypted vetkey: {e}")))?
        .decrypt_and_verify(&tsk, &dpk, KEY_LABEL)
        .map_err(|e| {
            SealedSecretsError::Internal(format!(
                "the subnet returned a key that does not match our derived public key: {e}"
            ))
        })?;

    let vetkey = Rc::new(vetkey);
    VETKEY_CACHE.with_borrow_mut(|c| *c = Some(vetkey.clone()));
    Ok(vetkey)
}

/// Decrypts a ciphertext with this canister's vetKey.
///
/// This is what `set` uses before storing — the check that turns a wrong key
/// name or master key table into an error in front of the operator, rather than
/// an accepted blob that nobody can decrypt months later.
pub async fn decrypt(ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, SealedSecretsError> {
    let vetkey = vetkey().await?;

    let parsed = ic_vetkeys::IbeCiphertext::deserialize(ciphertext).map_err(|e| {
        SealedSecretsError::InvalidCiphertext(format!("not an IBE ciphertext: {e}"))
    })?;

    parsed.decrypt(&vetkey).map(Zeroizing::new).map_err(|_| {
        SealedSecretsError::InvalidCiphertext(
            "ciphertext was not encrypted to this canister's key: check that the \
                 client used this canister's id, the same vetKD key name, and the \
                 master key table for this network"
                .to_string(),
        )
    })
}

/// Asks the subnet for this canister's public key.
///
/// This is what `decrypt_and_verify` checks a derived vetKey against, which
/// makes the check circular — the subnet vouching for itself. Cheaply so: a
/// subnet that would lie here already holds the master key and could decrypt
/// everything anyway. The non-circular check is the client's, which derives the
/// key offline from a master key it ships.
pub async fn reported_public_key() -> Result<Vec<u8>, SealedSecretsError> {
    let config = store::config();
    ic_cdk_management_canister::vetkd_public_key(&VetKDPublicKeyArgs {
        canister_id: None,
        context: CONTEXT.to_vec(),
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
