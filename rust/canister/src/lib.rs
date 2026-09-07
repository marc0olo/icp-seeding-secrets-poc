//! A canister that receives secrets, encrypted with vetKD IBE.
//!
//! The whole mechanism, in two endpoints:
//!
//!   set_dummy_secret(name, ciphertext)  decrypt and store under that name
//!   get_dummy_secret(name)              hand the plaintext back so you can see it worked
//!
//! The client encrypts to a public key it derives **offline** — no network call,
//! nothing to trust — and only this canister can have the matching private key
//! derived for it. See ../../README.md.

use ic_cdk::{query, update};
use ic_cdk_management_canister::{
    raw_rand, vetkd_derive_key, vetkd_public_key, VetKDCurve, VetKDDeriveKeyArgs, VetKDKeyId,
    VetKDPublicKeyArgs,
};
use ic_vetkeys::{DerivedPublicKey, EncryptedVetKey, IbeCiphertext, TransportSecretKey, VetKey};
use std::cell::RefCell;
use std::collections::BTreeMap;

/// The vetKD **context**: what selects the *keypair*.
///
/// The derivation is caller -> context, so changing this byte for byte gives
/// this canister an entirely different keypair. One context per purpose: a
/// canister using vetKD for two unrelated things gives each its own, and neither
/// can open the other's ciphertext.
const CONTEXT: &[u8] = b"dummy-secret-poc";

/// The label under which every secret here is sealed — in vetKD terms the **IBE
/// identity**, and the `input` to `vetkd_derive_key`.
///
/// Not a key, and not a secret's name. `(caller, context)` fixes a keypair; this
/// picks one of the infinitely many keys under it, and one key opens every
/// ciphertext sealed to it. That is why storing many secrets costs exactly one
/// derivation: they all share this label, and the per-secret names below are
/// just map keys that never reach vetKD.
///
/// Giving each secret its own label would cost a separate `vetkd_derive_key` —
/// 26 billion cycles each — and buy nothing, because there is no privilege
/// boundary inside a canister to enforce: this code can derive any label's key
/// whenever it likes.
const KEY_LABEL: &[u8] = b"dummy-secrets";

/// The vetKD key to use. `key_1` exists on mainnet and on a local network, so
/// one constant covers both. Deliberately not an install argument, because
/// `#[init]` does not re-run on upgrade and an empty key name fails with a
/// message that does not point at the cause.
const KEY_NAME: &str = "key_1";

thread_local! {
    /// The derived private key, cached after the first use.
    ///
    /// Safe to hold forever: derivation is deterministic in
    /// `(caller, context, input, key_id)`, none of which depends on the secrets,
    /// so this can never go stale. Without it every write would pay a
    /// `vetkd_derive_key` — 26 billion cycles and a round through consensus —
    /// for a key that never changes.
    ///
    /// Lost on upgrade, because this is the heap and nothing serialises it; the
    /// first write afterwards re-derives. The Motoko canister keeps its cache
    /// across upgrades, since orthogonal persistence gives that for free — which
    /// means editing `CONTEXT` or `KEY_LABEL` there needs a reinstall, not an
    /// upgrade, or it keeps serving the key for the old ones.
    static VETKEY: RefCell<Option<VetKey>> = const { RefCell::new(None) };

    /// The decrypted secrets, by name. The name is bookkeeping only — it is not
    /// part of any derivation and never leaves this canister.
    static SECRETS: RefCell<BTreeMap<String, String>> = const { RefCell::new(BTreeMap::new()) };
}

fn key_id() -> VetKDKeyId {
    VetKDKeyId {
        curve: VetKDCurve::Bls12_381_G2,
        name: KEY_NAME.to_string(),
    }
}

/// Fetches the vetKey for `KEY_LABEL`, once, and caches it.
///
/// "Private key" is loose shorthand. What comes back is one G1 point that is two
/// things at the same time: a BLS **signature** over `KEY_LABEL`, which is what
/// makes it verifiable against the derived public key, and the IBE **decryption
/// key** for that label, which is what opens the ciphertexts. See the README.
///
/// The canister does not derive it either — the subnet does. This asks for a
/// derivation and unwraps the reply.
///
/// Two concurrent callers on a cold cache will both derive. That is accepted
/// rather than prevented: derivation is deterministic, so both get the identical
/// key and the only cost is a duplicate fee. Rejecting the second is bad UX on a
/// write path, and making it wait is not implementable — they are separate
/// message executions and neither can await the other.
async fn vetkey() -> Result<VetKey, String> {
    // Read and drop the borrow before any await; holding one across a call
    // would panic when the canister re-enters.
    if let Some(cached) = VETKEY.with_borrow(|v| v.clone()) {
        return Ok(cached);
    }

    // 1. A single-use transport keypair. The private half never leaves here.
    //
    //    The public half goes into the share computation itself, so no node ever
    //    assembles the plaintext key: each produces a share already encrypted
    //    under it, and combining encrypted shares yields an encrypted key.
    //
    //    Step 3 does decrypt it, and the result then lives in this canister's
    //    memory — replicated and checkpointed like any other canister state, and
    //    protected there by SEV-SNP alone. What the transport key buys is that
    //    the plaintext never leaves here: not in a message, not in a
    //    cross-subnet stream, and not known to the subnet that derived it.
    let seed = raw_rand().await.map_err(|e| format!("raw_rand: {e}"))?;
    let tsk = TransportSecretKey::from_seed(seed).map_err(|e| format!("transport key: {e}"))?;

    // 2. Ask for the private key belonging to (this canister, CONTEXT, KEY_LABEL).
    //    The management canister routes this to a subnet holding the key — not
    //    necessarily our own — where each node contributes a share and none ever
    //    holds the whole key. What binds the result to us is that the caller's
    //    canister id is an input to the derivation, and `vetkd_derive_key` has no
    //    field for naming a different one.
    let reply = vetkd_derive_key(&VetKDDeriveKeyArgs {
        input: KEY_LABEL.to_vec(),
        context: CONTEXT.to_vec(),
        key_id: key_id(),
        transport_public_key: tsk.public_key(),
    })
    .await
    .map_err(|e| format!("vetkd_derive_key: {e} — is {KEY_NAME} available here?"))?;

    // 3. Unwrap it, and check that what fell out really is our key.
    //
    //    `decrypt_and_verify` does three things: rejects a malformed reply whose
    //    two halves disagree, strips the transport blinding, and then verifies
    //    the result is a valid BLS signature over KEY_LABEL under `dpk`. That
    //    last step is what makes a forged reply useless.
    //
    //    It needs the matching public key, and asking the same place we just
    //    asked for the private one is admittedly circular — a subnet that would
    //    lie here already holds the master key. The non-circular check is on the
    //    client, which derives the key offline and refuses to encrypt on a
    //    mismatch.
    let dpk_bytes = vetkd_public_key(&VetKDPublicKeyArgs {
        canister_id: None,
        context: CONTEXT.to_vec(),
        key_id: key_id(),
    })
    .await
    .map_err(|e| format!("vetkd_public_key: {e}"))?
    .public_key;

    let dpk = DerivedPublicKey::deserialize(&dpk_bytes).map_err(|e| format!("bad dpk: {e:?}"))?;

    let vetkey = EncryptedVetKey::deserialize(&reply.encrypted_key)
        .map_err(|e| format!("bad encrypted key: {e}"))?
        .decrypt_and_verify(&tsk, &dpk, KEY_LABEL)
        .map_err(|e| format!("the subnet returned a key we cannot verify: {e}"))?;

    VETKEY.with_borrow_mut(|v| *v = Some(vetkey.clone()));
    Ok(vetkey)
}

/// Stores a secret that was encrypted to this canister's public key.
///
/// Decrypting here rather than storing the blob is deliberate: a ciphertext
/// sealed under the wrong context, label or key fails now, in front of whoever
/// is seeding it, instead of being accepted and found unreadable later.
///
/// Storing several secrets costs one derivation in total, not one each — they
/// all share `KEY_LABEL`, so the cached key opens every one of them.
#[update]
async fn set_dummy_secret(name: String, ciphertext: Vec<u8>) -> Result<(), String> {
    // Whoever seeds a secret should be whoever controls the canister.
    // Ungated, anyone could overwrite one with a value of their choosing.
    if !ic_cdk::api::is_controller(&ic_cdk::api::msg_caller()) {
        return Err("only a controller may set a secret".to_string());
    }

    let vetkey = vetkey().await?;

    let plaintext = IbeCiphertext::deserialize(&ciphertext)
        .map_err(|e| format!("not an IBE ciphertext: {e}"))?
        .decrypt(&vetkey)
        .map_err(|_| "ciphertext was not sealed to this canister's key".to_string())?;

    let text = String::from_utf8(plaintext).map_err(|_| "secret is not UTF-8".to_string())?;
    SECRETS.with_borrow_mut(|s| s.insert(name, text));
    Ok(())
}

/// Returns a decrypted secret **in the clear**.
///
/// # This exists only so you can see that decryption worked
///
/// A real canister must not have this. The reply is not encrypted end-to-end:
/// the boundary node terminates TLS and is outside the subnet's trust boundary,
/// so this hands the secret straight back out — undoing, on the way out, exactly
/// what sealing achieved on the way in.
///
/// Controller-gated, which is not much of a defence (a controller can install
/// code that reads the secret anyway) but keeps the PoC from being an open
/// oracle while it is deployed.
#[query]
fn get_dummy_secret(name: String) -> Result<Option<String>, String> {
    if !ic_cdk::api::is_controller(&ic_cdk::api::msg_caller()) {
        return Err("only a controller may read a secret".to_string());
    }
    Ok(SECRETS.with_borrow(|s| s.get(&name).cloned()))
}

ic_cdk::export_candid!();
