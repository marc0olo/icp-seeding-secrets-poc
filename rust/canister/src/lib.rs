//! A canister that receives one secret, encrypted with vetKD IBE.
//!
//! The whole mechanism, in two endpoints:
//!
//!   set_dummy_secret(ciphertext)  have our private key derived, then decrypt
//!   get_dummy_secret()            hand the plaintext back so you can see it worked
//!
//! The client encrypts to a public key it derives **offline** — no network call,
//! nothing to trust — and only this canister can have the matching private key
//! derived for it. See ../../README.md.

use ic_cdk::{query, update};
use ic_cdk_management_canister::{
    raw_rand, vetkd_derive_key, vetkd_public_key, VetKDCurve, VetKDDeriveKeyArgs, VetKDKeyId,
    VetKDPublicKeyArgs,
};
use ic_vetkeys::{DerivedPublicKey, EncryptedVetKey, IbeCiphertext, TransportSecretKey};
use std::cell::RefCell;

/// The vetKD **context**: what selects the *keypair*.
///
/// The derivation is master key -> canister id -> context, so changing this byte
/// for byte gives this canister an entirely different keypair. One context per
/// purpose: a canister using vetKD for two unrelated things gives each its own,
/// and neither can open the other's ciphertext.
const CONTEXT: &[u8] = b"dummy-secret-poc";

/// Which secret this is: a label, not a key and not the value.
///
/// In vetKD terms it is the **IBE identity**, and it goes out as the `input` to
/// `vetkd_derive_key`. The context fixes a keypair; this picks one of the
/// infinitely many keys under it. The client seals to the same label, and a
/// different one would derive a different key that cannot open the ciphertext.
///
/// One label here, because there is one secret. Holding several, you could give
/// each its own — but inside a single canister that buys nothing and costs real
/// money: each distinct label is a separate `vetkd_derive_key` at 26 billion
/// cycles, and there is no privilege boundary to enforce, since this canister's
/// code can derive any label's key whenever it likes.
const SECRET_NAME: &[u8] = b"dummy-secret";

/// The vetKD key to use. `key_1` exists on mainnet and on a local network, so
/// one constant covers both. A canister that needed another would
/// change this line — deliberately not an install argument, because `#[init]`
/// does not re-run on upgrade and an empty key name fails with a message that
/// does not point at the cause.
const KEY_NAME: &str = "key_1";

thread_local! {
    /// The decrypted secret. Deliberately not persisted across upgrades: a PoC
    /// should make you re-seal and watch it work again.
    static SECRET: RefCell<Option<String>> = const { RefCell::new(None) };
}

fn key_id() -> VetKDKeyId {
    VetKDKeyId {
        curve: VetKDCurve::Bls12_381_G2,
        name: KEY_NAME.to_string(),
    }
}

/// Stores a secret that was encrypted to this canister's public key.
///
/// Everything interesting happens here. The canister does not hold a private
/// key — it has nowhere to hide one, since its whole memory is replicated — so
/// it has one reconstructed on demand, uses it once, and lets it go.
#[update]
async fn set_dummy_secret(ciphertext: Vec<u8>) -> Result<(), String> {
    // Whoever seeds the secret should be whoever controls the canister.
    // Ungated, anyone could overwrite it with a value of their choosing.
    if !ic_cdk::api::is_controller(&ic_cdk::api::msg_caller()) {
        return Err("only a controller may set the secret".to_string());
    }

    // 1. A single-use transport keypair. The private key never leaves here; the
    //    public half goes out with the request.
    //
    //    This is what keeps the vetKey off the wire and out of replicated state:
    //    the nodes do not reconstruct it and then encrypt it, they compute their
    //    shares ALREADY encrypted under this public key. The plaintext key
    //    therefore exists nowhere until step 3 unwraps it, here.
    let seed = raw_rand().await.map_err(|e| format!("raw_rand: {e}"))?;
    let tsk = TransportSecretKey::from_seed(seed).map_err(|e| format!("transport key: {e}"))?;

    // 2. Ask for the private key belonging to (this canister, CONTEXT, SECRET_NAME).
    //    The management canister routes this to a subnet holding the key — not
    //    necessarily our own — where each node contributes a share and none ever
    //    holds the whole key. What binds the result to us is the caller's
    //    canister id being an input to the derivation.
    let reply = vetkd_derive_key(&VetKDDeriveKeyArgs {
        input: SECRET_NAME.to_vec(),
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
    //    the result is a valid BLS signature over SECRET_NAME under `dpk`. That
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
        .decrypt_and_verify(&tsk, &dpk, SECRET_NAME)
        .map_err(|e| format!("the subnet returned a key we cannot verify: {e}"))?;

    // 4. Decrypt. Failing here means the ciphertext was sealed to a different
    //    key — wrong canister id, wrong context, or the wrong master key table.
    let plaintext = IbeCiphertext::deserialize(&ciphertext)
        .map_err(|e| format!("not an IBE ciphertext: {e}"))?
        .decrypt(&vetkey)
        .map_err(|_| "ciphertext was not sealed to this canister's key".to_string())?;

    let text = String::from_utf8(plaintext).map_err(|_| "secret is not UTF-8".to_string())?;
    SECRET.set(Some(text));
    Ok(())
}

/// Returns the decrypted secret **in the clear**.
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
fn get_dummy_secret() -> Result<Option<String>, String> {
    if !ic_cdk::api::is_controller(&ic_cdk::api::msg_caller()) {
        return Err("only a controller may read the secret".to_string());
    }
    Ok(SECRET.with_borrow(|s| s.clone()))
}

ic_cdk::export_candid!();
