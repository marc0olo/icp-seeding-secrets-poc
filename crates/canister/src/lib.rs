//! A proof-of-concept canister that receives secrets sealed with vetKD IBE and
//! decrypts them in memory.
//!
//! The point of the exercise: a client encrypts an API key to a public key it
//! derives offline, sends the ciphertext in an ordinary update call, and only
//! this canister — on a subnet holding the vetKD key — can recover the plaintext.
//! On a SEV-SNP subnet the decrypted value is protected from node operators by
//! memory encryption and a launch-measurement-keyed data disk.
//!
//! Read `README.md` before deploying this anywhere real; in particular, note that
//! a controller can read the plaintext out of a snapshot without upgrading the
//! canister, so the guarantee only means something for a blackholed or governed
//! canister.

mod keys;
mod store;
mod types;

use candid::CandidType;
use ic_cdk::{init, post_upgrade, query, update};
use sealed_secrets_core::validate_secret_name;
use serde::Deserialize;
use serde_bytes::ByteBuf;
use sha2::{Digest, Sha256};

use store::{Config, SealedRecord};
use types::{KeySource, SealedSecretEntry, SealedSecretInfo, SealedSecretsError, SelfTestReport};

/// Version of the wire interface this canister speaks.
const STANDARD_VERSION: u32 = 1;

/// Installation arguments.
///
/// Just the key name. The canister asks the subnet for its public key rather
/// than deriving it from a compiled-in constant, so the same build runs against
/// a local network and mainnet with nothing to configure — and nothing to get
/// wrong in a way that silently orphans every sealed ciphertext.
#[derive(CandidType, Deserialize, Debug, Clone)]
pub struct InitArgs {
    /// vetKD key name, e.g. `key_1`.
    pub key_name: String,
}

#[init]
fn init(args: InitArgs) {
    store::set_config(Config {
        key_name: args.key_name,
        ..Config::default()
    });
}

#[post_upgrade]
fn post_upgrade() {
    // Nothing to do: configuration and ciphertexts are in stable memory, and the
    // caches rebuild lazily on first use. Deliberately does not rewrite the
    // config — an upgrade must not be able to silently change the derivation and
    // orphan every stored ciphertext.
}

fn require_controller() -> Result<(), SealedSecretsError> {
    if ic_cdk::api::is_controller(&ic_cdk::api::msg_caller()) {
        Ok(())
    } else {
        Err(SealedSecretsError::Unauthorized)
    }
}

/// Everything a client needs to seal for this canister.
///
/// An update rather than a query, because `public_key` comes from
/// `vetkd_public_key` — authoritative for whichever subnet this canister is
/// actually on. It is cached, so only the first call pays for the round trip.
///
/// A client must treat `public_key` as a cross-check against its **own** offline
/// derivation, never as the key to encrypt to. That comparison is the real
/// defence: this response crosses boundary nodes, and a client that trusted it
/// could be handed a key an attacker controls.
#[update]
async fn icp_sealed_secret_info() -> Result<SealedSecretInfo, SealedSecretsError> {
    let config = store::config();
    let context = keys::context()?;
    let public_key = keys::public_key().await?;

    Ok(SealedSecretInfo {
        standard_version: STANDARD_VERSION,
        context: ByteBuf::from(context),
        identity: ByteBuf::from(keys::identity(config.epoch)),
        epoch: config.epoch,
        key_name: config.key_name,
        public_key: ByteBuf::from(public_key.serialize()),
        max_ciphertext_len: config.max_ciphertext_len,
        max_secrets: config.max_secrets,
    })
}

/// Stores a sealed secret, after proving it can actually be decrypted.
///
/// The trial decryption is the whole point of making this `async` rather than a
/// cheap synchronous write. Without it, a ciphertext sealed under the wrong
/// context, epoch or key id is accepted happily and only discovered to be
/// unreadable at the first production use, potentially months later.
///
/// Returns the new revision.
#[update]
async fn icp_sealed_secret_set(
    name: String,
    ciphertext: ByteBuf,
) -> Result<u64, SealedSecretsError> {
    require_controller()?;
    validate_secret_name(&name).map_err(|e| SealedSecretsError::InvalidName(e.to_string()))?;

    let config = store::config();
    let ciphertext = ciphertext.into_vec();

    if ciphertext.len() as u64 > config.max_ciphertext_len {
        return Err(SealedSecretsError::TooLarge {
            max: config.max_ciphertext_len,
        });
    }

    let existing = store::get_record(&name);
    if existing.is_none() && store::len() >= config.max_secrets {
        return Err(SealedSecretsError::TooMany {
            max: config.max_secrets,
        });
    }

    // Fails here, in front of the deployer, rather than in production.
    let _plaintext = keys::decrypt_with_epoch(&ciphertext, config.epoch).await?;

    let now = ic_cdk::api::time();
    let revision = existing.as_ref().map(|r| r.revision + 1).unwrap_or(0);
    let created_at_ns = existing.as_ref().map(|r| r.created_at_ns).unwrap_or(now);

    store::put_record(
        &name,
        SealedRecord {
            epoch: config.epoch,
            revision,
            created_at_ns,
            updated_at_ns: now,
            ciphertext_sha256: Sha256::digest(&ciphertext).to_vec(),
            ciphertext,
        },
    );

    Ok(revision)
}

/// Removes a secret and drops its cached plaintext.
#[update]
fn icp_sealed_secret_unset(name: String) -> Result<(), SealedSecretsError> {
    require_controller()?;
    match store::remove_record(&name) {
        Some(_) => {
            keys::purge_plaintext(&name);
            Ok(())
        }
        None => Err(SealedSecretsError::NotFound),
    }
}

/// Lists stored secrets.
///
/// Controller-gated, because it is more revealing than it looks: IBE overhead is
/// a fixed 136 bytes, so `ciphertext_len` gives the exact plaintext length, and
/// the names alone (`stripe_live_key`, …) are useful reconnaissance.
///
/// Nothing here is derived from a plaintext. A digest of the plaintext would be
/// an offline guessing oracle for low-entropy secrets; a digest of a randomised
/// ciphertext reveals nothing, while still letting a client confirm its upload
/// landed.
#[query]
fn icp_sealed_secret_list() -> Result<Vec<SealedSecretEntry>, SealedSecretsError> {
    require_controller()?;
    Ok(store::all_records()
        .into_iter()
        .map(|(name, r)| SealedSecretEntry {
            name,
            epoch: r.epoch,
            revision: r.revision,
            ciphertext_len: r.ciphertext.len() as u64,
            ciphertext_sha256: ByteBuf::from(r.ciphertext_sha256),
            created_at_ns: r.created_at_ns,
            updated_at_ns: r.updated_at_ns,
        })
        .collect())
}

/// Exercises the full decryption path and reports what actually happened.
///
/// Run this right after deploying and after every upgrade. It is the difference
/// between finding out at deploy time that this subnet does not hold the vetKD
/// key, and finding out during a customer request.
///
/// Pass `expected_source` to also audit the subnet's `vetkd_public_key` against a
/// master key compiled into this Wasm — the one check in the whole design that is
/// not the subnet vouching for itself. Do this once per deployment with the
/// network you believe you are on.
#[update]
async fn icp_sealed_secret_self_test(
    expected_source: Option<KeySource>,
) -> Result<SelfTestReport, SealedSecretsError> {
    require_controller()?;

    let config = store::config();
    let context = keys::context()?;
    let records = store::all_records();

    let reported = keys::reported_public_key().await.ok();

    // The audit: does the subnet's own answer match a master key compiled into
    // this Wasm, for the network the caller believes they are on? `None` means
    // the caller did not ask, or we hold no master key for this name.
    let public_key_matches_master = match (expected_source, &reported) {
        (Some(source), Some(remote)) => {
            keys::expected_public_key(source.into()).map(|expected| &expected == remote)
        }
        _ => None,
    };

    let vetkd_derive_ok = keys::vetkey(config.epoch).await.is_ok();

    let mut undecryptable = Vec::new();
    for (name, record) in &records {
        if keys::open(name, record).await.is_err() {
            undecryptable.push(name.clone());
        }
    }

    Ok(SelfTestReport {
        vetkd_public_key_ok: reported.is_some(),
        vetkd_derive_ok,
        public_key_matches_master,
        effective_key_name: config.key_name,
        effective_context: ByteBuf::from(context),
        epoch: config.epoch,
        num_secrets: records.len() as u64,
        undecryptable,
    })
}

/// Test hook: SHA-256 of a decrypted secret.
///
/// This exists so an end-to-end test can prove the canister recovered the exact
/// plaintext, without any endpoint ever returning a plaintext. Note it is still
/// an oracle for a guessed value, so it is controller-gated and has no business
/// being in a production build — it is the one thing to delete when adapting this
/// PoC. The naming is deliberate: `secret_sha256` should look conspicuous.
#[update]
async fn secret_sha256(name: String) -> Result<ByteBuf, SealedSecretsError> {
    require_controller()?;
    let record = store::get_record(&name).ok_or(SealedSecretsError::NotFound)?;
    let plaintext = keys::open(&name, &record).await?;
    Ok(ByteBuf::from(Sha256::digest(plaintext.as_slice()).to_vec()))
}

/// Demonstrates the intended shape of *using* a secret: the plaintext is read
/// inside the canister and only a derived result leaves it.
///
/// A real canister would put the value in an outcall header here. Read §4.1 of
/// the README first — the request context, headers included, enters replicated
/// state on every node, so this is only safe on a uniformly SEV-SNP subnet.
#[update]
async fn secret_len(name: String) -> Result<u64, SealedSecretsError> {
    require_controller()?;
    let record = store::get_record(&name).ok_or(SealedSecretsError::NotFound)?;
    let plaintext = keys::open(&name, &record).await?;
    Ok(plaintext.len() as u64)
}

ic_cdk::export_candid!();
