//! A proof-of-concept canister that receives secrets sealed with vetKD IBE,
//! decrypts them in memory, and uses them.
//!
//! The point of the exercise: a client encrypts an API key to a public key it
//! derives offline, sends the ciphertext in an ordinary update call, and only
//! this canister — on a subnet holding the vetKD key — can recover the plaintext.
//! On a SEV-SNP subnet the decrypted value is protected from node operators by
//! memory encryption and a launch-measurement-keyed data disk.
//!
//! The endpoints fall into three groups:
//!
//! - **The proposed standard.** `icp_sealed_secret_{info,set}` are what any tool
//!   needs to seal; `matches` is what an operator needs to confirm the right
//!   value is deployed; `list`, `unset` and `self_test` are convenience.
//! - **The worked example**, and the reason any of this exists:
//!   `call_api_with_secret` authenticates an outbound HTTPS request with a sealed
//!   secret, and `strip_response` makes its reply deterministic enough for
//!   consensus. Neither is part of the standard — a real canister writes its own.
//! - **A test hook.** `secret_reveal` returns a plaintext and exists only behind
//!   `--features test-hooks`, so a human can watch the round trip work.
//!
//! Read `README.md` before deploying this anywhere real. In particular: a
//! controller can read the plaintext — by installing code that decrypts, or by
//! snapshotting the heap — because vetKD binds the key to the canister ID rather
//! than the module hash. For the case this is built for that is not a defect: the
//! controller is whoever seeded the secret. It matters only if your threat model
//! puts the controller in scope, and the answer there is governance, not
//! blackholing, which would leave a canister that can never be seeded or rotated.

mod keys;
mod store;
mod types;

use candid::CandidType;
use ic_cdk::{init, post_upgrade, query, update};
use ic_cdk_management_canister::{
    HttpHeader, HttpMethod, HttpRequestArgs, HttpRequestResult, TransformArgs,
};
use sealed_secrets_core::validate_secret_name;
use serde::Deserialize;
use serde_bytes::ByteBuf;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use store::{Config, SealedRecord};
use types::{KeySource, SealedSecretEntry, SealedSecretInfo, SealedSecretsError, SelfTestReport};

/// Version of the wire interface this canister speaks.
const STANDARD_VERSION: u32 = 1;

/// Where `call_api_with_secret` sends its authenticated request.
///
/// postman-echo's `/basic-auth` genuinely **evaluates** the credential — the
/// documented `postman:password` gets `200 {"authenticated":true}`, anything else
/// gets `401` — and it does not echo the credential back, which matters because
/// the response body enters replicated state on every node.
///
/// Using a *publicly documented* credential is right for a demo and wrong for
/// production, and the distinction is worth being precise about. A published
/// credential proves nothing about **secrecy**. But it is ideal for proving the
/// **mechanism**, because the test can seal the correct value and see `200`, then
/// seal a wrong one and see `401`, with no setup and no real key anywhere. An
/// endpoint that ignores `Authorization` could not show that: it answers `200`
/// whatever the canister sends.
///
/// Point this at your own API for anything real.
const DEMO_API_ENDPOINT: &str = "https://postman-echo.com/basic-auth";

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

/// Answers "is the value I hold the one you have stored?" without either side
/// disclosing it.
///
/// The caller seals its candidate exactly as it would for `set` — a fresh IBE
/// seed, so the ciphertext is unlinkable to any other — and the canister decrypts
/// both and compares in constant time. One bit comes back.
///
/// This is the endpoint an operator should reach for when they want to confirm
/// the right secret is deployed, and it is deliberately *not* "return me a
/// digest of the plaintext":
///
/// - a digest of a low-entropy secret is brute-forceable offline by anyone who
///   sees it, and replies cross a boundary node in the clear;
/// - the caller already knows the value they are checking, so a boolean tells
///   them everything a digest would;
/// - a ciphertext discloses nothing in the request direction either, whereas
///   sending `sha256(expected)` would put the same brute-forceable digest on the
///   wire.
///
/// Controller-gated, because for anyone else it is an oracle for confirming
/// guesses. For a controller it discloses nothing new — they can already read
/// the secret by installing code that decrypts it.
#[update]
async fn icp_sealed_secret_matches(
    name: String,
    candidate: ByteBuf,
) -> Result<bool, SealedSecretsError> {
    require_controller()?;

    let record = store::get_record(&name).ok_or(SealedSecretsError::NotFound)?;
    let config = store::config();

    // Each side is opened under its own epoch: a client seals against the
    // current one, while a stored record may predate a rotation.
    let candidate_plaintext = keys::decrypt_with_epoch(&candidate.into_vec(), config.epoch).await?;
    let stored_plaintext = keys::open(&name, &record).await?;

    Ok(bool::from(
        stored_plaintext
            .as_slice()
            .ct_eq(candidate_plaintext.as_slice()),
    ))
}

/// Lists stored secrets.
///
/// Controller-gated, because it is more revealing than it looks: IBE overhead is
/// a fixed 136 bytes, so `ciphertext_len` gives the exact plaintext length, and
/// the names alone (`billing_live_key`, …) are useful reconnaissance.
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

/// The actual use case: authenticate an outbound HTTPS request with a sealed
/// secret, without the secret ever leaving the canister.
///
/// This is what the whole exercise is for, so read it as the template.
///
/// The sealed secret is the **complete `Authorization` header value**, not just a
/// token, so it works for any scheme — `Bearer ghp_…`, `Basic dXNlcjpwYXNz`, or
/// whatever an API expects — without this code baking one in.
///
/// Seal the correct credential and this returns `200`; seal a wrong one and it
/// returns `401`. That both branches are observable is the point: it proves the
/// secret's *value* reached the API and was evaluated, not merely that a request
/// went out.
///
/// **The endpoint is a constant, not a parameter.** A `call_api(url, ...)` taking
/// the URL from the caller would be an exfiltration primitive: point it at a
/// server you control and the secret is yours. A controller could achieve that
/// anyway by installing code, but shipping the capability as an endpoint is
/// gratuitous, and real canisters call a known API rather than an arbitrary one.
///
/// **Only the status code comes back.** Returning the body would be a mistake
/// waiting to happen: plenty of endpoints echo request headers (`/headers`,
/// `/anything`, most debug routes), and echoing our own `Authorization` header
/// back through the reply would undo the sealing entirely.
///
/// **The transform is mandatory, not decoration.** Every node performs this call
/// independently and consensus requires byte-identical responses, so anything
/// varying per node — `Date`, request ids, cookies — must be stripped or the call
/// fails.
///
/// Note the exposure, which the README covers in full: the request context,
/// headers included, enters replicated state on **every** node of the subnet
/// before any of them executes the call. On a SEV-SNP subnet that memory and the
/// checkpoints behind it are encrypted; on any other subnet the secret is
/// readable by every node operator the moment this runs.
#[update]
async fn call_api_with_secret(
    name: String,
    idempotency_key: String,
) -> Result<u16, SealedSecretsError> {
    require_controller()?;

    let record = store::get_record(&name).ok_or(SealedSecretsError::NotFound)?;
    let plaintext = keys::open(&name, &record).await?;
    let token = core::str::from_utf8(plaintext.as_slice())
        .map_err(|_| SealedSecretsError::Internal("secret is not valid UTF-8".to_string()))?;

    let request = HttpRequestArgs {
        url: DEMO_API_ENDPOINT.to_string(),
        method: HttpMethod::GET,
        headers: vec![
            // The secret is the whole header value. See above.
            HttpHeader {
                name: "Authorization".to_string(),
                value: token.to_string(),
            },
            // Not optional for anything that mutates — see the doc comment.
            HttpHeader {
                name: "Idempotency-Key".to_string(),
                value: idempotency_key,
            },
            HttpHeader {
                name: "User-Agent".to_string(),
                value: "icp-sealed-secrets-poc".to_string(),
            },
        ],
        body: None,
        // Keep this tight: the call is priced on it.
        max_response_bytes: Some(2_048),
        transform: Some(ic_cdk_management_canister::transform_context_from_query(
            "strip_response".to_string(),
            vec![],
        )),
        ..Default::default()
    };

    let response = ic_cdk_management_canister::http_request(&request)
        .await
        .map_err(|e| SealedSecretsError::Internal(format!("http_request failed: {e}")))?;

    // Only the status. See above.
    u16::try_from(response.status.0)
        .map_err(|_| SealedSecretsError::Internal("implausible status code".to_string()))
}

/// Makes an HTTP response deterministic across the nodes that fetched it.
///
/// Drops every response header — they carry `Date`, request ids and cookies that
/// differ per node, which would break consensus — and, incidentally, stops an
/// endpoint that echoes our `Authorization` header from smuggling the secret into
/// replicated state.
///
/// **This passes the body through unchanged, which is only safe because the demo
/// endpoint returns a constant.** If yours returns a timestamp, a request id or
/// anything else that differs between fetches, normalise it here too — parse out
/// the fields you need and drop the rest. Local testing will not catch this:
/// PocketIC issues exactly one request, so a varying body agrees with itself,
/// while on mainnet every node fetches independently and the call fails.
#[query]
fn strip_response(args: TransformArgs) -> HttpRequestResult {
    HttpRequestResult {
        status: args.response.status,
        headers: vec![],
        body: args.response.body,
    }
}

/// Measures what an IBE decryption costs in this canister, in instructions.
/// **Requires the `test-hooks` feature.**
///
/// Exists so the Rust and Motoko implementations can be compared on the same
/// footing. Native benchmarks are not comparable — what matters is the
/// instruction count the replica charges, and that is wasm-specific.
///
/// Takes the vetKey and ciphertext as arguments so both implementations can be
/// pointed at the identical vector from `motoko/bls12-381/test/vectors.json`.
///
/// **The first call costs about three times the rest.** `ic-vetkeys` holds a
/// `lazy_static` precomputed multiplication table for the `G2` generator
/// (`utils/mod.rs:219`), built on first use and reused thereafter. Quote the
/// steady-state figure when comparing, and remember the Motoko port has no such
/// table — a plain double-and-add ladder — so the gap is partly a missing
/// optimisation rather than a property of the language.
#[cfg(feature = "test-hooks")]
#[update]
fn bench_ibe_decrypt(vetkey: ByteBuf, ciphertext: ByteBuf) -> Result<u64, SealedSecretsError> {
    require_controller()?;

    let key = ic_vetkeys::VetKey::deserialize(&vetkey)
        .map_err(|e| SealedSecretsError::Internal(format!("bad vetkey: {e}")))?;
    let ct = ic_vetkeys::IbeCiphertext::deserialize(&ciphertext)
        .map_err(|e| SealedSecretsError::InvalidCiphertext(e))?;

    let before = ic_cdk::api::performance_counter(0);
    let plaintext = ct
        .decrypt(&key)
        .map_err(|_| SealedSecretsError::InvalidCiphertext("decrypt failed".to_string()))?;
    let after = ic_cdk::api::performance_counter(0);

    // Touch the result so the optimiser cannot elide the work being measured.
    if plaintext.is_empty() {
        return Err(SealedSecretsError::Internal("empty plaintext".to_string()));
    }

    Ok(after - before)
}

/// Returns a decrypted secret **in the clear**. Requires the `test-hooks` feature.
///
/// It exists so you can see with your own eyes that decryption worked. It must
/// never be in a real deployment, and the reason is not that a controller could
/// not obtain the secret anyway — they can, by installing code that decrypts, or
/// by reading the heap out of a snapshot.
///
/// The reason is that this endpoint:
///
/// 1. **sends the plaintext to a boundary node.** The reply is not encrypted
///    end-to-end; the boundary node terminates TLS and is outside the subnet's
///    SEV-SNP trust boundary entirely. That undoes, in the outbound direction,
///    exactly what sealing achieved on the way in.
/// 2. **destroys the property that makes the code auditable.** "The published
///    code never returns the plaintext" is a claim a reader can verify by
///    reading it. Replace it with "…unless the caller is a controller" and the
///    guarantee now rests on the controller set being, and remaining, what you
///    think it is.
/// 3. **leaves no trace.** Installing code that leaks changes the module hash,
///    which is visible in the state tree. A call to this leaves nothing behind.
///
/// If you want to confirm the right secret is deployed, use
/// `icp_sealed_secret_matches` instead — it answers the same question with one
/// bit and is safe to keep in a production build.
#[cfg(feature = "test-hooks")]
#[update]
async fn secret_reveal(name: String) -> Result<String, SealedSecretsError> {
    require_controller()?;
    let record = store::get_record(&name).ok_or(SealedSecretsError::NotFound)?;
    let plaintext = keys::open(&name, &record).await?;
    String::from_utf8(plaintext.to_vec())
        .map_err(|_| SealedSecretsError::Internal("secret is not valid UTF-8".to_string()))
}

ic_cdk::export_candid!();
