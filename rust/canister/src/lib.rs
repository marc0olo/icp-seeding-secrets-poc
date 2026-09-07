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
//!   value is deployed; `list` and `unset` are convenience.
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
use types::{SealedSecretEntry, SealedSecretsError};

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
    });
}

#[post_upgrade]
fn post_upgrade() {
    // Nothing to do: configuration and secrets are in stable memory, and the
    // vetKey cache rebuilds lazily on first use. Deliberately does not rewrite
    // the config — an upgrade must not be able to silently change the derivation
    // and so reject every subsequently sealed ciphertext.
}

fn require_controller() -> Result<(), SealedSecretsError> {
    if ic_cdk::api::is_controller(&ic_cdk::api::msg_caller()) {
        Ok(())
    } else {
        Err(SealedSecretsError::Unauthorized)
    }
}

/// Stores a sealed secret, after proving it can actually be decrypted.
///
/// The decryption is the whole point of making this `async` rather than a cheap
/// synchronous write. Without it, a ciphertext sealed to the wrong canister id,
/// key name or master key table is accepted happily and only discovered to be
/// unreadable at the first production use, potentially months later. It is also
/// the only health check this interface needs: it exercises `vetkd_public_key`,
/// `vetkd_derive_key`, verification and decryption, on real data.
///
/// Returns the new revision.
#[update]
async fn icp_sealed_secret_set(
    name: String,
    ciphertext: ByteBuf,
) -> Result<u64, SealedSecretsError> {
    require_controller()?;
    validate_secret_name(&name).map_err(|e| SealedSecretsError::InvalidName(e.to_string()))?;

    let ciphertext = ciphertext.into_vec();
    let existing = store::get_record(&name);

    // Fails here, in front of the deployer, rather than in production — and its
    // output is what gets stored, so the decryption is not merely a check.
    let plaintext = keys::decrypt(&ciphertext).await?;

    let now = ic_cdk::api::time();
    let revision = existing.as_ref().map(|r| r.revision + 1).unwrap_or(0);
    let created_at_ns = existing.as_ref().map(|r| r.created_at_ns).unwrap_or(now);

    store::put_record(
        &name,
        SealedRecord {
            revision,
            created_at_ns,
            updated_at_ns: now,
            ciphertext_sha256: Sha256::digest(&ciphertext).to_vec(),
            // The decryption above produced this. Storing it is what lets every
            // later read be a map lookup instead of a vetKD round trip.
            plaintext: plaintext.to_vec(),
        },
    );

    Ok(revision)
}

/// Removes a secret.
#[update]
fn icp_sealed_secret_unset(name: String) -> Result<(), SealedSecretsError> {
    require_controller()?;
    match store::remove_record(&name) {
        // Nothing to purge: the record was the only copy, so removing it is the
        // whole operation.
        Some(_) => Ok(()),
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

    // Only the candidate is sealed; the stored side is already plaintext. The
    // comparison stays constant-time regardless, because a timing difference
    // would leak how many leading bytes a guess got right.
    let candidate_plaintext = keys::decrypt(&candidate.into_vec()).await?;

    Ok(bool::from(
        record
            .plaintext
            .as_slice()
            .ct_eq(candidate_plaintext.as_slice()),
    ))
}

/// Lists stored secrets: the inventory, and how a client confirms its write
/// landed.
///
/// Controller-gated, because names alone (`billing_live_key`, …) are useful
/// reconnaissance.
///
/// Nothing here is derived from a plaintext. A digest of the plaintext would be
/// an offline guessing oracle for low-entropy secrets; a digest of a randomised
/// ciphertext reveals nothing, while still letting the client that produced it
/// recognise its own upload.
#[query]
fn icp_sealed_secret_list() -> Result<Vec<SealedSecretEntry>, SealedSecretsError> {
    require_controller()?;
    Ok(store::all_records()
        .into_iter()
        .map(|(name, r)| SealedSecretEntry {
            name,
            revision: r.revision,
            ciphertext_sha256: ByteBuf::from(r.ciphertext_sha256),
            created_at_ns: r.created_at_ns,
            updated_at_ns: r.updated_at_ns,
        })
        .collect())
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
    let token = core::str::from_utf8(&record.plaintext)
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
/// pointed at the identical vector from `motoko/vectors.json`.
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
fn secret_reveal(name: String) -> Result<String, SealedSecretsError> {
    require_controller()?;
    let record = store::get_record(&name).ok_or(SealedSecretsError::NotFound)?;
    String::from_utf8(record.plaintext)
        .map_err(|_| SealedSecretsError::Internal("secret is not valid UTF-8".to_string()))
}

ic_cdk::export_candid!();
