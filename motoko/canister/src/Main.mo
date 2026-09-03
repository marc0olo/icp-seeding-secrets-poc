/// A Motoko canister that receives secrets sealed with vetKD IBE.
///
/// Mirrors `rust/canister/src/lib.rs` endpoint for endpoint, so the same
/// TypeScript seeder drives either one. Where the two diverge internally, the
/// reason is written down at the divergence — see `Keys.mo` on persistence.
///
/// ⚠️ This depends on an **experimental, unaudited** BLS12-381 implementation.
/// It is a demonstration that Motoko can do this, not a recommendation that it
/// should yet.

import Keys "Keys";
import Format "Format";
import Store "Store";
import Types "Types";

import Array "mo:core/Array";
import Blob "mo:core/Blob";
import Error "mo:core/Error";
import Map "mo:core/Map";
import Int "mo:core/Int";
import Iter "mo:core/Iter";
import Nat "mo:core/Nat";
import Nat32 "mo:core/Nat32";
import Nat64 "mo:core/Nat64";
import Principal "mo:core/Principal";
import Text "mo:core/Text";
import Time "mo:core/Time";
import Sha256 "mo:sha2/Sha256";

persistent actor class SealedSecrets(initArgs : { key_name : Text }) = self {

  // ---------------------------------------------------------------- state

  /// Pinned at first init and kept across upgrades. See `Store.Config`.
  let config : Store.Config = Store.defaultConfig(initArgs.key_name);

  /// Ciphertexts. The durable artifact — a plaintext is always reproducible
  /// from one of these plus a vetKey.
  let secrets : Store.Secrets = Store.emptySecrets();

  /// Derived keys. Deliberately **not** `transient`: under orthogonal
  /// persistence they survive an upgrade for free, so the canister does not pay
  /// a `vetkd_derive_key` — the call, its fee and a consensus round — to
  /// reproduce something the runtime was going to keep anyway.
  let caches : Keys.Caches = Keys.emptyCaches();

  /// Decrypted secrets. `transient`, so the ciphertext stays the one durable
  /// copy. Re-decrypting after an upgrade is pure computation, which is the
  /// cheap half; see `Keys.mo`.
  transient let plaintexts : Keys.Plaintexts = Keys.emptyPlaintexts();

  /// Behaviour only — methods are not a stable type, so this is rebuilt on every
  /// upgrade and reattached to the state above.
  transient let keys = Keys.Manager(config.keyName, caches, plaintexts);

  /// Where `call_api_with_secret` sends its authenticated request.
  ///
  /// postman-echo's `/basic-auth` genuinely **evaluates** the credential — the
  /// documented `postman:password` gets `200 {"authenticated":true}`, anything
  /// else gets `401` — and it does not echo the credential back, which matters
  /// because the response body enters replicated state.
  transient let DEMO_API_ENDPOINT = "https://postman-echo.com/basic-auth";

  transient let IC : actor {
    http_request : shared HttpRequestArgs -> async HttpRequestResult;
  } = actor ("aaaaa-aa");

  public type HttpHeader = { name : Text; value : Text };

  public type HttpRequestResult = {
    status : Nat;
    headers : [HttpHeader];
    body : Blob;
  };

  public type TransformArgs = { response : HttpRequestResult; context : Blob };

  type HttpRequestArgs = {
    url : Text;
    max_response_bytes : ?Nat64;
    headers : [HttpHeader];
    body : ?Blob;
    method : { #get; #post; #head };
    transform : ?{
      function : shared query TransformArgs -> async HttpRequestResult;
      context : Blob;
    };
  };

  // ---------------------------------------------------------------- helpers

  func isController(p : Principal) : Bool = Principal.isController(p);

  func requireController(caller : Principal) : ?Types.SealedSecretsError =
    if (isController(caller)) { null } else { ?#Unauthorized };

  func now() : Nat64 = Nat.toNat64(Int.abs(Time.now()));

  func sha256(b : Blob) : Blob = Sha256.fromBlob(#sha256, b);

  func checkName(name : Text) : ?Types.SealedSecretsError =
    switch (Format.validateSecretName(name)) {
      case (#ok) null;
      case (#err(e)) ?#InvalidName(Format.errorText(e));
    };

  // ---------------------------------------------------------------- endpoints

  /// Everything a client needs in order to seal for this canister.
  ///
  /// An update rather than a query, because `public_key` comes from
  /// `vetkd_public_key` — an inter-canister call, which a query cannot make. The
  /// result is cached, so only the first call after a cold start pays for it.
  ///
  /// A client must treat `public_key` as a cross-check against its own offline
  /// derivation, never as the key to encrypt to. That comparison is the real
  /// defence: this response crosses boundary nodes, and a client that trusted it
  /// could be handed a key an attacker controls.
  public func icp_sealed_secret_info() : async Types.Result<Types.SealedSecretInfo> {
    switch (await* keys.publicKeyBytes()) {
      case (#Err(e)) #Err(e);
      case (#Ok(pk)) {
        #Ok({
          standard_version = 1 : Nat32;
          context = Array.toBlob(keys.context());
          identity = Array.toBlob(keys.identity(config.epoch));
          epoch = config.epoch;
          key_name = config.keyName;
          public_key = pk;
          max_ciphertext_len = config.maxCiphertextLen;
          max_secrets = config.maxSecrets;
        });
      };
    };
  };

  /// Stores a sealed secret, after proving it can actually be decrypted.
  ///
  /// The trial decryption is the whole point of making this an update that awaits
  /// rather than a plain write. Without it, a ciphertext sealed under the wrong
  /// context, epoch or key name is accepted happily and found unreadable at the
  /// first production use, potentially months later.
  ///
  /// Returns the new revision.
  public shared ({ caller }) func icp_sealed_secret_set(
    name : Text,
    ciphertext : Blob,
  ) : async Types.Result<Nat64> {
    switch (requireController(caller)) { case (?e) { return #Err(e) }; case null {} };
    switch (checkName(name)) { case (?e) { return #Err(e) }; case null {} };

    if (Nat.toNat64(ciphertext.size()) > config.maxCiphertextLen) {
      return #Err(#TooLarge({ max = config.maxCiphertextLen }));
    };
    let existing = Map.get(secrets, Text.compare, name);
    if (existing == null and Nat.toNat64(Map.size(secrets)) >= config.maxSecrets) {
      return #Err(#TooMany({ max = config.maxSecrets }));
    };

    switch (await* keys.decryptWithEpoch(ciphertext, config.epoch)) {
      case (#Err(e)) { return #Err(e) };
      case (#Ok(_)) {};
    };

    let ts = now();
    let revision : Nat64 = switch (existing) {
      case (?r) r.revision + 1;
      case null 1;
    };
    Map.add(
      secrets,
      Text.compare,
      name,
      {
        epoch = config.epoch;
        revision;
        createdAtNs = switch (existing) { case (?r) r.createdAtNs; case null ts };
        updatedAtNs = ts;
        ciphertextSha256 = sha256(ciphertext);
        ciphertext;
      },
    );
    #Ok(revision);
  };

  /// Answers "is the value I hold the one you have stored?" without either side
  /// disclosing it.
  ///
  /// Compares plaintexts, not ciphertexts: IBE is randomised, so sealing the
  /// same value twice gives different bytes and a ciphertext comparison would
  /// always say no.
  ///
  /// Controller-gated, because for anyone else it is an oracle for confirming
  /// guesses. For a controller it discloses nothing new — they can already read
  /// the secret by installing code that decrypts it.
  public shared ({ caller }) func icp_sealed_secret_matches(
    name : Text,
    candidate : Blob,
  ) : async Types.Result<Bool> {
    switch (requireController(caller)) { case (?e) { return #Err(e) }; case null {} };

    let record = switch (Map.get(secrets, Text.compare, name)) {
      case (?r) r;
      case null { return #Err(#NotFound) };
    };

    let mine = switch (await* keys.open(name, record.epoch, record.revision, record.ciphertext)) {
      case (#Ok(p)) p;
      case (#Err(e)) { return #Err(e) };
    };
    let theirs = switch (await* keys.decryptWithEpoch(candidate, config.epoch)) {
      case (#Ok(p)) p;
      case (#Err(e)) { return #Err(e) };
    };
    #Ok(mine == theirs);
  };

  /// Removes a secret and drops its cached plaintext.
  public shared ({ caller }) func icp_sealed_secret_unset(name : Text) : async Types.Result<()> {
    switch (requireController(caller)) { case (?e) { return #Err(e) }; case null {} };
    switch (Map.get(secrets, Text.compare, name)) {
      case null #Err(#NotFound);
      case (?_) {
        Map.remove(secrets, Text.compare, name);
        keys.forget(name);
        #Ok(());
      };
    };
  };

  /// Lists stored secrets.
  ///
  /// Controller-gated, because it is more revealing than it looks: IBE overhead
  /// is a fixed 136 bytes, so `ciphertext_len` gives the exact plaintext length,
  /// and the names alone are reconnaissance.
  ///
  /// Reports a digest of the *ciphertext*. A digest of the plaintext would be an
  /// offline guessing oracle for low-entropy secrets; a digest of a randomised
  /// ciphertext reveals nothing, while still letting a client confirm its upload
  /// landed.
  public shared query ({ caller }) func icp_sealed_secret_list() : async Types.Result<[Types.SealedSecretEntry]> {
    switch (requireController(caller)) { case (?e) { return #Err(e) }; case null {} };
    #Ok(
      Map.entries(secrets)
      |> Iter.toArray<(Text, Store.SealedRecord)>(_)
      |> Array.map<(Text, Store.SealedRecord), Types.SealedSecretEntry>(
        _,
        func((name, r)) = {
          name;
          epoch = r.epoch;
          revision = r.revision;
          ciphertext_len = Nat.toNat64(r.ciphertext.size());
          ciphertext_sha256 = r.ciphertextSha256;
          created_at_ns = r.createdAtNs;
          updated_at_ns = r.updatedAtNs;
        },
      )
    );
  };

  /// Exercises the full decryption path and reports what actually happened.
  ///
  /// Run this after deploying and after every upgrade. It is the difference
  /// between "the canister installed" and "the canister can read its secrets".
  ///
  /// Pass `expected_source` to also check the subnet's public key against the
  /// master key compiled into this Wasm — the one check in the design that is
  /// not the subnet vouching for itself. Do it once per deployment, with the
  /// network you believe you are on.
  public shared ({ caller }) func icp_sealed_secret_self_test(
    expectedSource : ?Types.KeySource
  ) : async Types.Result<Types.SelfTestReport> {
    switch (requireController(caller)) { case (?e) { return #Err(e) }; case null {} };

    let reported = await* keys.publicKeyBytes();
    let publicKeyOk = switch (reported) { case (#Ok(_)) true; case (#Err(_)) false };

    let matchesMaster : ?Bool = switch (expectedSource, reported) {
      case (?source, #Ok(actual)) {
        switch (keys.expectedPublicKey(source, Principal.fromActor(self))) {
          case (?expected) ?(expected == actual);
          case null null;
        };
      };
      case _ null;
    };

    var deriveOk = false;
    var undecryptable : [Text] = [];
    for ((name, r) in Map.entries(secrets)) {
      switch (await* keys.open(name, r.epoch, r.revision, r.ciphertext)) {
        case (#Ok(_)) { deriveOk := true };
        case (#Err(_)) { undecryptable := Array.concat(undecryptable, [name]) };
      };
    };
    // With nothing stored there is no ciphertext to open, so derive the key on
    // its own — otherwise a fresh deployment reports derive_ok = false and looks
    // broken when it is merely empty.
    if (Map.size(secrets) == 0) {
      deriveOk := switch (await* keys.vetkey(config.epoch)) {
        case (#Ok(_)) true;
        case (#Err(_)) false;
      };
    };

    #Ok({
      vetkd_public_key_ok = publicKeyOk;
      vetkd_derive_ok = deriveOk;
      public_key_matches_master = matchesMaster;
      effective_key_name = config.keyName;
      effective_context = Array.toBlob(keys.context());
      epoch = config.epoch;
      num_secrets = Nat.toNat64(Map.size(secrets));
      undecryptable;
    });
  };

  // ------------------------------------------------------- using the secret

  /// The actual use case: authenticate an outbound HTTPS request with a sealed
  /// secret, without the secret ever leaving the canister.
  ///
  /// Returns only the HTTP status. Returning the body would let a hostile
  /// endpoint echo the `Authorization` header straight back out through this
  /// canister's public interface.
  ///
  /// `idempotencyKey` is **not optional in practice.** An HTTPS outcall fans out
  /// to every node in the subnet, each of which issues its own request; without
  /// a key, an endpoint that mutates state sees N charges, N sends, N writes.
  /// This demo endpoint is a read, so nothing here would break without it —
  /// which is exactly why it is present anyway, as the thing to copy.
  ///
  /// Note where the plaintext goes. The request — url, headers and body — enters
  /// **replicated state on every node** before any of them executes the call. On
  /// a SEV-SNP subnet that memory and the checkpoints behind it are encrypted;
  /// on any other subnet the secret is readable by every node operator the
  /// moment this runs.
  public shared ({ caller }) func call_api_with_secret(
    name : Text,
    idempotencyKey : Text,
  ) : async Types.Result<Nat16> {
    switch (requireController(caller)) { case (?e) { return #Err(e) }; case null {} };

    let record = switch (Map.get(secrets, Text.compare, name)) {
      case (?r) r;
      case null { return #Err(#NotFound) };
    };

    let plaintext = switch (await* keys.open(name, record.epoch, record.revision, record.ciphertext)) {
      case (#Ok(p)) p;
      case (#Err(e)) { return #Err(e) };
    };
    let token = switch (Text.decodeUtf8(plaintext)) {
      case (?t) t;
      case null { return #Err(#Internal("secret is not valid UTF-8")) };
    };

    let response = try {
      await (with cycles = 50_000_000_000) IC.http_request({
        url = DEMO_API_ENDPOINT;
        // Keep this tight: the call is priced on it.
        max_response_bytes = ?(2_048 : Nat64);
        headers = [
          // The secret is the whole header value.
          { name = "Authorization"; value = token },
          { name = "Idempotency-Key"; value = idempotencyKey },
          { name = "User-Agent"; value = "icp-sealed-secrets-poc" },
        ];
        body = null;
        method = #get;
        transform = ?{ function = strip_response; context = "" : Blob };
      });
    } catch (e) {
      return #Err(#Internal("http_request failed: " # Error.message(e)));
    };

    if (response.status > 65535) {
      return #Err(#Internal("implausible status code"));
    };
    #Ok(Nat.toNat16(response.status));
  };

  /// Makes an HTTP response deterministic across the nodes that fetched it.
  ///
  /// Drops every response header — they carry `Date`, request ids and cookies
  /// that differ per node, which would break consensus — and, incidentally,
  /// stops an endpoint that echoes our `Authorization` header from smuggling the
  /// secret into replicated state.
  ///
  /// **This passes the body through unchanged, which is only safe because the
  /// demo endpoint returns a constant.** If yours returns a timestamp, a request
  /// id or anything else that differs between fetches, normalise it here too.
  /// Local testing will not catch this: a local replica issues exactly one
  /// request, so a varying body agrees with itself, while on mainnet every node
  /// fetches independently and the call fails.
  public shared query func strip_response(args : TransformArgs) : async HttpRequestResult {
    {
      status = args.response.status;
      headers = [] : [HttpHeader];
      body = args.response.body;
    };
  };
};
