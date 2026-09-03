/// The sealed-secrets interface.
///
/// The six endpoints a client needs in order to seal a secret for this canister
/// and to confirm what it holds. This is the part that is meant to be a
/// standard, and it is the whole reason `seed/` can drive this canister and the
/// Rust one without changes.
///
/// The demo use case — actually spending a secret on an outbound call — is
/// deliberately a separate mixin, because it is not part of that interface.
/// `../mixins/Demo.mo` has it.
///
/// Mirrors the endpoints in `rust/canister/src/lib.rs`.

import Guard "../lib/Guard";
import Keys "../lib/Keys";
import Store "../Store";
import Types "../Types";

import Array "mo:core/Array";
import Iter "mo:core/Iter";
import Map "mo:core/Map";
import Nat "mo:core/Nat";
import Nat64 "mo:core/Nat64";
import Principal "mo:core/Principal";
import Text "mo:core/Text";
import Sha256 "mo:sha2/Sha256";

mixin (
  config : Store.Config,
  secrets : Store.Secrets,
  keyCtx : Keys.Context,
  selfPrincipal : Principal,
) {

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
    switch (await* Keys.publicKeyBytes(keyCtx)) {
      case (#Err(e)) #Err(e);
      case (#Ok(pk)) {
        #Ok({
          standard_version = 1 : Nat32;
          context = Keys.context().toBlob();
          identity = Keys.identity(config.epoch).toBlob();
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
    switch (Guard.requireController(caller)) { case (?e) { return #Err(e) }; case null {} };
    switch (Guard.checkName(name)) { case (?e) { return #Err(e) }; case null {} };

    if (ciphertext.size().toNat64() > config.maxCiphertextLen) {
      return #Err(#TooLarge({ max = config.maxCiphertextLen }));
    };
    let existing = secrets.get(name);
    if (existing == null and secrets.size().toNat64() >= config.maxSecrets) {
      return #Err(#TooMany({ max = config.maxSecrets }));
    };

    // Fails here, in front of the deployer, rather than in production — and its
    // output is what gets stored, so the decryption is not merely a check.
    let plaintext = switch (await* Keys.decryptWithEpoch(keyCtx, ciphertext, config.epoch)) {
      case (#Ok(p)) p;
      case (#Err(e)) { return #Err(e) };
    };

    let ts = Guard.now();
    let revision : Nat64 = switch (existing) {
      case (?r) r.revision + 1;
      case null 1;
    };
    secrets.add(
      name,
      {
        epoch = config.epoch;
        revision;
        createdAtNs = switch (existing) { case (?r) r.createdAtNs; case null ts };
        updatedAtNs = ts;
        ciphertextSha256 = Sha256.fromBlob(#sha256, ciphertext);
        ciphertextLen = ciphertext.size().toNat64();
        plaintext;
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
    switch (Guard.requireController(caller)) { case (?e) { return #Err(e) }; case null {} };

    let record = switch (secrets.get(name)) {
      case (?r) r;
      case null { return #Err(#NotFound) };
    };

    // Only the candidate is sealed; the stored side is already plaintext.
    let theirs = switch (await* Keys.decryptWithEpoch(keyCtx, candidate, config.epoch)) {
      case (#Ok(p)) p;
      case (#Err(e)) { return #Err(e) };
    };
    #Ok(record.plaintext == theirs);
  };

  /// Removes a secret.
  public shared ({ caller }) func icp_sealed_secret_unset(name : Text) : async Types.Result<()> {
    switch (Guard.requireController(caller)) { case (?e) { return #Err(e) }; case null {} };
    switch (secrets.get(name)) {
      case null #Err(#NotFound);
      case (?_) {
        // Nothing to purge: the record was the only copy.
        secrets.remove(name);
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
    switch (Guard.requireController(caller)) { case (?e) { return #Err(e) }; case null {} };
    #Ok(
      secrets.entries()
      |> _.toArray()
      |> _.map(
        func((name, r)) = {
          name;
          epoch = r.epoch;
          revision = r.revision;
          ciphertext_len = r.ciphertextLen;
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
    switch (Guard.requireController(caller)) { case (?e) { return #Err(e) }; case null {} };

    let reported = await* Keys.publicKeyBytes(keyCtx);
    let publicKeyOk = switch (reported) { case (#Ok(_)) true; case (#Err(_)) false };

    let matchesMaster : ?Bool = switch (expectedSource, reported) {
      case (?source, #Ok(actual)) {
        switch (Keys.expectedPublicKey(keyCtx, source, selfPrincipal)) {
          case (?expected) ?(expected == actual);
          case null null;
        };
      };
      case _ null;
    };

    let deriveOk = switch (await* Keys.vetkey(keyCtx, config.epoch)) {
      case (#Ok(_)) true;
      case (#Err(_)) false;
    };

    #Ok({
      vetkd_public_key_ok = publicKeyOk;
      vetkd_derive_ok = deriveOk;
      public_key_matches_master = matchesMaster;
      effective_key_name = config.keyName;
      effective_context = Keys.context().toBlob();
      epoch = config.epoch;
      num_secrets = secrets.size().toNat64();
    });
  };
};
