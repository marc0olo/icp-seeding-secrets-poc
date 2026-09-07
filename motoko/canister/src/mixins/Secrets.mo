/// The sealed-secrets interface.
///
/// Four required endpoints plus one optional (`matches`). This is the part that
/// is meant to be a standard, and it is the whole reason `seed/` can drive this
/// canister and the Rust one without changes.
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

  /// Stores a sealed secret, after proving it can actually be decrypted.
  ///
  /// The decryption is the whole point of making this an update that awaits
  /// rather than a plain write. Without it, a ciphertext sealed to the wrong
  /// canister id, key name or master key table is accepted happily and found
  /// unreadable at the first production use, potentially months later. It is
  /// also the only health check this interface needs: it exercises
  /// `vetkd_public_key`, `vetkd_derive_key`, verification and decryption, on
  /// real data.
  ///
  /// Returns the new revision.
  public shared ({ caller }) func icp_sealed_secret_set(
    name : Text,
    ciphertext : Blob,
  ) : async Types.Result<Nat64> {
    switch (Guard.requireController(caller)) { case (?e) { return #Err(e) }; case null {} };
    switch (Guard.checkName(name)) { case (?e) { return #Err(e) }; case null {} };

    let existing = secrets.get(name);

    // Fails here, in front of the deployer, rather than in production — and its
    // output is what gets stored, so the decryption is not merely a check.
    let plaintext = switch (await* Keys.decrypt(keyCtx, ciphertext)) {
      case (#Ok(p)) p;
      case (#Err(e)) { return #Err(e) };
    };

    let ts = Guard.now();
    // Starts at 0, matching the Rust canister — one interface, one meaning.
    let revision : Nat64 = switch (existing) {
      case (?r) r.revision + 1;
      case null 0;
    };
    secrets.add(
      name,
      {
        revision;
        createdAtNs = switch (existing) { case (?r) r.createdAtNs; case null ts };
        updatedAtNs = ts;
        ciphertextSha256 = Sha256.fromBlob(#sha256, ciphertext);
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
    let theirs = switch (await* Keys.decrypt(keyCtx, candidate)) {
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

  /// Lists stored secrets: the inventory, and how a client confirms its write
  /// landed.
  ///
  /// Controller-gated, because names alone are reconnaissance.
  ///
  /// Reports a digest of the *ciphertext*. A digest of the plaintext would be an
  /// offline guessing oracle for low-entropy secrets; a digest of a randomised
  /// ciphertext reveals nothing, while still letting the client that produced it
  /// recognise its own upload.
  public shared query ({ caller }) func icp_sealed_secret_list() : async Types.Result<[Types.SealedSecretEntry]> {
    switch (Guard.requireController(caller)) { case (?e) { return #Err(e) }; case null {} };
    #Ok(
      secrets.entries()
      |> _.toArray()
      |> _.map(
        func((name, r)) = {
          name;
          revision = r.revision;
          ciphertext_sha256 = r.ciphertextSha256;
          created_at_ns = r.createdAtNs;
          updated_at_ns = r.updatedAtNs;
        },
      )
    );
  };

};
