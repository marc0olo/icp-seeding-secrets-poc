/// vetKD key derivation and the in-memory caches.
///
/// # A porting hazard that has no Rust equivalent
///
/// The Rust canister keeps ciphertext in stable memory and plaintext only in the
/// heap, because a Rust canister's heap is discarded on upgrade unless it is
/// explicitly serialised. **Motoko's enhanced orthogonal persistence inverts
/// that**: the heap *is* the persisted state, and everything survives an upgrade
/// unless it is marked `transient`.
///
/// So the same design requires the opposite spelling. The caches below live in a
/// class that `Main` holds in a `transient` field; without that keyword, a
/// decrypted secret would be written into the canister's persisted state on
/// every upgrade — the exact thing the Rust design avoids, arrived at by doing
/// nothing.
///
/// Mirrors `rust/canister/src/keys.rs`.

import G1 "mo:sealed-secrets-bls/G1";
import G2 "mo:sealed-secrets-bls/G2";
import Ibe "mo:sealed-secrets-vetkeys/Ibe";
import PublicKey "mo:sealed-secrets-vetkeys/PublicKey";
import Scalar "mo:sealed-secrets-bls/Scalar";
import VetKey "mo:sealed-secrets-vetkeys/VetKey";

import Format "Format";
import Types "Types";

import Array "mo:core/Array";
import Blob "mo:core/Blob";
import Iter "mo:core/Iter";
import Error "mo:core/Error";
import Map "mo:core/Map";
import Nat32 "mo:core/Nat32";
import Nat64 "mo:core/Nat64";
import Principal "mo:core/Principal";
import Text "mo:core/Text";

module {
  /// The management canister's vetKD surface.
  ///
  /// Declared here rather than taken from `mo:ic-vetkeys`' `ManagementCanister`
  /// for two reasons: that wrapper hardcodes the `key_1` fee for every key name,
  /// and it traps on a reject where this canister wants a typed
  /// `VetKdUnavailable` error.
  type VetKdSystemApi = actor {
    vetkd_public_key : ({
      canister_id : ?Principal;
      context : Blob;
      key_id : { curve : { #bls12_381_g2 }; name : Text };
    }) -> async ({ public_key : Blob });
    vetkd_derive_key : ({
      context : Blob;
      input : Blob;
      key_id : { curve : { #bls12_381_g2 }; name : Text };
      transport_public_key : Blob;
    }) -> async ({ encrypted_key : Blob });
    raw_rand : () -> async Blob;
  };

  let IC : VetKdSystemApi = actor ("aaaaa-aa");

  /// Domain separator for turning `raw_rand` output into a transport scalar.
  ///
  /// The reference runs the seed through ChaCha20 (`utils/mod.rs:297`). Hashing
  /// to a scalar reaches the same place — a uniform scalar nobody else knows —
  /// without porting a stream cipher, and unlike reducing the raw bytes it is
  /// unbiased. Nothing interoperates with this value: the subnet only ever sees
  /// the corresponding public key.
  let DS_TRANSPORT_KEY = "icp-sealed-secrets-v1-transport-key";

  /// The vetKD fee, which is charged per call and scales with subnet size.
  ///
  /// Overpaying is safe — the management canister refunds the remainder — but
  /// underpaying is rejected outright, so these are the published figures for
  /// the 13-node reference subnet.
  func vetkdFee(keyName : Text) : Nat = switch (keyName) {
    case ("test_key_1") 10_000_000_000;
    case (_) 26_153_846_153;
  };

  func keyId(name : Text) : { curve : { #bls12_381_g2 }; name : Text } = {
    curve = #bls12_381_g2;
    name;
  };

  /// Holds every cache. `Main` must keep this in a `transient` field — see the
  /// module comment.
  public class Manager(keyName : Text) {
    /// The derived public key the subnet reports, cached after the first call.
    var dpk : ?G2.Affine = null;

    /// vetKeys by epoch. Each miss costs one `vetkd_derive_key`, hence the cache.
    let vetkeys = Map.empty<Nat32, G1.Affine>();

    /// Decrypted secrets, keyed by `name # "@" # revision` so an overwrite
    /// invalidates the entry with no explicit purge.
    let plaintexts = Map.empty<Text, Blob>();

    public func context() : [Nat8] = switch (Format.context("")) {
      case (#ok(c)) c;
      // The separator is the empty string, which cannot exceed the bound.
      case (#err(_)) [];
    };

    public func identity(epoch : Nat32) : [Nat8] = Format.identity(epoch);

    /// This canister's public key, as the subnet reports it.
    ///
    /// Asking the subnet rather than deriving from a compiled-in constant is what
    /// lets one build run against a local network and mainnet with no
    /// configuration saying which. The trade is an inter-canister call, which is
    /// why `info` is an update rather than a query.
    ///
    /// Verifying against this is admittedly circular — a subnet that would lie
    /// about its public key already holds the master key. The non-circular check
    /// is `selfTest`, which compares it against a constant compiled into this
    /// Wasm for a source the *caller* nominates, and the check that matters most
    /// is on the client, which derives offline and refuses to encrypt on a
    /// mismatch.
    public func publicKey() : async* Types.Result<G2.Affine> {
      switch (dpk) { case (?k) { return #Ok(k) }; case null {} };

      let reported = try {
        await IC.vetkd_public_key({
          canister_id = null;
          context = Array.toBlob(context());
          key_id = keyId(keyName);
        });
      } catch (e) {
        return #Err(#VetKdUnavailable({ key_name = keyName; detail = Error.message(e) }));
      };

      switch (G2.fromCompressed(reported.public_key)) {
        case (?k) { dpk := ?k; #Ok(k) };
        case null #Err(#Internal("subnet returned a malformed public key"));
      };
    };

    /// Derives the public key offline from a master key compiled into this Wasm.
    ///
    /// Only `selfTest` uses it, to audit the subnet's answer against an
    /// expectation the caller supplies. `null` when no master key is compiled in
    /// for this key name under that source.
    public func expectedPublicKey(source : Types.KeySource, self : Principal) : ?Blob {
      let s : PublicKey.KeySource = switch (source) {
        case (#Mainnet) #Mainnet;
        case (#PocketIc) #PocketIc;
      };
      switch (PublicKey.masterPublicKey(s, keyName)) {
        case null null;
        case (?mpk) {
          let canisterKey = PublicKey.deriveCanisterKey(mpk, Blob.toArray(Principal.toBlob(self)));
          ?G2.toCompressed(PublicKey.deriveSubKey(canisterKey, context()));
        };
      };
    };

    /// The vetKey for `epoch`, deriving it on a miss.
    ///
    /// Two concurrent cold callers will both derive. Accepted rather than
    /// prevented: derivation is deterministic in
    /// `(canister_id, context, input, key_id)`, so both get the identical key and
    /// the only cost is a duplicate fee. Rejecting the second caller is bad UX in
    /// a business path, and making it wait is not implementable — they are
    /// separate message executions and neither can await the other.
    public func vetkey(epoch : Nat32) : async* Types.Result<G1.Affine> {
      switch (Map.get(vetkeys, Nat32.compare, epoch)) {
        case (?k) { return #Ok(k) };
        case null {};
      };

      let derivedPublicKey = switch (await* publicKey()) {
        case (#Ok(k)) k;
        case (#Err(e)) { return #Err(e) };
      };

      let seed = try { await IC.raw_rand() } catch (e) {
        return #Err(#Internal("raw_rand failed: " # Error.message(e)));
      };

      // A real, single-use transport key. The timelock example's alternative —
      // an all-zero seed — makes the derived key readable by anyone who can read
      // the subnet's messages, and moots the verification below.
      let tsk = Scalar.hashToScalar(Blob.toArray(seed), DS_TRANSPORT_KEY);
      let identityBytes = identity(epoch);

      let reply = try {
        await (with cycles = vetkdFee(keyName)) IC.vetkd_derive_key({
          context = Array.toBlob(context());
          input = Array.toBlob(identityBytes);
          key_id = keyId(keyName);
          transport_public_key = VetKey.transportPublicKey(tsk);
        });
      } catch (e) {
        // Most often: this subnet holds no NI-DKG transcript for the key.
        return #Err(#VetKdUnavailable({ key_name = keyName; detail = Error.message(e) }));
      };

      let encrypted = switch (VetKey.deserialize(Blob.toArray(reply.encrypted_key))) {
        case (?e) e;
        case null { return #Err(#Internal("malformed encrypted vetkey")) };
      };

      switch (VetKey.decryptAndVerify(encrypted, tsk, derivedPublicKey, identityBytes)) {
        case (?k) {
          Map.add(vetkeys, Nat32.compare, epoch, k);
          #Ok(k);
        };
        case null #Err(
          #Internal("the subnet returned a key that does not match our derived public key")
        );
      };
    };

    /// Decrypts a ciphertext under an epoch's key, touching no cache.
    ///
    /// This is what `set` uses to trial-decrypt before storing — the check that
    /// turns a wrong context, epoch or key id into an error in front of the
    /// operator rather than a stored blob nobody can open months later.
    public func decryptWithEpoch(ciphertext : Blob, epoch : Nat32) : async* Types.Result<Blob> {
      let key = switch (await* vetkey(epoch)) {
        case (#Ok(k)) k;
        case (#Err(e)) { return #Err(e) };
      };

      let parsed = switch (Ibe.deserialize(Blob.toArray(ciphertext))) {
        case (?c) c;
        case null { return #Err(#InvalidCiphertext("not an IBE ciphertext")) };
      };

      switch (Ibe.decrypt(parsed, key)) {
        case (?plaintext) #Ok(Array.toBlob(plaintext));
        case null #Err(
          #InvalidCiphertext(
            "ciphertext was not encrypted to this canister's key for this epoch — "
            # "check the context, epoch and key name"
          )
        );
      };
    };

    /// Decrypts a stored record, using and populating the plaintext cache.
    public func open(name : Text, epoch : Nat32, revision : Nat64, ciphertext : Blob) : async* Types.Result<Blob> {
      let cacheKey = name # "@" # Nat64.toText(revision);
      switch (Map.get(plaintexts, Text.compare, cacheKey)) {
        case (?p) { return #Ok(p) };
        case null {};
      };
      switch (await* decryptWithEpoch(ciphertext, epoch)) {
        case (#Ok(p)) { Map.add(plaintexts, Text.compare, cacheKey, p); #Ok(p) };
        case (#Err(e)) #Err(e);
      };
    };

    /// Drops a name's cached plaintexts. Called on unset.
    public func forget(name : Text) {
      let stale = Array.filter<Text>(
        Map.keys(plaintexts) |> Iter.toArray<Text>(_),
        func k = Text.startsWith(k, #text(name # "@")),
      );
      for (k in stale.vals()) { Map.remove(plaintexts, Text.compare, k) };
    };
  };
}
