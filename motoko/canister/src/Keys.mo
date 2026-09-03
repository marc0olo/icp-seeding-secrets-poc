/// vetKD key derivation and the in-memory caches.
///
/// # What is cached, and why
///
/// Only vetKeys. There is no plaintext cache, because records hold the
/// decrypted secret (see `Store.SealedRecord`) — reading one is a map lookup.
/// Decryption happens only where a caller hands the canister a ciphertext:
/// `set`, which trial-decrypts before storing, and `matches`, which decrypts the
/// candidate it is asked to compare.
///
/// **The vetKey cache persists across upgrades, and that is a cost decision, not
/// a security one.** Worth stating plainly, because it is easy to assume
/// otherwise: plaintext in the heap and plaintext in persisted state have the
/// same exposure on ICP. Both are replicated, checkpointed to disk on every
/// node, shipped in state sync, and captured by `read_canister_snapshot_data`.
/// `transient` only clears state at an *upgrade*; between upgrades a transient
/// value sits in the heap and is checkpointed like everything else. Nothing here
/// keeps a secret off disk — only SEV-SNP changes who can read it. See the
/// security model in `../../../README.md`.
///
/// The cost being avoided is real: a cache miss means a `vetkd_derive_key` —
/// an inter-canister call, a fee of 26 billion cycles for `key_1`, and a round
/// of consensus. Rust cannot dodge it, because its heap is discarded on upgrade
/// unless serialised, and serialising into `ic-stable-structures` would mean
/// paying stable-memory access on every read thereafter. Motoko has no such
/// split: under enhanced orthogonal persistence the persisted state *is* the
/// heap, with no serialisation barrier and no per-read cost, so keeping the
/// cache is free.
///
/// A persisted vetKey cannot go stale. It is keyed by epoch, and the key name
/// cannot change across an upgrade because `Main` keeps the persisted config
/// rather than the install argument, as the Rust canister does.
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
import Error "mo:core/Error";
import Map "mo:core/Map";
import Nat32 "mo:core/Nat32";
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

  /// The persisted caches.
  ///
  /// `Main` owns this and does *not* mark it `transient`, so it survives
  /// upgrades — see the module comment for why that is the right call in Motoko
  /// and the wrong one in Rust. Every field is a stable type.
  public type Caches = {
    /// The derived public key the subnet reports, after the first call.
    var dpk : ?G2.Affine;
    /// vetKeys by epoch. Each miss costs one `vetkd_derive_key` — the call, its
    /// fee, and a round of consensus. This is the expensive thing, and the whole
    /// reason to persist anything.
    vetkeys : Map.Map<Nat32, G1.Affine>;
  };

  public func emptyCaches() : Caches = {
    var dpk = null;
    vetkeys = Map.empty<Nat32, G1.Affine>();
  };

  /// Behaviour over the persisted caches.
  ///
  /// The class itself carries no state worth keeping — it has methods, which are
  /// not a stable type — so `Main` holds it `transient` and the `Caches` record
  /// separately. That separation is what lets the data persist while the code
  /// that operates on it is rebuilt on every upgrade.
  public class Manager(keyName : Text, caches : Caches) {
    let vetkeys = caches.vetkeys;

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
      switch (caches.dpk) { case (?k) { return #Ok(k) }; case null {} };

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
        case (?k) { caches.dpk := ?k; #Ok(k) };
        case null #Err(#Internal("subnet returned a malformed public key"));
      };
    };

    /// The subnet's reported public key, compressed — what `info` returns and
    /// `selfTest` compares against.
    public func publicKeyBytes() : async* Types.Result<Blob> {
      switch (await* publicKey()) {
        case (#Ok(k)) #Ok(G2.toCompressed(k));
        case (#Err(e)) #Err(e);
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

  };
}
