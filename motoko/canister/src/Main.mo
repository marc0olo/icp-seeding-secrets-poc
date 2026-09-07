/// A canister that receives secrets, encrypted with vetKD IBE.
///
/// The Motoko counterpart of `rust/canister`, endpoint for endpoint, so the
/// same seeding script drives either one. It decrypts using this repo's
/// **experimental, unaudited** BLS12-381 implementation — see `../README.md`.
///
///   setDummySecret(name, ciphertext)  decrypt and store under that name
///   getDummySecret(name)              hand the plaintext back so you can see it worked
///
/// One file on purpose: the point of this PoC is that a person can read it
/// start to finish.

import G1 "mo:sealed-secrets-bls/G1";
import G2 "mo:sealed-secrets-bls/G2";
import Scalar "mo:sealed-secrets-bls/Scalar";
import Ibe "mo:sealed-secrets-vetkeys/Ibe";
import VetKey "mo:sealed-secrets-vetkeys/VetKey";

import { ic } "mo:ic";
import IC "mo:ic/Types";

import Array "mo:core/Array";
import Blob "mo:core/Blob";
import Error "mo:core/Error";
import Map "mo:core/Map";
import Principal "mo:core/Principal";
import Text "mo:core/Text";

persistent actor DummySecret {

  /// The vetKD key to use. `key_1` exists on mainnet and on a local network, so
  /// one constant covers both. Deliberately not an install argument: a constant
  /// cannot be lost on upgrade.
  transient let KEY_NAME = "key_1";

  /// The vetKD **context**: what selects the *keypair*.
  ///
  /// The derivation is caller -> context, so changing this byte for byte gives
  /// this canister an entirely different keypair. One context per purpose. Must
  /// match the client exactly.
  transient let CONTEXT : Blob = Text.encodeUtf8("dummy-secret-poc");

  /// The label under which every secret here is sealed — in vetKD terms the
  /// **IBE identity**, and the `input` to `vetkd_derive_key`.
  ///
  /// Not a key, and not a secret's name. `(caller, context)` fixes a keypair;
  /// this picks one of the infinitely many keys under it, and one key opens
  /// every ciphertext sealed to it. That is why storing many secrets costs
  /// exactly one derivation: they share this label, and the per-secret names
  /// below are map keys that never reach vetKD.
  transient let KEY_LABEL : Blob = Text.encodeUtf8("dummy-secret");

  /// Turns 32 random bytes into a transport scalar. Nothing interoperates with
  /// this value — the subnet only ever sees the matching public key.
  transient let DS_TRANSPORT = "dummy-secret-poc-transport-key";

  /// The vetKD fee, charged per call. Overpaying is refunded; underpaying is
  /// rejected outright, so this is the published figure for `key_1`.
  transient let VETKD_FEE = 26_153_846_153;

  /// The derived private key, cached after the first use.
  ///
  /// Safe to hold forever: derivation is deterministic in
  /// `(caller, context, input, key_id)`, none of which depends on the secrets,
  /// so it can never go stale.
  ///
  /// Unlike the Rust canister's, this survives upgrades — orthogonal
  /// persistence gives that for free, so a redeploy costs no re-derivation.
  var vetkey : ?G1.Affine = null;

  /// The decrypted secrets, by name. The name is bookkeeping only — it is not
  /// part of any derivation and never leaves this canister.
  ///
  /// Transient, so a PoC makes you re-seal after an upgrade and watch it work.
  transient let secrets = Map.empty<Text, Text>();

  transient let keyId : { name : Text; curve : IC.VetkdCurve } = {
    name = KEY_NAME;
    curve = #bls12_381_g2;
  };

  /// Capitalised to match what Rust's `Result<T, String>` produces, so both
  /// canisters have the identical Candid shape and one client can call either.
  public type Result<T> = { #Ok : T; #Err : Text };

  /// This canister's private key for `KEY_LABEL`, deriving it once.
  ///
  /// Two concurrent callers on a cold cache will both derive. Accepted rather
  /// than prevented: derivation is deterministic, so both get the identical key
  /// and the only cost is a duplicate fee.
  func deriveVetkey() : async* Result<G1.Affine> {
    switch (vetkey) { case (?k) { return #Ok(k) }; case null {} };

    // 1. A single-use transport keypair. The private half never leaves here.
    //
    //    This is what keeps the vetKey off the wire and out of replicated state:
    //    the nodes do not reconstruct it and then encrypt it, they compute their
    //    shares ALREADY encrypted under the public half. The plaintext key
    //    exists nowhere until step 3 unwraps it, here.
    let seed = try { await ic.raw_rand() } catch (e) {
      return #Err("raw_rand: " # e.message());
    };
    let tsk = Scalar.hashToScalar(seed.toArray(), DS_TRANSPORT);

    // 2. Ask for the private key belonging to (this canister, CONTEXT, KEY_LABEL).
    //    The management canister routes this to a subnet holding the key — not
    //    necessarily our own — where each node contributes a share. What binds
    //    the result to us is that the caller's canister id is a derivation input,
    //    and vetkd_derive_key has no field for naming a different one.
    let reply = try {
      await (with cycles = VETKD_FEE) ic.vetkd_derive_key({
        context = CONTEXT;
        input = KEY_LABEL;
        key_id = keyId;
        transport_public_key = VetKey.transportPublicKey(tsk);
      });
    } catch (e) {
      return #Err("vetkd_derive_key: " # e.message() # " — is " # KEY_NAME # " available here?");
    };

    // 3. Unwrap it, and check that what fell out really is our key.
    //
    //    decryptAndVerify rejects a malformed reply whose two halves disagree,
    //    strips the transport blinding, then verifies the result is a valid BLS
    //    signature over KEY_LABEL under dpk. That last step is what makes a
    //    forged reply useless.
    //
    //    Asking the same place for the public key is circular — a subnet that
    //    would lie here already holds the master key. The non-circular check is
    //    on the client, which derives offline and refuses to encrypt on a
    //    mismatch.
    let reported = try {
      await ic.vetkd_public_key({ canister_id = null; context = CONTEXT; key_id = keyId });
    } catch (e) {
      return #Err("vetkd_public_key: " # e.message());
    };
    let dpk = switch (G2.fromCompressed(reported.public_key)) {
      case (?k) k;
      case null { return #Err("subnet returned a malformed public key") };
    };

    let encrypted = switch (VetKey.deserialize(reply.encrypted_key.toArray())) {
      case (?e) e;
      case null { return #Err("malformed encrypted key") };
    };

    switch (VetKey.decryptAndVerify(encrypted, tsk, dpk, KEY_LABEL.toArray())) {
      case null #Err("the subnet returned a key we cannot verify");
      case (?k) { vetkey := ?k; #Ok(k) };
    };
  };

  /// Stores a secret that was encrypted to this canister's public key.
  ///
  /// Decrypting here rather than storing the blob is deliberate: a ciphertext
  /// sealed under the wrong context, label or key fails now, in front of whoever
  /// is seeding it, instead of being accepted and found unreadable later.
  ///
  /// Storing several secrets costs one derivation in total, not one each.
  public shared ({ caller }) func setDummySecret(name : Text, ciphertext : Blob) : async Result<()> {
    // Whoever seeds a secret should be whoever controls the canister.
    // Ungated, anyone could overwrite one with a value of their choosing.
    if (not caller.isController()) { return #Err("only a controller may set a secret") };

    let key = switch (await* deriveVetkey()) {
      case (#Ok(k)) k;
      case (#Err(e)) { return #Err(e) };
    };

    let parsed = switch (Ibe.deserialize(ciphertext.toArray())) {
      case (?c) c;
      case null { return #Err("not an IBE ciphertext") };
    };

    switch (Ibe.decrypt(parsed, key)) {
      case null #Err("ciphertext was not sealed to this canister's key");
      case (?plaintext) {
        switch (plaintext.toBlob().decodeUtf8()) {
          case null #Err("secret is not UTF-8");
          case (?t) { secrets.add(name, t); #Ok(()) };
        };
      };
    };
  };

  /// Returns a decrypted secret **in the clear**.
  ///
  /// # This exists only so you can see that decryption worked
  ///
  /// A real canister must not have this. The reply is not encrypted end to end:
  /// the boundary node terminates TLS and sits outside the subnet's trust
  /// boundary, so this hands the secret straight back out — undoing, on the way
  /// out, exactly what sealing achieved on the way in.
  ///
  /// Controller-gated, which is not much of a defence (a controller can install
  /// code that reads a secret anyway) but keeps the PoC from being an open
  /// oracle while it is deployed.
  public shared query ({ caller }) func getDummySecret(name : Text) : async Result<?Text> {
    if (not caller.isController()) { return #Err("only a controller may read a secret") };
    #Ok(secrets.get(name));
  };
};
