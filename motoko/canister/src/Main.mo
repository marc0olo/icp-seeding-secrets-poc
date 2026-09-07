/// A canister that receives one secret, encrypted with vetKD IBE.
///
/// The Motoko counterpart of `rust/canister`, endpoint for endpoint, so the
/// same seeding script drives either one. It decrypts using this repo's
/// **experimental, unaudited** BLS12-381 implementation — see `../README.md`.
///
///   setDummySecret(ciphertext)  ask the subnet for our private key, decrypt
///   getDummySecret()            hand the plaintext back so you can see it worked
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
import Principal "mo:core/Principal";
import Text "mo:core/Text";

persistent actor DummySecret {

  /// The vetKD key this subnet serves. `key_1` exists on mainnet and on a local
  /// network, so one constant covers both. Deliberately not an install
  /// argument: a constant cannot be lost on upgrade.
  transient let KEY_NAME = "key_1";

  /// The vetKD **context**: what selects the *keypair*.
  ///
  /// The derivation is master key -> canister id -> context, so changing this
  /// byte for byte gives this canister an entirely different keypair. One
  /// context per purpose. Must match the client exactly.
  transient let CONTEXT : Blob = "\64\75\6d\6d\79\2d\73\65\63\72\65\74\2d\70\6f\63"; // "dummy-secret-poc"

  /// The IBE **identity**: what selects a key *within* that keypair.
  ///
  /// Also the `input` to `vetkd_derive_key`. One fixed identity here, because
  /// there is one secret. Several secrets could each have their own — but inside
  /// one canister that costs a separate 26-billion-cycle derive per identity and
  /// buys nothing, since this canister's code can derive any identity's key
  /// whenever it likes.
  transient let IDENTITY : Blob = "\64\75\6d\6d\79\2d\73\65\63\72\65\74"; // "dummy-secret"

  /// Turns 32 random bytes into a transport scalar. Nothing interoperates with
  /// this value — the subnet only ever sees the matching public key.
  transient let DS_TRANSPORT = "dummy-secret-poc-transport-key";

  /// The vetKD fee, charged per call. Overpaying is refunded; underpaying is
  /// rejected outright, so this is the published figure for `key_1`.
  transient let VETKD_FEE = 26_153_846_153;

  /// The decrypted secret. Deliberately not persisted across upgrades: a PoC
  /// should make you re-seal and watch it work again.
  transient var secret : ?Text = null;

  transient let keyId : { name : Text; curve : IC.VetkdCurve } = {
    name = KEY_NAME;
    curve = #bls12_381_g2;
  };

  /// Stores a secret that was encrypted to this canister's public key.
  ///
  /// The canister holds no private key — it has nowhere to hide one, since its
  /// whole memory is replicated — so it asks the subnet to reconstruct one, uses
  /// it once, and lets it go.
  public shared ({ caller }) func setDummySecret(ciphertext : Blob) : async Result<()> {
    // Whoever seeds the secret should be whoever controls the canister.
    // Ungated, anyone could overwrite it with a value of their choosing.
    if (not caller.isController()) { return #Err("only a controller may set the secret") };

    // 1. A single-use transport key, so the subnet's reply comes back encrypted
    //    to us rather than readable by every node that helped produce it.
    let seed = try { await ic.raw_rand() } catch (e) {
      return #Err("raw_rand: " # e.message());
    };
    let tsk = Scalar.hashToScalar(seed.toArray(), DS_TRANSPORT);

    // 2. Ask the subnet for the private key belonging to
    //    (this canister, CONTEXT, IDENTITY). Each node contributes a share.
    let reply = try {
      await (with cycles = VETKD_FEE) ic.vetkd_derive_key({
        context = CONTEXT;
        input = IDENTITY;
        key_id = keyId;
        transport_public_key = VetKey.transportPublicKey(tsk);
      });
    } catch (e) {
      return #Err("vetkd_derive_key: " # e.message() # " — does this subnet hold the key?");
    };

    // 3. Unwrap it and check it really is our key. Verifying against a public
    //    key the same subnet supplies is circular — a subnet that would lie here
    //    already holds the master key. The non-circular check is on the client,
    //    which derives the key offline and refuses to encrypt on a mismatch.
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
    let vetkey : G1.Affine = switch (
      VetKey.decryptAndVerify(encrypted, tsk, dpk, IDENTITY.toArray())
    ) {
      case (?k) k;
      case null { return #Err("the subnet returned a key we cannot verify") };
    };

    // 4. Decrypt. Failing here means the ciphertext was sealed to a different
    //    key — wrong canister id, wrong context, or the wrong master key table.
    let parsed = switch (Ibe.deserialize(ciphertext.toArray())) {
      case (?c) c;
      case null { return #Err("not an IBE ciphertext") };
    };
    switch (Ibe.decrypt(parsed, vetkey)) {
      case null #Err("ciphertext was not sealed to this canister's key");
      case (?plaintext) {
        switch (plaintext.toBlob().decodeUtf8()) {
          case null #Err("secret is not UTF-8");
          case (?t) { secret := ?t; #Ok(()) };
        };
      };
    };
  };

  /// Returns the decrypted secret **in the clear**.
  ///
  /// # This exists only so you can see that decryption worked
  ///
  /// A real canister must not have this. The reply is not encrypted end-to-end:
  /// the boundary node terminates TLS and sits outside the subnet's trust
  /// boundary, so this hands the secret straight back out — undoing, on the way
  /// out, exactly what sealing achieved on the way in.
  ///
  /// Controller-gated, which is not much of a defence (a controller can install
  /// code that reads the secret anyway) but keeps the PoC from being an open
  /// oracle while it is deployed.
  public shared query ({ caller }) func getDummySecret() : async Result<?Text> {
    if (not caller.isController()) { return #Err("only a controller may read the secret") };
    #Ok(secret);
  };

  /// Capitalised to match what Rust's `Result<T, String>` produces, so both
  /// canisters have the identical Candid shape and one client can call either.
  public type Result<T> = { #Ok : T; #Err : Text };
};
