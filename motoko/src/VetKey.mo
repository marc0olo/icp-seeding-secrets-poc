/// The vetKD reply: unwrapping and verifying an `EncryptedVetKey`.
///
/// # ⚠️ EXPERIMENTAL AND UNAUDITED — see ../README.md
///
/// This is the step between `vetkd_derive_key` returning and `Ibe.decrypt`
/// being callable. The subnet does not hand back the vetKey in the clear — it
/// encrypts it to a transport key the canister generated for this one call — so
/// the canister has to unwrap it, and then check that what fell out is really
/// the key it asked for.
///
/// **The verification is the point.** Without it a canister accepts whatever
/// the management-canister reply contained. The check is a BLS signature
/// verification against a derived public key the canister computed itself, from
/// a master key compiled into its own Wasm — so a forged reply fails even if
/// everything between the canister and the subnet is hostile.
///
/// Ported from `ic_vetkeys::EncryptedVetKey` (`utils/mod.rs:789`) and
/// `verify_bls_signature_pt` (`:1379`).

import Fp12 "Fp12";
import G1 "G1";
import G2 "G2";
import Pairing "Pairing";
import HashToCurve "HashToCurve";
import Scalar "Scalar";
import Array "mo:core/Array";
import Blob "mo:core/Blob";
import Nat8 "mo:core/Nat8";

module {
  /// `2 * G1_compressed + G2_compressed`.
  public let BYTES : Nat = 192;

  /// The domain separator for the augmented BLS signature scheme
  /// (`utils/mod.rs:1396`). The `_AUG_` suffix is not decoration: it marks the
  /// variant that prefixes the public key to the message, which is what
  /// `augmentedHashToG1` does below.
  public let SIGNATURE_DST = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_AUG_";

  public type EncryptedVetKey = {
    c1 : G1.Affine;
    c2 : G2.Affine;
    c3 : G1.Affine;
  };

  /// Parses the 192-byte reply: compressed `c1 ‖ c2 ‖ c3`.
  public func deserialize(bytes : [Nat8]) : ?EncryptedVetKey {
    if (bytes.size() != BYTES) { return null };
    let slice = func(from : Nat, to : Nat) : Blob {
      Array.toBlob(Array.sliceToArray<Nat8>(bytes, from, to));
    };
    switch (
      G1.fromCompressed(slice(0, 48)),
      G2.fromCompressed(slice(48, 144)),
      G1.fromCompressed(slice(144, 192)),
    ) {
      case (?c1, ?c2, ?c3) ?{ c1; c2; c3 };
      case _ null;
    };
  };

  /// The transport public key to send with `vetkd_derive_key`: `g1 · sk`.
  ///
  /// The secret key is an ordinary scalar. The reference derives it from a seed
  /// with ChaCha20 (`utils/mod.rs:297`), which this port deliberately does not
  /// reproduce — that would mean porting a stream cipher to reimplement what is
  /// only a convenience for turning 32 bytes into a scalar. A canister should
  /// take 32 bytes from `raw_rand` and pass them through `Scalar.fromBytes`.
  public func transportPublicKey(sk : Scalar.Scalar) : Blob =
    G1.toCompressed(G1.toAffine(G1.mul(G1.fromAffine(G1.generator), sk)));

  /// Hashes to `G1` with the signer's public key prefixed to the message
  /// (`utils/mod.rs:1395`).
  ///
  /// Prefixing is what stops a rogue-key attack: without it an attacker who
  /// picks their public key after seeing others' can produce a key whose
  /// signature verifies against a message they never signed.
  public func augmentedHashToG1(pk : G2.Affine, data : [Nat8]) : G1.Affine {
    let prefix = Blob.toArray(G2.toCompressed(pk));
    HashToCurve.hashToCurveText(Array.concat<Nat8>(prefix, data), SIGNATURE_DST);
  };

  /// True when `signature` is a valid BLS signature on `input` under `dpk`.
  ///
  /// Checks `e(sig, g2) == e(H(pk ‖ input), dpk)`, rearranged into
  /// `e(sig, -g2) · e(msg, dpk) == 1` so one final exponentiation covers both
  /// terms — about a third of the total cost saved.
  public func verifyBlsSignature(
    dpk : G2.Affine,
    input : [Nat8],
    signature : G1.Affine,
  ) : Bool {
    if (dpk.infinity) { return false };
    let msg = augmentedHashToG1(dpk, input);
    isGtIdentity([(signature, G2.negAffine(G2.generator)), (msg, dpk)]);
  };

  /// Unwraps the reply and verifies the key that comes out (`utils/mod.rs:803`).
  ///
  /// Returns `null` on either failure, without distinguishing them: the caller
  /// cannot act differently on the two, and a canister that reports which check
  /// failed tells an attacker probing it which half of a forged reply was wrong.
  public func decryptAndVerify(
    ek : EncryptedVetKey,
    tsk : Scalar.Scalar,
    dpk : G2.Affine,
    input : [Nat8],
  ) : ?G1.Affine {
    // `c1` and `c2` must have the same discrete logarithm — the subnet
    // committed to one randomiser in both groups. Equivalent to
    // `e(c1, -g2) · e(g1, c2) == 1`.
    if (not isGtIdentity([(ek.c1, G2.negAffine(G2.generator)), (G1.generator, ek.c2)])) {
      return null;
    };

    // Strip the transport blinding: k = c3 - c1·tsk.
    let k = G1.toAffine(
      G1.sub(G1.fromAffine(ek.c3), G1.mul(G1.fromAffine(ek.c1), tsk))
    );

    if (verifyBlsSignature(dpk, input, k)) { ?k } else { null };
  };

  /// Whether a product of pairings is the identity of `G_T`.
  func isGtIdentity(pairs : [(G1.Affine, G2.Affine)]) : Bool {
    switch (Pairing.finalExponentiation(Pairing.multiMillerLoop(pairs))) {
      case (?r) Fp12.equal(r, Fp12.one);
      // The Miller-loop product was zero, which no honest input produces.
      case null false;
    };
  };
}
