/// Identity-based encryption over BLS12-381 — the decryption half.
///
/// # ⚠️ EXPERIMENTAL AND UNAUDITED — see ../README.md
///
/// This is what the whole port is for: given a vetKey obtained from
/// `vetkd_derive_key`, recover the plaintext a client sealed to this canister.
///
/// Only decryption is implemented. A canister never encrypts — the client does
/// that, with `ic-vetkeys` or `@icp-sdk/vetkeys` — and leaving it out removes
/// any chance of a weak seed being generated on-chain, where randomness is not
/// private anyway.
///
/// Ported from `ic_vetkeys::IbeCiphertext`.

import Fp12 "Fp12";
import G1 "G1";
import G2 "G2";
import Pairing "Pairing";
import Scalar "Scalar";
import Hash "Hash";
import Array "mo:core/Array";
import Nat8 "mo:core/Nat8";
import Nat "mo:core/Nat";
import Text "mo:core/Text";

module {
  /// `"IC IBE"` followed by the version, `0x00 0x01`.
  public let HEADER : [Nat8] = [0x49, 0x43, 0x20, 0x49, 0x42, 0x45, 0x00, 0x01];

  public let HEADER_BYTES : Nat = 8;
  public let SEED_BYTES : Nat = 32;
  public let G2_BYTES : Nat = 96;

  /// Fixed overhead: header, the `G2` point, and the masked seed.
  public let OVERHEAD : Nat = 136; // 8 + 96 + 32

  /// Domain separators, which must match `ic-vetkeys`' `IbeDomainSep`
  /// (`utils/mod.rs:996`) exactly.
  let DS_HASH_TO_MASK = "ic-vetkd-bls12-381-ibe-hash-to-mask";
  let DS_MASK_SEED = "ic-vetkd-bls12-381-ibe-mask-seed";

  /// `ic-vetkd-bls12-381-ibe-mask-msg-` with the length zero-padded to 20
  /// digits, so every separator in the family is the same length.
  func dsMaskMsg(len : Nat) : Text {
    var digits = Nat.toText(len);
    while (digits.size() < 20) { digits := "0" # digits };
    "ic-vetkd-bls12-381-ibe-mask-msg-" # digits;
  };

  public type Ciphertext = {
    header : [Nat8];
    c1 : G2.Affine;
    c2 : [Nat8];
    c3 : [Nat8];
  };

  /// Parses the wire format: header ‖ compressed `G2` ‖ masked seed ‖ masked
  /// message (`utils/mod.rs:1013`).
  public func deserialize(bytes : [Nat8]) : ?Ciphertext {
    if (bytes.size() < OVERHEAD) { return null };

    let header = Array.sliceToArray<Nat8>(bytes, 0, HEADER_BYTES);
    for (i in Nat.range(0, HEADER_BYTES)) {
      if (header[i] != HEADER[i]) { return null };
    };

    let c1Bytes = Array.sliceToArray<Nat8>(bytes, HEADER_BYTES, HEADER_BYTES + G2_BYTES);
    let c1 = switch (G2.fromCompressed(Array.toBlob(c1Bytes))) {
      case (?p) p;
      case null { return null };
    };

    let c2 = Array.sliceToArray<Nat8>(
      bytes,
      HEADER_BYTES + G2_BYTES,
      HEADER_BYTES + G2_BYTES + SEED_BYTES,
    );
    let c3 = Array.sliceToArray<Nat8>(bytes, OVERHEAD, bytes.size());

    ?{ header; c1; c2; c3 };
  };

  /// XORs a buffer with an HKDF-derived mask of the same length.
  func maskSeed(seed : [Nat8], t : Fp12.Fp12) : [Nat8] {
    let mask = Hash.hkdf(Fp12.toBytes(t), DS_MASK_SEED, SEED_BYTES);
    Array.tabulate<Nat8>(SEED_BYTES, func i = mask[i] ^ seed[i]);
  };

  /// XORs the message with a SHAKE256 stream keyed by an HKDF of the seed.
  func maskMsg(msg : [Nat8], seed : [Nat8]) : [Nat8] {
    let shakeSeed = Hash.hkdf(seed, dsMaskMsg(msg.size()), SEED_BYTES);
    let mask = Hash.shake256(shakeSeed, msg.size());
    Array.tabulate<Nat8>(msg.size(), func i = mask[i] ^ msg[i]);
  };

  /// The scalar the ciphertext commits to.
  func hashToMask(header : [Nat8], seed : [Nat8], msg : [Nat8]) : Scalar.Scalar {
    let input = Array.concat<Nat8>(Array.concat<Nat8>(header, seed), msg);
    Scalar.hashToScalar(input, DS_HASH_TO_MASK);
  };

  /// Decrypts, given the vetKey for the identity this was sealed to.
  ///
  /// Returns `null` when the ciphertext does not verify — which happens when
  /// the vetKey is for a different identity, the ciphertext was tampered with,
  /// or it was sealed under a different context.
  ///
  /// The final check is what makes this authenticated: after recovering the
  /// message, the scalar it commits to is recomputed and `c1` must equal
  /// `g2^t`. Without it, a wrong key would yield plausible-looking garbage
  /// rather than an error (`utils/mod.rs:1159`).
  public func decrypt(ct : Ciphertext, vetkeyPoint : G1.Affine) : ?[Nat8] {
    let tsig = Pairing.pairing(vetkeyPoint, ct.c1);
    let seed = maskSeed(ct.c2, tsig);
    let msg = maskMsg(ct.c3, seed);
    let t = hashToMask(ct.header, seed, msg);
    let gT = G2.toAffine(G2.mul(G2.fromAffine(G2.generator), t));
    if (G2.equalAffine(ct.c1, gT)) { ?msg } else { null };
  };
}
