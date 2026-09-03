/// Scalars: integers modulo the group order `r`.
///
/// # ⚠️ EXPERIMENTAL AND UNAUDITED — see ../README.md
///
/// `r` is the order of both `G1` and `G2`, so scalars are what multiplies a
/// point. Distinct from `Fp`, whose modulus is the larger base-field prime.

import Hash "Hash";
import Array "mo:core/Array";
import Nat "mo:core/Nat";
import Nat8 "mo:core/Nat8";
import Blob "mo:core/Blob";
import Text "mo:core/Text";

module {
  /// The group order,
  /// `r = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001`.
  public let R : Nat =
    52435875175126190479447740508185965837690552500527637822603658699938581184513;

  public type Scalar = Nat;

  public let BYTES : Nat = 32;

  public func fromNat(n : Nat) : Scalar = n % R;

  /// Big-endian, 32 bytes.
  public func toBytes(s : Scalar) : [Nat8] {
    Array.tabulate(
      BYTES,
      func i {
        let shift = (BYTES - 1 - i : Nat) * 8;
        Nat.toNat8((s / (2 ** shift)) % 256);
      },
    );
  };

  /// Parses 32 big-endian bytes, rejecting values at or above `r`.
  public func fromBytes(b : [Nat8]) : ?Scalar {
    if (b.size() != BYTES) { return null };
    var acc : Nat = 0;
    for (byte in b.vals()) { acc := acc * 256 + byte.toNat() };
    if (acc >= R) { null } else { ?acc };
  };

  /// Hashes to a scalar, matching `ic-vetkeys`' `hash_to_scalar`
  /// (`utils/mod.rs:245`).
  ///
  /// RFC 9380 `hash_to_field` with `L = 48`: expand to 48 bytes, interpret
  /// big-endian, reduce mod `r`. The 48 is not arbitrary — it gives enough
  /// excess over the 32-byte modulus that the reduction bias is negligible, and
  /// using 32 instead would produce different scalars *and* a biased
  /// distribution.
  public func hashToScalar(input : [Nat8], domainSep : Text) : Scalar {
    let dst = domainSep.encodeUtf8().toArray();
    let expanded = Hash.expandMessageXmd(input, dst, 48);
    var acc : Nat = 0;
    for (byte in expanded.vals()) { acc := acc * 256 + byte.toNat() };
    acc % R;
  };
}
