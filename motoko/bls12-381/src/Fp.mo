/// The BLS12-381 base field, `F_p`.
///
/// # ⚠️ EXPERIMENTAL AND UNAUDITED
///
/// This is a proof-of-concept port. It has not been reviewed by a cryptographer
/// and must not be used in production. See the repository README.
///
/// # Representation
///
/// The reference (`ic_bls12_381::fp`) stores an element as `[u64; 6]` in
/// Montgomery form, built on 64×64→128 multiplication. Motoko has no widening
/// 64-bit multiply, so each partial product of a limb representation would
/// round-trip through `Nat` anyway.
///
/// So an element is a `Nat` in `[0, p)`. Multiplication is a bignum product
/// followed by **Barrett reduction**: two multiplications and two shifts in
/// place of the division `%` would perform. `Nat.bitshiftRight` is an order of
/// magnitude cheaper than dividing by a power of two, which is what makes this
/// pay — `bench/Why.bench.mo` measures the split.

import Bits "Bits";
import Nat "mo:core/Nat";
import Nat8 "mo:core/Nat8";
import Int "mo:core/Int";
import Blob "mo:core/Blob";
import Array "mo:core/Array";

module {
  /// The field modulus:
  /// `p = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab`
  ///
  /// Reassembled from the reference's little-endian `MODULUS: [u64; 6]`
  /// (`fp.rs:70`); `test/Fp.test.mo` pins it against the published hex.
  public let P : Nat =
    4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787;

  /// `floor(2^762 / P)`, the Barrett constant for `P`'s 381-bit width.
  /// `test/Fp.test.mo` re-derives it.
  public let BARRETT_MU : Nat =
    6060872796126202341416486485954650311182547756064496405659909846341149209992573236889604617486802525004416140330728;

  /// An element of `F_p`, always reduced into `[0, P)`.
  public type Fp = Nat;

  /// Bytes in the canonical big-endian encoding of an element.
  public let BYTES : Nat = 48;

  public let zero : Fp = 0;
  public let one : Fp = 1;

  public func isZero(a : Fp) : Bool = a == 0;
  public func equal(a : Fp, b : Fp) : Bool = a == b;

  /// Reduces an arbitrary `Nat` into the field.
  public func fromNat(a : Nat) : Fp = a % P;

  public func add(a : Fp, b : Fp) : Fp {
    let s = a + b;
    if (s >= P) { s - P : Nat } else { s };
  };

  public func sub(a : Fp, b : Fp) : Fp {
    if (a >= b) { a - b : Nat } else { P - (b - a : Nat) : Nat };
  };

  public func neg(a : Fp) : Fp = if (a == 0) { 0 } else { P - a : Nat };

  /// Reduces a product of two field elements, `x < P^2`, by Barrett's method
  /// (Handbook of Applied Cryptography, 14.42).
  ///
  /// `q` never exceeds `x / P` and falls short of it by at most two, so the
  /// subtraction cannot underflow and at most two corrections follow.
  func reduce(x : Nat) : Fp {
    let q = Nat.bitshiftRight(Nat.bitshiftRight(x, 380) * BARRETT_MU, 382);
    var r : Nat = x - q * P;
    if (r >= P) { r -= P };
    if (r >= P) { r -= P };
    r;
  };

  public func mul(a : Fp, b : Fp) : Fp = reduce(a * b);

  public func square(a : Fp) : Fp = reduce(a * a);

  public func double(a : Fp) : Fp = add(a, a);

  /// `a^e mod P`, by left-to-right square-and-multiply.
  ///
  /// The exponent is public in every use here (it is always a fixed constant
  /// such as `(p-3)/4`), so a data-independent ladder is not required. Do not
  /// reuse this with a secret exponent.
  public func pow(a : Fp, e : Nat) : Fp {
    var result : Fp = 1;
    for (bit in Bits.msbFirst(e).vals()) {
      result := square(result);
      if (bit) { result := mul(result, a) };
    };
    result;
  };

  /// Multiplicative inverse, by the extended Euclidean algorithm.
  ///
  /// Returns `null` for zero, which has no inverse.
  public func inverse(a : Fp) : ?Fp {
    if (a == 0) { return null };
    var r0 : Int = P;
    var r1 : Int = a;
    var t0 : Int = 0;
    var t1 : Int = 1;
    while (r1 != 0) {
      let q = r0 / r1;
      let r2 = r0 - q * r1;
      r0 := r1;
      r1 := r2;
      let t2 = t0 - q * t1;
      t0 := t1;
      t1 := t2;
    };
    ?Int.abs(if (t0 < 0) { t0 + P } else { t0 });
  };

  /// The square root, when one exists.
  ///
  /// `p ≡ 3 (mod 4)`, so a root is `a^((p+1)/4)` — the same shortcut the
  /// reference uses (`fp.rs`, `sqrt`). Squaring the candidate is what decides
  /// whether `a` was actually a residue.
  public func sqrt(a : Fp) : ?Fp {
    let candidate = pow(a, (P + 1) / 4);
    if (mul(candidate, candidate) == a) { ?candidate } else { null };
  };

  /// True when the element is lexicographically larger than its negation.
  ///
  /// Point compression stores this bit to pick between the two roots.
  public func lexicographicallyLargest(a : Fp) : Bool = a > (P - 1 : Nat) / 2;

  /// Big-endian, 48 bytes, as in the reference's `to_bytes`.
  public func toBytes(a : Fp) : Blob {
    let out = Array.tabulate(
      BYTES,
      func i {
        Bits.byteAt(a, (BYTES - 1 - i : Nat) * 8);
      },
    );
    out.toBlob();
  };

  /// Parses 48 big-endian bytes, rejecting anything not already reduced.
  ///
  /// The reference rejects non-canonical encodings here, and so does this: two
  /// encodings of one element would break the equality that point compression
  /// and signature verification depend on.
  public func fromBytes(b : Blob) : ?Fp {
    let arr = b.toArray();
    if (arr.size() != BYTES) { return null };
    var acc : Nat = 0;
    for (byte in arr.vals()) { acc := acc * 256 + byte.toNat() };
    if (acc >= P) { null } else { ?acc };
  };
}
