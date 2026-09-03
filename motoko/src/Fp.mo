/// The BLS12-381 base field, `F_p`.
///
/// # ⚠️ EXPERIMENTAL AND UNAUDITED
///
/// This is a proof-of-concept port. It has not been reviewed by a cryptographer
/// and must not be used in production. See the repository README.
///
/// # Why this does not mirror the Rust representation
///
/// The reference (`ic_bls12_381::fp`) stores an element as `[u64; 6]` in
/// Montgomery form, with hand-written carry propagation built on 64×64→128
/// multiplication. Motoko has no `Nat128`, so every such multiply would have to
/// be split into 32-bit halves and reassembled — roughly four multiplications
/// and a carry chain each, across ~1000 lines whose correctness lives entirely
/// in those carries.
///
/// This port keeps the *semantics* and drops the representation: an element is a
/// `Nat` in `[0, p)`, and the operations are ordinary modular arithmetic. That is
/// a fraction of the code, it is reviewable by reading it, and it is validated
/// against the reference's own test vectors. The cost is speed — see
/// `test/Bench.mo` for measured instruction counts against the 40 billion
/// per-update budget.
///
/// If the benchmark ever says this is too slow, the limb representation is the
/// escape hatch, and the test vectors here are what would make that port safe.

import Nat "mo:core/Nat";
import Nat8 "mo:core/Nat8";
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

  public func mul(a : Fp, b : Fp) : Fp = (a * b) % P;

  public func square(a : Fp) : Fp = (a * a) % P;

  public func double(a : Fp) : Fp = add(a, a);

  /// `a^e mod P`, by square-and-multiply.
  ///
  /// The exponent is public in every use here (it is always a fixed constant
  /// such as `(p-3)/4`), so a data-independent ladder is not required. Do not
  /// reuse this with a secret exponent.
  public func pow(a : Fp, e : Nat) : Fp {
    var result : Fp = 1;
    var base = a % P;
    var exp = e;
    while (exp > 0) {
      if (exp % 2 == 1) { result := (result * base) % P };
      base := (base * base) % P;
      exp /= 2;
    };
    result;
  };

  /// Multiplicative inverse via Fermat's little theorem: `a^(p-2)`.
  ///
  /// Returns `null` for zero, which has no inverse.
  public func inverse(a : Fp) : ?Fp {
    if (a == 0) { return null };
    ?pow(a, P - 2 : Nat);
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
    let out = Array.tabulate<Nat8>(
      BYTES,
      func i {
        let shift = (BYTES - 1 - i : Nat) * 8;
        Nat.toNat8((a / (2 ** shift)) % 256);
      },
    );
    Array.toBlob(out);
  };

  /// Parses 48 big-endian bytes, rejecting anything not already reduced.
  ///
  /// The reference rejects non-canonical encodings here, and so does this: two
  /// encodings of one element would break the equality that point compression
  /// and signature verification depend on.
  public func fromBytes(b : Blob) : ?Fp {
    let arr = Blob.toArray(b);
    if (arr.size() != BYTES) { return null };
    var acc : Nat = 0;
    for (byte in arr.vals()) { acc := acc * 256 + Nat8.toNat(byte) };
    if (acc >= P) { null } else { ?acc };
  };
}
