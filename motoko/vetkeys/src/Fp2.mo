/// The quadratic extension `F_p2 = F_p[u] / (u^2 + 1)`.
///
/// # ⚠️ EXPERIMENTAL AND UNAUDITED — see ../README.md
///
/// An element is `c0 + c1·u` with `u^2 = -1`. This is where `G2` lives, and it
/// is the first floor of the tower the pairing is built on.
///
/// Ported from `ic_bls12_381::fp2`, semantics preserved, representation not —
/// see `Fp.mo` for why.

import Fp "Fp";
import Blob "mo:core/Blob";
import Array "mo:core/Array";

module {
  /// `c0 + c1·u`.
  public type Fp2 = { c0 : Fp.Fp; c1 : Fp.Fp };

  /// Bytes in the canonical encoding: `c1 || c0`, big-endian, as the reference
  /// serializes it. Note the order — c1 comes first, which is easy to get wrong.
  public let BYTES : Nat = 96;

  public let zero : Fp2 = { c0 = Fp.zero; c1 = Fp.zero };
  public let one : Fp2 = { c0 = Fp.one; c1 = Fp.zero };

  public func isZero(a : Fp2) : Bool = Fp.isZero(a.c0) and Fp.isZero(a.c1);

  public func equal(a : Fp2, b : Fp2) : Bool =
    Fp.equal(a.c0, b.c0) and Fp.equal(a.c1, b.c1);

  /// Lifts a base-field element.
  public func fromFp(a : Fp.Fp) : Fp2 = { c0 = a; c1 = Fp.zero };

  public func add(a : Fp2, b : Fp2) : Fp2 = {
    c0 = Fp.add(a.c0, b.c0);
    c1 = Fp.add(a.c1, b.c1);
  };

  public func sub(a : Fp2, b : Fp2) : Fp2 = {
    c0 = Fp.sub(a.c0, b.c0);
    c1 = Fp.sub(a.c1, b.c1);
  };

  public func neg(a : Fp2) : Fp2 = { c0 = Fp.neg(a.c0); c1 = Fp.neg(a.c1) };

  public func double(a : Fp2) : Fp2 = add(a, a);

  /// `(a0 + a1·u)(b0 + b1·u) = (a0·b0 − a1·b1) + (a0·b1 + a1·b0)·u`, using
  /// `u^2 = −1`.
  public func mul(a : Fp2, b : Fp2) : Fp2 = {
    c0 = Fp.sub(Fp.mul(a.c0, b.c0), Fp.mul(a.c1, b.c1));
    c1 = Fp.add(Fp.mul(a.c0, b.c1), Fp.mul(a.c1, b.c0));
  };

  /// `(a0 + a1·u)^2 = (a0 + a1)(a0 − a1) + 2·a0·a1·u`.
  ///
  /// The difference-of-squares form costs one multiplication instead of two,
  /// which matters: squaring dominates the Miller loop.
  public func square(a : Fp2) : Fp2 {
    let sum = Fp.add(a.c0, a.c1);
    let diff = Fp.sub(a.c0, a.c1);
    {
      c0 = Fp.mul(sum, diff);
      c1 = Fp.double(Fp.mul(a.c0, a.c1));
    };
  };

  /// The conjugate `c0 − c1·u`, which is also the Frobenius endomorphism here.
  public func conjugate(a : Fp2) : Fp2 = { c0 = a.c0; c1 = Fp.neg(a.c1) };

  /// `a · conjugate(a) = c0^2 + c1^2`, an element of the base field.
  public func norm(a : Fp2) : Fp.Fp =
    Fp.add(Fp.square(a.c0), Fp.square(a.c1));

  /// Multiplication by `u + 1`, the non-residue the next tower floor is built
  /// on: `(c0 + c1·u)(1 + u) = (c0 − c1) + (c0 + c1)·u`.
  public func mulByNonresidue(a : Fp2) : Fp2 = {
    c0 = Fp.sub(a.c0, a.c1);
    c1 = Fp.add(a.c0, a.c1);
  };

  /// `conjugate(a) / norm(a)`. Returns `null` only for zero.
  public func inverse(a : Fp2) : ?Fp2 {
    switch (Fp.inverse(norm(a))) {
      case null null;
      case (?nInv) ?{
        c0 = Fp.mul(a.c0, nInv);
        c1 = Fp.neg(Fp.mul(a.c1, nInv));
      };
    };
  };

  /// `a^e`, exponent public — see `Fp.pow`.
  public func pow(a : Fp2, e : Nat) : Fp2 {
    var result = one;
    var base = a;
    var exp = e;
    while (exp > 0) {
      if (exp % 2 == 1) { result := mul(result, base) };
      base := square(base);
      exp /= 2;
    };
    result;
  };

  /// Square root, following Algorithm 9 of <https://eprint.iacr.org/2012/685.pdf>
  /// — the same one the reference uses (`fp2.rs`, `sqrt`).
  ///
  /// The awkward case is `alpha = −1`: the element then has order `p − 1`, so it
  /// is the square of something in the base subfield, and the root is `x0 · u`.
  /// Getting that branch wrong yields a function that works on most inputs and
  /// silently fails on a few, which is why the tests cover both paths.
  public func sqrt(a : Fp2) : ?Fp2 {
    if (isZero(a)) { return ?zero };

    // a1 = a^((p − 3) / 4)
    let a1 = pow(a, (Fp.P - 3 : Nat) / 4);
    // alpha = a1^2 · a
    let alpha = mul(square(a1), a);
    // x0 = a^((p + 1) / 4)
    let x0 = mul(a1, a);

    let candidate = if (equal(alpha, neg(one))) {
      { c0 = Fp.neg(x0.c1); c1 = x0.c0 };
    } else {
      mul(pow(add(alpha, one), (Fp.P - 1 : Nat) / 2), x0);
    };

    if (equal(square(candidate), a)) { ?candidate } else { null };
  };

  /// True when the element is lexicographically larger than its negation, by
  /// `c1` first and `c0` only as a tiebreak — the ordering point compression
  /// depends on.
  public func lexicographicallyLargest(a : Fp2) : Bool {
    if (Fp.isZero(a.c1)) { Fp.lexicographicallyLargest(a.c0) } else {
      Fp.lexicographicallyLargest(a.c1);
    };
  };

  /// 96 bytes, `c1 || c0`, big-endian.
  public func toBytes(a : Fp2) : Blob {
    let c1 = Blob.toArray(Fp.toBytes(a.c1));
    let c0 = Blob.toArray(Fp.toBytes(a.c0));
    Array.toBlob(Array.concat<Nat8>(c1, c0));
  };

  /// Parses 96 bytes as `c1 || c0`, rejecting non-canonical components.
  public func fromBytes(b : Blob) : ?Fp2 {
    let arr = Blob.toArray(b);
    if (arr.size() != BYTES) { return null };
    let c1 = Array.toBlob(Array.sliceToArray<Nat8>(arr, 0, Fp.BYTES));
    let c0 = Array.toBlob(Array.sliceToArray<Nat8>(arr, Fp.BYTES, BYTES));
    switch (Fp.fromBytes(c1), Fp.fromBytes(c0)) {
      case (?v1, ?v0) ?{ c0 = v0; c1 = v1 };
      case _ null;
    };
  };
}
