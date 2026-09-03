/// The sextic extension `F_p6 = F_p2[v] / (v^3 − (u + 1))`.
///
/// # ⚠️ EXPERIMENTAL AND UNAUDITED — see ../README.md
///
/// An element is `c0 + c1·v + c2·v^2` over `F_p2`, with `v^3 = u + 1`. This floor
/// exists only to carry `F_p12`, which is where pairing values live.
///
/// Ported from `ic_bls12_381::fp6`.

import Fp "Fp";
import Fp2 "Fp2";

module {
  public type Fp6 = { c0 : Fp2.Fp2; c1 : Fp2.Fp2; c2 : Fp2.Fp2 };

  public let zero : Fp6 = { c0 = Fp2.zero; c1 = Fp2.zero; c2 = Fp2.zero };
  public let one : Fp6 = { c0 = Fp2.one; c1 = Fp2.zero; c2 = Fp2.zero };

  public func isZero(a : Fp6) : Bool =
    Fp2.isZero(a.c0) and Fp2.isZero(a.c1) and Fp2.isZero(a.c2);

  public func equal(a : Fp6, b : Fp6) : Bool =
    Fp2.equal(a.c0, b.c0) and Fp2.equal(a.c1, b.c1) and Fp2.equal(a.c2, b.c2);

  public func fromFp2(a : Fp2.Fp2) : Fp6 = { c0 = a; c1 = Fp2.zero; c2 = Fp2.zero };

  public func add(a : Fp6, b : Fp6) : Fp6 = {
    c0 = Fp2.add(a.c0, b.c0);
    c1 = Fp2.add(a.c1, b.c1);
    c2 = Fp2.add(a.c2, b.c2);
  };

  public func sub(a : Fp6, b : Fp6) : Fp6 = {
    c0 = Fp2.sub(a.c0, b.c0);
    c1 = Fp2.sub(a.c1, b.c1);
    c2 = Fp2.sub(a.c2, b.c2);
  };

  public func neg(a : Fp6) : Fp6 = {
    c0 = Fp2.neg(a.c0);
    c1 = Fp2.neg(a.c1);
    c2 = Fp2.neg(a.c2);
  };

  public func double(a : Fp6) : Fp6 = add(a, a);

  /// Multiplication by `v`: `a + bv + cv^2` becomes `c·(u+1) + av + bv^2`,
  /// since `v^3 = u + 1` (`fp6.rs:139`).
  public func mulByNonresidue(a : Fp6) : Fp6 = {
    c0 = Fp2.mulByNonresidue(a.c2);
    c1 = a.c0;
    c2 = a.c1;
  };

  /// Karatsuba over three terms: six `Fp2` multiplications instead of the nine
  /// a schoolbook expansion needs. Multiplication dominates the Miller loop, so
  /// the saving is the difference between comfortable and marginal.
  public func mul(a : Fp6, b : Fp6) : Fp6 {
    let v0 = Fp2.mul(a.c0, b.c0);
    let v1 = Fp2.mul(a.c1, b.c1);
    let v2 = Fp2.mul(a.c2, b.c2);

    let t1 = Fp2.sub(
      Fp2.sub(Fp2.mul(Fp2.add(a.c1, a.c2), Fp2.add(b.c1, b.c2)), v1),
      v2,
    );
    let t2 = Fp2.sub(
      Fp2.sub(Fp2.mul(Fp2.add(a.c0, a.c1), Fp2.add(b.c0, b.c1)), v0),
      v1,
    );
    let t3 = Fp2.sub(
      Fp2.sub(Fp2.mul(Fp2.add(a.c0, a.c2), Fp2.add(b.c0, b.c2)), v0),
      v2,
    );

    {
      c0 = Fp2.add(v0, Fp2.mulByNonresidue(t1));
      c1 = Fp2.add(t2, Fp2.mulByNonresidue(v2));
      c2 = Fp2.add(t3, v1);
    };
  };

  /// `fp6.rs:277`.
  public func square(a : Fp6) : Fp6 {
    let s0 = Fp2.square(a.c0);
    let ab = Fp2.mul(a.c0, a.c1);
    let s1 = Fp2.add(ab, ab);
    let s2 = Fp2.square(Fp2.add(Fp2.sub(a.c0, a.c1), a.c2));
    let bc = Fp2.mul(a.c1, a.c2);
    let s3 = Fp2.add(bc, bc);
    let s4 = Fp2.square(a.c2);

    {
      c0 = Fp2.add(Fp2.mulByNonresidue(s3), s0);
      c1 = Fp2.add(Fp2.mulByNonresidue(s4), s1);
      c2 = Fp2.sub(Fp2.sub(Fp2.add(Fp2.add(s1, s2), s3), s0), s4);
    };
  };

  /// `(u + 1)^((p − 1) / 3)`, the coefficient the Frobenius map applies to `c1`.
  ///
  /// The reference stores this in Montgomery form, which cannot be read off the
  /// page. These were computed independently and are re-derived by
  /// `test/Fp6.test.mo`, so the constant is checked rather than trusted — and the
  /// shape agrees with the reference (this one is purely imaginary, the next
  /// purely real).
  public let FROBENIUS_C1 : Fp2.Fp2 = {
    c0 = 0;
    c1 = 4002409555221667392624310435006688643935503118305586438271171395842971157480381377015405980053539358417135540939436;
  };

  /// `(u + 1)^((2p − 2) / 3)`, applied to `c2`.
  public let FROBENIUS_C2 : Fp2.Fp2 = {
    c0 = 4002409555221667392624310435006688643935503118305586438271171395842971157480381377015405980053539358417135540939437;
    c1 = 0;
  };

  /// The Frobenius endomorphism `x -> x^p` (`fp6.rs:154`).
  public func frobeniusMap(a : Fp6) : Fp6 = {
    c0 = Fp2.conjugate(a.c0);
    c1 = Fp2.mul(Fp2.conjugate(a.c1), FROBENIUS_C1);
    c2 = Fp2.mul(Fp2.conjugate(a.c2), FROBENIUS_C2);
  };

  /// `fp6.rs:294`.
  public func inverse(a : Fp6) : ?Fp6 {
    let c0 = Fp2.sub(Fp2.square(a.c0), Fp2.mulByNonresidue(Fp2.mul(a.c1, a.c2)));
    let c1 = Fp2.sub(Fp2.mulByNonresidue(Fp2.square(a.c2)), Fp2.mul(a.c0, a.c1));
    let c2 = Fp2.sub(Fp2.square(a.c1), Fp2.mul(a.c0, a.c2));

    let tmp = Fp2.add(
      Fp2.mulByNonresidue(Fp2.add(Fp2.mul(a.c1, c2), Fp2.mul(a.c2, c1))),
      Fp2.mul(a.c0, c0),
    );

    switch (Fp2.inverse(tmp)) {
      case null null;
      case (?t) ?{
        c0 = Fp2.mul(t, c0);
        c1 = Fp2.mul(t, c1);
        c2 = Fp2.mul(t, c2);
      };
    };
  };

  /// Multiplication by an element with only `c0` and `c1` populated, which is
  /// the shape the Miller loop's line evaluations produce. Cheaper than the
  /// general case, and used often enough to matter.
  public func mulBy01(a : Fp6, b0 : Fp2.Fp2, b1 : Fp2.Fp2) : Fp6 {
    let aa = Fp2.mul(a.c0, b0);
    let bb = Fp2.mul(a.c1, b1);

    let t1 = Fp2.add(Fp2.mulByNonresidue(Fp2.mul(a.c2, b1)), aa);
    let t2 = Fp2.sub(
      Fp2.sub(Fp2.mul(Fp2.add(b0, b1), Fp2.add(a.c0, a.c1)), aa),
      bb,
    );
    let t3 = Fp2.add(Fp2.mul(a.c2, b0), bb);

    { c0 = t1; c1 = t2; c2 = t3 };
  };

  /// Multiplication by an element with only `c1` populated.
  public func mulBy1(a : Fp6, b1 : Fp2.Fp2) : Fp6 = {
    c0 = Fp2.mulByNonresidue(Fp2.mul(a.c2, b1));
    c1 = Fp2.mul(a.c0, b1);
    c2 = Fp2.mul(a.c1, b1);
  };

  public func pow(a : Fp6, e : Nat) : Fp6 {
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

  /// Unused here but kept for parity with the reference's surface.
  public func mulByFp(a : Fp6, s : Fp.Fp) : Fp6 {
    let m = Fp2.fromFp(s);
    { c0 = Fp2.mul(a.c0, m); c1 = Fp2.mul(a.c1, m); c2 = Fp2.mul(a.c2, m) };
  };
}
