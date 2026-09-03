/// The dodecic extension `F_p12 = F_p6[w] / (w^2 − v)`.
///
/// # ⚠️ EXPERIMENTAL AND UNAUDITED — see ../README.md
///
/// An element is `c0 + c1·w` over `F_p6`, with `w^2 = v`. This is the target
/// group of the pairing: `e(P, Q)` lands here, and so does everything the final
/// exponentiation touches.
///
/// Ported from `ic_bls12_381::fp12`.

import Fp2 "Fp2";
import Fp6 "Fp6";

module {
  public type Fp12 = { c0 : Fp6.Fp6; c1 : Fp6.Fp6 };

  public let zero : Fp12 = { c0 = Fp6.zero; c1 = Fp6.zero };
  public let one : Fp12 = { c0 = Fp6.one; c1 = Fp6.zero };

  public func isZero(a : Fp12) : Bool = Fp6.isZero(a.c0) and Fp6.isZero(a.c1);

  public func equal(a : Fp12, b : Fp12) : Bool =
    Fp6.equal(a.c0, b.c0) and Fp6.equal(a.c1, b.c1);

  public func fromFp6(a : Fp6.Fp6) : Fp12 = { c0 = a; c1 = Fp6.zero };

  public func add(a : Fp12, b : Fp12) : Fp12 = {
    c0 = Fp6.add(a.c0, b.c0);
    c1 = Fp6.add(a.c1, b.c1);
  };

  public func sub(a : Fp12, b : Fp12) : Fp12 = {
    c0 = Fp6.sub(a.c0, b.c0);
    c1 = Fp6.sub(a.c1, b.c1);
  };

  public func neg(a : Fp12) : Fp12 = { c0 = Fp6.neg(a.c0); c1 = Fp6.neg(a.c1) };

  /// `c0 − c1·w`.
  ///
  /// In the cyclotomic subgroup — which is where every pairing value lives after
  /// the final exponentiation — conjugation *is* inversion, and the final
  /// exponentiation relies on that being true.
  public func conjugate(a : Fp12) : Fp12 = { c0 = a.c0; c1 = Fp6.neg(a.c1) };

  /// Karatsuba over two terms, reducing with `w^2 = v`.
  public func mul(a : Fp12, b : Fp12) : Fp12 {
    let aa = Fp6.mul(a.c0, b.c0);
    let bb = Fp6.mul(a.c1, b.c1);
    let o = Fp6.add(b.c0, b.c1);
    let c1 = Fp6.sub(
      Fp6.sub(Fp6.mul(Fp6.add(a.c1, a.c0), o), aa),
      bb,
    );
    { c0 = Fp6.add(Fp6.mulByNonresidue(bb), aa); c1 };
  };

  /// `fp12.rs:174`.
  public func square(a : Fp12) : Fp12 {
    let ab = Fp6.mul(a.c0, a.c1);
    let c0c1 = Fp6.add(a.c0, a.c1);
    var c0 = Fp6.mulByNonresidue(a.c1);
    c0 := Fp6.add(c0, a.c0);
    c0 := Fp6.mul(c0, c0c1);
    c0 := Fp6.sub(c0, ab);
    let c1 = Fp6.add(ab, ab);
    c0 := Fp6.sub(c0, Fp6.mulByNonresidue(ab));
    { c0; c1 };
  };

  /// `fp12.rs:187`.
  public func inverse(a : Fp12) : ?Fp12 {
    let t = Fp6.sub(Fp6.square(a.c0), Fp6.mulByNonresidue(Fp6.square(a.c1)));
    switch (Fp6.inverse(t)) {
      case null null;
      case (?tInv) ?{
        c0 = Fp6.mul(a.c0, tInv);
        c1 = Fp6.mul(a.c1, Fp6.neg(tInv));
      };
    };
  };

  /// `(u + 1)^((p − 1) / 6)`, the coefficient the Frobenius map applies to `c1`.
  ///
  /// As with `Fp6`, computed independently rather than read from the
  /// reference's Montgomery form, and re-derived in the tests.
  public let FROBENIUS_C1 : Fp2.Fp2 = {
    c0 = 3850754370037169011952147076051364057158807420970682438676050522613628423219637725072182697113062777891589506424760;
    c1 = 151655185184498381465642749684540099398075398968325446656007613510403227271200139370504932015952886146304766135027;
  };

  /// `x -> x^p`.
  public func frobeniusMap(a : Fp12) : Fp12 {
    let c0 = Fp6.frobeniusMap(a.c0);
    let f1 = Fp6.frobeniusMap(a.c1);
    {
      c0;
      c1 = {
        c0 = Fp2.mul(f1.c0, FROBENIUS_C1);
        c1 = Fp2.mul(f1.c1, FROBENIUS_C1);
        c2 = Fp2.mul(f1.c2, FROBENIUS_C1);
      };
    };
  };

  /// Multiplication by an element sparse in the way a Miller-loop line
  /// evaluation is: only `c0`, `c1` of the lower `Fp6` and `c1` of the upper
  /// are populated (`fp12.rs:116`).
  ///
  /// This is the single hottest operation in the pairing, called once per
  /// Miller-loop step.
  public func mulBy014(a : Fp12, c0 : Fp2.Fp2, c1 : Fp2.Fp2, c4 : Fp2.Fp2) : Fp12 {
    let aa = Fp6.mulBy01(a.c0, c0, c1);
    let bb = Fp6.mulBy1(a.c1, c4);
    let o = Fp2.add(c1, c4);
    var t = Fp6.add(a.c1, a.c0);
    t := Fp6.mulBy01(t, c0, o);
    t := Fp6.sub(Fp6.sub(t, aa), bb);
    { c0 = Fp6.add(Fp6.mulByNonresidue(bb), aa); c1 = t };
  };

  public func pow(a : Fp12, e : Nat) : Fp12 {
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

  /// `a^e` where the exponent is given as a `Nat` and the result is inverted if
  /// `negative` — the shape the BLS parameter needs, since `x` is negative for
  /// this curve.
  public func powSigned(a : Fp12, e : Nat, negative : Bool) : ?Fp12 {
    let r = pow(a, e);
    if (negative) { inverse(r) } else { ?r };
  };
}
