/// The optimal ate pairing `e : G1 × G2 → F_p12`.
///
/// # ⚠️ EXPERIMENTAL AND UNAUDITED — see ../README.md
///
/// Ported from `ic_bls12_381::pairings`. Two halves:
///
///   - the **Miller loop**, which walks the bits of the curve parameter `x`,
///     accumulating line evaluations into an `Fp12`;
///   - the **final exponentiation**, which raises that to `(p^12 − 1)/r` and is
///     what makes the result bilinear and non-degenerate.
///
/// The final exponentiation is not a plain `pow` — the exponent has ~4000 bits.
/// It is factored into an easy part, which conjugation and Frobenius handle
/// almost for free, and a hard part expressed through `cyclotomicExp`, which
/// exploits the fact that inversion in the cyclotomic subgroup is conjugation.

import Fp "Fp";
import Fp2 "Fp2";
import Fp12 "Fp12";
import G1 "G1";
import G2 "G2";

module {
  /// The BLS12-381 curve parameter, `x = -0xd201000000010000`. Negative, which
  /// is why the Miller loop ends with a conjugation.
  let BLS_X : Nat = 0xd201_0000_0001_0000;
  let BLS_X_IS_NEGATIVE : Bool = true;

  /// The three `Fp2` coefficients of one line evaluation.
  type Coeffs = (Fp2.Fp2, Fp2.Fp2, Fp2.Fp2);

  /// Algorithm 26 of <https://eprint.iacr.org/2010/354.pdf>, doubling `r` and
  /// returning the line through it (`pairings.rs:721`).
  func doublingStep(r : G2.Point) : (G2.Point, Coeffs) {
    let tmp0 = Fp2.square(r.x);
    let tmp1 = Fp2.square(r.y);
    let tmp2 = Fp2.square(tmp1);
    var tmp3 = Fp2.sub(Fp2.sub(Fp2.square(Fp2.add(tmp1, r.x)), tmp0), tmp2);
    tmp3 := Fp2.add(tmp3, tmp3);
    let tmp4 = Fp2.add(Fp2.add(tmp0, tmp0), tmp0);
    var tmp6 = Fp2.add(r.x, tmp4);
    let tmp5 = Fp2.square(tmp4);
    let zsquared = Fp2.square(r.z);

    let rx = Fp2.sub(Fp2.sub(tmp5, tmp3), tmp3);
    let rz = Fp2.sub(Fp2.sub(Fp2.square(Fp2.add(r.z, r.y)), tmp1), zsquared);
    var ry = Fp2.mul(Fp2.sub(tmp3, rx), tmp4);

    var t2 = Fp2.add(tmp2, tmp2);
    t2 := Fp2.add(t2, t2);
    t2 := Fp2.add(t2, t2);
    ry := Fp2.sub(ry, t2);

    var t3 = Fp2.mul(tmp4, zsquared);
    t3 := Fp2.add(t3, t3);
    t3 := Fp2.neg(t3);

    tmp6 := Fp2.sub(Fp2.sub(Fp2.square(tmp6), tmp0), tmp5);
    var t1 = Fp2.add(tmp1, tmp1);
    t1 := Fp2.add(t1, t1);
    tmp6 := Fp2.sub(tmp6, t1);

    var t0 = Fp2.mul(rz, zsquared);
    t0 := Fp2.add(t0, t0);

    ({ x = rx; y = ry; z = rz }, (t0, t3, tmp6));
  };

  /// Algorithm 27 of the same paper, adding `q` to `r` (`pairings.rs:752`).
  func additionStep(r : G2.Point, q : G2.Affine) : (G2.Point, Coeffs) {
    let zsquared = Fp2.square(r.z);
    let ysquared = Fp2.square(q.y);
    let t0 = Fp2.mul(zsquared, q.x);
    let t1 = Fp2.mul(
      Fp2.sub(Fp2.sub(Fp2.square(Fp2.add(q.y, r.z)), ysquared), zsquared),
      zsquared,
    );
    let t2 = Fp2.sub(t0, r.x);
    let t3 = Fp2.square(t2);
    var t4 = Fp2.add(t3, t3);
    t4 := Fp2.add(t4, t4);
    let t5 = Fp2.mul(t4, t2);
    let t6 = Fp2.sub(Fp2.sub(t1, r.y), r.y);
    var t9 = Fp2.mul(t6, q.x);
    let t7 = Fp2.mul(t4, r.x);

    let rx = Fp2.sub(Fp2.sub(Fp2.sub(Fp2.square(t6), t5), t7), t7);
    let rz = Fp2.sub(Fp2.sub(Fp2.square(Fp2.add(r.z, t2)), zsquared), t3);
    var t10 = Fp2.add(q.y, rz);
    let t8 = Fp2.mul(Fp2.sub(t7, rx), t6);
    var t0b = Fp2.mul(r.y, t5);
    t0b := Fp2.add(t0b, t0b);
    let ry = Fp2.sub(t8, t0b);

    t10 := Fp2.sub(Fp2.square(t10), ysquared);
    let ztsquared = Fp2.square(rz);
    t10 := Fp2.sub(t10, ztsquared);
    t9 := Fp2.sub(Fp2.add(t9, t9), t10);
    t10 := Fp2.add(rz, rz);
    let t6n = Fp2.neg(t6);
    let t1b = Fp2.add(t6n, t6n);

    ({ x = rx; y = ry; z = rz }, (t10, t1b, t9));
  };

  /// Folds one line evaluation into the accumulator (`pairings.rs:708`).
  func ell(f : Fp12.Fp12, coeffs : Coeffs, p : G1.Affine) : Fp12.Fp12 {
    let (c0raw, c1raw, c2) = coeffs;
    let c0 : Fp2.Fp2 = {
      c0 = Fp.mul(c0raw.c0, p.y);
      c1 = Fp.mul(c0raw.c1, p.y);
    };
    let c1 : Fp2.Fp2 = {
      c0 = Fp.mul(c1raw.c0, p.x);
      c1 = Fp.mul(c1raw.c1, p.x);
    };
    Fp12.mulBy014(f, c2, c1, c0);
  };

  /// Is bit `i` of `n` set?
  func bit(n : Nat, i : Nat) : Bool = (n / (2 ** i)) % 2 == 1;

  /// The Miller loop for a single pair (`pairings.rs:680`).
  ///
  /// It walks the bits of `x >> 1` from the top, skipping until the first set
  /// bit, doubling every step and adding where the bit is set.
  public func millerLoop(p : G1.Affine, q : G2.Affine) : Fp12.Fp12 {
    // The identity in either argument gives the identity in the target. The
    // reference substitutes the generator and masks the result; branching is
    // equivalent here and clearer.
    if (p.infinity or q.infinity) { return Fp12.one };

    var f = Fp12.one;
    var r = G2.fromAffine(q);
    var foundOne = false;

    let shifted = BLS_X / 2;
    var i : Nat = 64;
    while (i > 0) {
      i -= 1;
      let b = bit(shifted, i);
      if (not foundOne) {
        foundOne := b;
      } else {
        let (r1, c1) = doublingStep(r);
        r := r1;
        f := ell(f, c1, p);

        if (b) {
          let (r2, c2) = additionStep(r, q);
          r := r2;
          f := ell(f, c2, p);
        };

        f := Fp12.square(f);
      };
    };

    let (r3, c3) = doublingStep(r);
    r := r3;
    f := ell(f, c3, p);

    if (BLS_X_IS_NEGATIVE) { Fp12.conjugate(f) } else { f };
  };

  /// `fp4_square` from `pairings.rs:52`, a helper for cyclotomic squaring.
  func fp4Square(a : Fp2.Fp2, b : Fp2.Fp2) : (Fp2.Fp2, Fp2.Fp2) {
    let t0 = Fp2.square(a);
    let t1 = Fp2.square(b);
    var t2 = Fp2.mulByNonresidue(t1);
    let c0 = Fp2.add(t2, t0);
    t2 := Fp2.square(Fp2.add(a, b));
    t2 := Fp2.sub(t2, t0);
    let c1 = Fp2.sub(t2, t1);
    (c0, c1);
  };

  /// Squaring specialised to the cyclotomic subgroup — Algorithm 5.5.4 of the
  /// Guide to Pairing-Based Cryptography (`pairings.rs:69`). Substantially
  /// cheaper than a general `Fp12` squaring, and the final exponentiation does
  /// hundreds of them.
  func cyclotomicSquare(f : Fp12.Fp12) : Fp12.Fp12 {
    var z0 = f.c0.c0;
    var z4 = f.c0.c1;
    var z3 = f.c0.c2;
    var z2 = f.c1.c0;
    var z1 = f.c1.c1;
    var z5 = f.c1.c2;

    let (s0, s1) = fp4Square(z0, z1);

    z0 := Fp2.sub(s0, z0);
    z0 := Fp2.add(Fp2.add(z0, z0), s0);
    z1 := Fp2.add(s1, z1);
    z1 := Fp2.add(Fp2.add(z1, z1), s1);

    let (u0, u1) = fp4Square(z2, z3);
    let (v0, v1) = fp4Square(z4, z5);

    z4 := Fp2.sub(u0, z4);
    z4 := Fp2.add(Fp2.add(z4, z4), u0);
    z5 := Fp2.add(u1, z5);
    z5 := Fp2.add(Fp2.add(z5, z5), u1);

    let w = Fp2.mulByNonresidue(v1);
    z2 := Fp2.add(w, z2);
    z2 := Fp2.add(Fp2.add(z2, z2), w);
    z3 := Fp2.sub(v0, z3);
    z3 := Fp2.add(Fp2.add(z3, z3), v0);

    {
      c0 = { c0 = z0; c1 = z4; c2 = z3 };
      c1 = { c0 = z2; c1 = z1; c2 = z5 };
    };
  };

  /// `f^x` in the cyclotomic subgroup, conjugated because `x` is negative
  /// (`pairings.rs:118`).
  func cyclotomicExp(f : Fp12.Fp12) : Fp12.Fp12 {
    var tmp = Fp12.one;
    var foundOne = false;
    var i : Nat = 64;
    while (i > 0) {
      i -= 1;
      let b = bit(BLS_X, i);
      if (foundOne) { tmp := cyclotomicSquare(tmp) } else { foundOne := b };
      if (b) { tmp := Fp12.mul(tmp, f) };
    };
    Fp12.conjugate(tmp);
  };

  /// Raises a Miller-loop result to `(p^12 − 1)/r` (`pairings.rs:49`).
  ///
  /// Returns `null` only if the input is zero, which a Miller loop cannot
  /// produce.
  public func finalExponentiation(mlr : Fp12.Fp12) : ?Fp12.Fp12 {
    var f = mlr;

    // The easy part: f^(p^6 − 1), then f^(p^2 + 1).
    var t0 = f;
    var k = 0;
    while (k < 6) { t0 := Fp12.frobeniusMap(t0); k += 1 };

    switch (Fp12.inverse(f)) {
      case null null;
      case (?inv) {
        var t1 = inv;
        var t2 = Fp12.mul(t0, t1);
        t1 := t2;
        t2 := Fp12.frobeniusMap(Fp12.frobeniusMap(t2));
        t2 := Fp12.mul(t2, t1);
        f := t2;

        // The hard part.
        t1 := Fp12.conjugate(cyclotomicSquare(t2));
        var t3 = cyclotomicExp(t2);
        var t4 = Fp12.mul(t1, t3);
        t1 := cyclotomicExp(t4);
        t4 := Fp12.conjugate(t4);
        f := Fp12.mul(f, t4);
        t4 := cyclotomicSquare(t3);
        t0 := cyclotomicExp(t1);
        t3 := Fp12.mul(t3, t0);
        t3 := Fp12.frobeniusMap(Fp12.frobeniusMap(t3));
        f := Fp12.mul(f, t3);
        t4 := Fp12.mul(t4, cyclotomicExp(t0));
        f := Fp12.mul(f, cyclotomicExp(t4));
        t4 := Fp12.mul(t4, Fp12.conjugate(t2));
        t2 := Fp12.mul(t2, t1);
        t2 := Fp12.frobeniusMap(Fp12.frobeniusMap(Fp12.frobeniusMap(t2)));
        f := Fp12.mul(f, t2);
        t4 := Fp12.frobeniusMap(t4);
        f := Fp12.mul(f, t4);

        ?f;
      };
    };
  };

  /// The pairing itself.
  public func pairing(p : G1.Affine, q : G2.Affine) : Fp12.Fp12 {
    if (p.infinity or q.infinity) { return Fp12.one };
    switch (finalExponentiation(millerLoop(p, q))) {
      case (?r) r;
      case null Fp12.one;
    };
  };

  /// The product of several Miller loops, exponentiated once.
  ///
  /// Verifying a pairing equation this way costs one final exponentiation
  /// instead of two, which is roughly a third of the total — and it is the shape
  /// `decrypt_and_verify` needs.
  public func multiMillerLoop(pairs : [(G1.Affine, G2.Affine)]) : Fp12.Fp12 {
    var acc = Fp12.one;
    for ((p, q) in pairs.vals()) {
      if (not (p.infinity or q.infinity)) {
        acc := Fp12.mul(acc, millerLoop(p, q));
      };
    };
    acc;
  };
}
