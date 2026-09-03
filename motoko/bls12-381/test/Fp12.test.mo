/// Tests for `Fp12`, the pairing's target group.
///
/// As with `Fp6` there are no serialized reference vectors at this layer, so the
/// constraints are algebraic — plus two that are specific to how the pairing
/// uses this field, and that a plausible-looking implementation can fail:
///
///   - **conjugation equals inversion in the cyclotomic subgroup.** The final
///     exponentiation replaces inversions with conjugations on that basis. If it
///     is not true here, the pairing produces wrong answers rather than errors.
///   - **`mulBy014` agrees with the general multiplication.** It is the hottest
///     operation in the Miller loop and the easiest to get subtly wrong, because
///     it is only correct for one shape of input.

import { test } "mo:test";
import Fp "../src/Fp";
import Fp2 "../src/Fp2";
import Fp6 "../src/Fp6";
import Fp12 "../src/Fp12";

func fp2(a : Nat, b : Nat) : Fp2.Fp2 = { c0 = a; c1 = b };

func sample(i : Nat) : Fp12.Fp12 = {
  c0 = {
    c0 = fp2(7 * i + 1, 11 * i + 2);
    c1 = fp2(13 * i + 3, 17 * i + 5);
    c2 = fp2(19 * i + 7, 23 * i + 11);
  };
  c1 = {
    c0 = fp2(29 * i + 13, 31 * i + 17);
    c1 = fp2(37 * i + 19, 41 * i + 23);
    c2 = fp2(43 * i + 29, 47 * i + 31);
  };
};

let samples : [Fp12.Fp12] = [sample(1), sample(2), sample(97), sample(1000003)];

test(
  "w^2 = v",
  func() {
    // The defining relation: w squared is v, the generator of Fp6 over Fp2.
    let w : Fp12.Fp12 = { c0 = Fp6.zero; c1 = Fp6.one };
    let v : Fp12.Fp12 = {
      c0 = { c0 = Fp2.zero; c1 = Fp2.one; c2 = Fp2.zero };
      c1 = Fp6.zero;
    };
    assert Fp12.equal(Fp12.square(w), v);
  },
);

test(
  "ring axioms",
  func() {
    for (a in samples.vals()) {
      for (b in samples.vals()) {
        assert Fp12.equal(Fp12.mul(a, b), Fp12.mul(b, a));
        assert Fp12.equal(Fp12.mul(Fp12.mul(a, b), a), Fp12.mul(a, Fp12.mul(b, a)));
        assert Fp12.equal(
          Fp12.mul(a, Fp12.add(b, Fp12.one)),
          Fp12.add(Fp12.mul(a, b), a),
        );
        assert Fp12.equal(Fp12.sub(Fp12.add(a, b), b), a);
      };
      assert Fp12.equal(Fp12.mul(a, Fp12.one), a);
      assert Fp12.equal(Fp12.add(a, Fp12.neg(a)), Fp12.zero);
    };
  },
);

test(
  "squaring agrees with multiplication",
  func() {
    for (a in samples.vals()) {
      assert Fp12.equal(Fp12.square(a), Fp12.mul(a, a));
    };
  },
);

test(
  "inversion",
  func() {
    assert Fp12.inverse(Fp12.zero) == null;
    for (a in samples.vals()) {
      switch (Fp12.inverse(a)) {
        case (?inv) assert Fp12.equal(Fp12.mul(a, inv), Fp12.one);
        case null assert false;
      };
    };
  },
);

test(
  "the Frobenius coefficient is what it claims to be",
  func() {
    let xi = fp2(1, 1);
    assert Fp2.equal(Fp12.FROBENIUS_C1, Fp2.pow(xi, (Fp.P - 1 : Nat) / 6));
  },
);

test(
  "frobeniusMap computes x^p",
  func() {
    for (a in samples.vals()) {
      assert Fp12.equal(Fp12.frobeniusMap(a), Fp12.pow(a, Fp.P));
    };
  },
);

test(
  "frobenius has order 12",
  func() {
    for (a in samples.vals()) {
      var x = a;
      var i = 0;
      while (i < 11) {
        x := Fp12.frobeniusMap(x);
        assert not Fp12.equal(x, a);
        i += 1;
      };
      assert Fp12.equal(Fp12.frobeniusMap(x), a);
    };
  },
);

test(
  "mulBy014 agrees with the general multiplication",
  func() {
    // The Miller loop's hot path. It is only correct for line-evaluation shape,
    // so the comparison has to construct exactly that shape.
    for (a in samples.vals()) {
      let c0 = fp2(3, 5);
      let c1 = fp2(7, 11);
      let c4 = fp2(13, 17);
      let sparse : Fp12.Fp12 = {
        c0 = { c0; c1; c2 = Fp2.zero };
        c1 = { c0 = Fp2.zero; c1 = c4; c2 = Fp2.zero };
      };
      assert Fp12.equal(Fp12.mulBy014(a, c0, c1, c4), Fp12.mul(a, sparse));
    };
  },
);

test(
  "conjugation is inversion in the cyclotomic subgroup",
  func() {
    // The property the final exponentiation is built on. An element is pushed
    // into the cyclotomic subgroup by raising to (p^6 - 1)(p^2 + 1); there,
    // x^(p^6) = x^-1, and conjugation computes exactly that.
    for (a in samples.vals()) {
      switch (Fp12.inverse(a)) {
        case null assert false;
        case (?aInv) {
          // easy part of the final exponentiation: a^(p^6 - 1)
          var x = Fp12.mul(Fp12.conjugate(a), aInv);
          // ... then a^(p^2 + 1)
          x := Fp12.mul(Fp12.frobeniusMap(Fp12.frobeniusMap(x)), x);

          switch (Fp12.inverse(x)) {
            case null assert false;
            case (?xInv) assert Fp12.equal(Fp12.conjugate(x), xInv);
          };
        };
      };
    };
  },
);
