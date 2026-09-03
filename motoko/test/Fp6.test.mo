/// Tests for `Fp6`.
///
/// There are no reference vectors at this layer — `Fp6` is not part of any
/// serialized value, so nothing in the protocol pins it down directly. What
/// constrains it instead is algebra: an implementation with a wrong Karatsuba
/// term or a misplaced non-residue fails associativity or distributivity on
/// almost any input, and fails `inverse` on all of them.
///
/// The Frobenius coefficients get a stronger check. They are re-derived here by
/// exponentiation rather than taken on faith, and `frobeniusMap` is checked
/// against the definition it implements — `x^p` — which is the property that
/// actually matters and the one a transcription error breaks.

import { test } "mo:test";
import Fp "../src/Fp";
import Fp2 "../src/Fp2";
import Fp6 "../src/Fp6";

/// A few elements with no special structure, so a bug cannot hide in a zero.
func sample(i : Nat) : Fp6.Fp6 = {
  c0 = { c0 = 7 * i + 1; c1 = 11 * i + 2 };
  c1 = { c0 = 13 * i + 3; c1 = 17 * i + 5 };
  c2 = { c0 = 19 * i + 7; c1 = 23 * i + 11 };
};

let samples : [Fp6.Fp6] = [sample(1), sample(2), sample(97), sample(1000003)];

test(
  "v^3 = u + 1",
  func() {
    // The defining relation of the extension. Everything else depends on it.
    let v : Fp6.Fp6 = { c0 = Fp2.zero; c1 = Fp2.one; c2 = Fp2.zero };
    let vCubed = Fp6.mul(Fp6.square(v), v);
    let uPlusOne = Fp6.fromFp2({ c0 = 1; c1 = 1 });
    assert Fp6.equal(vCubed, uPlusOne);
  },
);

test(
  "ring axioms",
  func() {
    for (a in samples.vals()) {
      for (b in samples.vals()) {
        assert Fp6.equal(Fp6.mul(a, b), Fp6.mul(b, a));
        assert Fp6.equal(Fp6.add(a, b), Fp6.add(b, a));
        assert Fp6.equal(Fp6.mul(Fp6.mul(a, b), a), Fp6.mul(a, Fp6.mul(b, a)));
        assert Fp6.equal(
          Fp6.mul(a, Fp6.add(b, Fp6.one)),
          Fp6.add(Fp6.mul(a, b), a),
        );
        assert Fp6.equal(Fp6.sub(Fp6.add(a, b), b), a);
      };
      assert Fp6.equal(Fp6.mul(a, Fp6.one), a);
      assert Fp6.equal(Fp6.mul(a, Fp6.zero), Fp6.zero);
      assert Fp6.equal(Fp6.add(a, Fp6.neg(a)), Fp6.zero);
      assert Fp6.equal(Fp6.double(a), Fp6.add(a, a));
    };
  },
);

test(
  "squaring agrees with multiplication",
  func() {
    // square() is a separate formula, not a call to mul.
    for (a in samples.vals()) {
      assert Fp6.equal(Fp6.square(a), Fp6.mul(a, a));
    };
  },
);

test(
  "inversion",
  func() {
    assert Fp6.inverse(Fp6.zero) == null;
    for (a in samples.vals()) {
      switch (Fp6.inverse(a)) {
        case (?inv) assert Fp6.equal(Fp6.mul(a, inv), Fp6.one);
        case null assert false;
      };
    };
  },
);

test(
  "multiplication by the non-residue matches multiplying by v",
  func() {
    let v : Fp6.Fp6 = { c0 = Fp2.zero; c1 = Fp2.one; c2 = Fp2.zero };
    for (a in samples.vals()) {
      assert Fp6.equal(Fp6.mulByNonresidue(a), Fp6.mul(a, v));
    };
  },
);

test(
  "the sparse multiplications agree with the general one",
  func() {
    // mulBy01 and mulBy1 are the Miller loop's hot paths, specialised for the
    // shape line evaluations produce. They must agree with mul on that shape.
    for (a in samples.vals()) {
      let b0 : Fp2.Fp2 = { c0 = 5; c1 = 9 };
      let b1 : Fp2.Fp2 = { c0 = 12; c1 = 4 };

      let sparse01 : Fp6.Fp6 = { c0 = b0; c1 = b1; c2 = Fp2.zero };
      assert Fp6.equal(Fp6.mulBy01(a, b0, b1), Fp6.mul(a, sparse01));

      let sparse1 : Fp6.Fp6 = { c0 = Fp2.zero; c1 = b1; c2 = Fp2.zero };
      assert Fp6.equal(Fp6.mulBy1(a, b1), Fp6.mul(a, sparse1));
    };
  },
);

test(
  "the Frobenius coefficients are what they claim to be",
  func() {
    // Re-derived rather than trusted: the reference stores these in Montgomery
    // form, so they were computed independently and this is the check.
    let xi : Fp2.Fp2 = { c0 = 1; c1 = 1 };
    assert Fp2.equal(Fp6.FROBENIUS_C1, Fp2.pow(xi, (Fp.P - 1 : Nat) / 3));
    assert Fp2.equal(Fp6.FROBENIUS_C2, Fp2.pow(xi, (2 * Fp.P - 2 : Nat) / 3));
  },
);

test(
  "frobeniusMap computes x^p",
  func() {
    // The definition, checked directly. A transcription error in either
    // coefficient shows up here on every input.
    for (a in samples.vals()) {
      assert Fp6.equal(Fp6.frobeniusMap(a), Fp6.pow(a, Fp.P));
    };
  },
);

test(
  "frobenius has order 6",
  func() {
    // Gal(Fp6/Fp) is cyclic of order 6, so six applications is the identity and
    // fewer is not. Asserting the "not" half matters: a frobeniusMap that
    // returned its input unchanged would satisfy the identity check alone.
    for (a in samples.vals()) {
      var x = a;
      for (i in [0, 1, 2, 3, 4].vals()) {
        x := Fp6.frobeniusMap(x);
        assert not Fp6.equal(x, a);
      };
      assert Fp6.equal(Fp6.frobeniusMap(x), a);
    };
  },
);
