/// Tests for the optimal ate pairing.
///
/// Bilinearity is the whole point of a pairing and it is also the property that
/// no plausible bug survives: `e(aP, bQ) = e(P, Q)^(ab)` ties the Miller loop,
/// the final exponentiation, both group laws and the entire field tower to a
/// single arithmetic identity. An implementation that is wrong anywhere gives a
/// value that fails it.
///
/// Non-degeneracy matters too, and separately: a `pairing` that returned `one`
/// for everything would satisfy bilinearity perfectly.

import { test } "mo:test";
import Fp12 "../src/Fp12";
import G1 "../src/G1";
import G2 "../src/G2";
import Pairing "../src/Pairing";

let g1 = G1.generator;
let g2 = G2.generator;

func g1Mul(k : Nat) : G1.Affine = G1.toAffine(G1.mul(G1.fromAffine(g1), k));
func g2Mul(k : Nat) : G2.Affine = G2.toAffine(G2.mul(G2.fromAffine(g2), k));

test(
  "the pairing is non-degenerate",
  func() {
    // e(G, H) must not be 1, or everything below is vacuous.
    let e = Pairing.pairing(g1, g2);
    assert not Fp12.equal(e, Fp12.one);
    assert not Fp12.isZero(e);
  },
);

test(
  "the identity in either argument gives one",
  func() {
    assert Fp12.equal(Pairing.pairing(G1.affineIdentity, g2), Fp12.one);
    assert Fp12.equal(Pairing.pairing(g1, G2.affineIdentity), Fp12.one);
  },
);

test(
  "bilinear in the first argument",
  func() {
    // e(aP, Q) = e(P, Q)^a
    let base = Pairing.pairing(g1, g2);
    for (a in [2, 3, 7].vals()) {
      assert Fp12.equal(Pairing.pairing(g1Mul(a), g2), Fp12.pow(base, a));
    };
  },
);

test(
  "bilinear in the second argument",
  func() {
    let base = Pairing.pairing(g1, g2);
    for (b in [2, 3, 7].vals()) {
      assert Fp12.equal(Pairing.pairing(g1, g2Mul(b)), Fp12.pow(base, b));
    };
  },
);

test(
  "e(aP, bQ) = e(P, Q)^(ab)",
  func() {
    // The full statement, and the one that pins down every layer at once.
    let base = Pairing.pairing(g1, g2);
    for ((a, b) in [(2, 3), (5, 7), (11, 13)].vals()) {
      assert Fp12.equal(Pairing.pairing(g1Mul(a), g2Mul(b)), Fp12.pow(base, a * b));
    };
  },
);

test(
  "e(aP, Q) = e(P, aQ)",
  func() {
    // Moving the scalar between arguments must not change the value — a
    // symmetry that catches a Miller loop wired to the wrong side.
    for (a in [2, 5, 9].vals()) {
      assert Fp12.equal(
        Pairing.pairing(g1Mul(a), g2),
        Pairing.pairing(g1, g2Mul(a)),
      );
    };
  },
);

test(
  "the pairing of a negation is the inverse",
  func() {
    let base = Pairing.pairing(g1, g2);
    let negated = Pairing.pairing(G1.negAffine(g1), g2);
    assert Fp12.equal(Fp12.mul(base, negated), Fp12.one);
  },
);

test(
  "a multi-Miller loop verifies a pairing equation",
  func() {
    // e(P, Q) · e(-P, Q) = 1, checked through the multi-loop with a single
    // final exponentiation — the shape decrypt_and_verify needs.
    let acc = Pairing.multiMillerLoop([
      (g1, g2),
      (G1.negAffine(g1), g2),
    ]);
    switch (Pairing.finalExponentiation(acc)) {
      case (?r) assert Fp12.equal(r, Fp12.one);
      case null assert false;
    };
  },
);
