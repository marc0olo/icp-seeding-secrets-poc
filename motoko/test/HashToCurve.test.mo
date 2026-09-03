/// Tests for `hashToCurve`, against vectors from the Rust reference.
///
/// This closes the last functional gap with the Rust canister. Without it a
/// Motoko canister could decrypt a sealed secret but could not check that the
/// vetKey the subnet returned is a genuine BLS signature — it would have to take
/// the subnet's word for it.
///
/// The vectors use the domain separator `ic-vetkeys` uses for exactly that
/// check, so agreeing with them is agreeing on the operation that matters.

import { test } "mo:test";
import G1 "../src/G1";
import HashToCurve "../src/HashToCurve";
import Array "mo:core/Array";
import Nat8 "mo:core/Nat8";
import Char "mo:core/Char";
import Nat32 "mo:core/Nat32";
import Text "mo:core/Text";
import Blob "mo:core/Blob";

func bytes(t : Text) : [Nat8] = Blob.toArray(Text.encodeUtf8(t));

func toHex(b : Blob) : Text {
  let digits = Array.fromIter<Char>(Text.toIter("0123456789abcdef"));
  var out = "";
  for (byte in Blob.toArray(b).vals()) {
    let n = Nat8.toNat(byte);
    out #= Char.toText(digits[n / 16]) # Char.toText(digits[n % 16]);
  };
  out;
};

let DST = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_AUG_";

type Vector = { msg : Text; compressed : Text };

let vectors : [Vector] = [
  { msg = ""; compressed = "89e1d7cb9e5ec9d8a38a51bc0e32a0b45d182d48127aeec6ea5b430fbddc51808c390c2e923eb7dbfd59c221c8d4f008" },
  { msg = "abc"; compressed = "a4b925a7f78b97ad6a8203e9b1e319f0fcde5bea79e58fac5ec79a2867d11bd97ded3fed5e346bc0afd8e23f0069055d" },
  { msg = "a message long enough to need more than one expansion block here"; compressed = "931201b0362377713464d3e09493bf488d7f2711399e3a5898ba025d83f7ac6ccdcbc51928eb9e7885639d53325eb57d" }
];

test(
  "hashToCurve matches the reference",
  func() {
    for (v in vectors.vals()) {
      let p = HashToCurve.hashToCurveText(bytes(v.msg), DST);
      assert toHex(G1.toCompressed(p)) == v.compressed;
    };
  },
);

test(
  "results are on the curve and not the identity",
  func() {
    for (v in vectors.vals()) {
      let p = HashToCurve.hashToCurveText(bytes(v.msg), DST);
      assert G1.isOnCurve(p);
      assert not p.infinity;
    };
  },
);

test(
  "distinct messages give distinct points",
  func() {
    let a = HashToCurve.hashToCurveText(bytes("one"), DST);
    let b = HashToCurve.hashToCurveText(bytes("two"), DST);
    assert not G1.equalAffine(a, b);
  },
);

test(
  "the domain separator changes the result",
  func() {
    // Two suites must not collide, which is the entire purpose of a DST.
    let a = HashToCurve.hashToCurveText(bytes("msg"), DST);
    let b = HashToCurve.hashToCurveText(bytes("msg"), "SOME_OTHER_DST");
    assert not G1.equalAffine(a, b);
  },
);
