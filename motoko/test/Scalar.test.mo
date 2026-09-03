/// Tests for `Scalar`, against reference vectors.
///
/// `hashToScalar` is the one that matters: the IBE scheme derives its
/// per-message scalar this way, so a mismatch means nothing decrypts and the
/// failure gives no hint as to why. These vectors come from the same primitive
/// `ic-vetkeys` calls.

import { test } "mo:test";
import Scalar "../src/Scalar";
import Array "mo:core/Array";
import Nat8 "mo:core/Nat8";
import Char "mo:core/Char";
import Nat32 "mo:core/Nat32";
import Text "mo:core/Text";
import Blob "mo:core/Blob";

func bytes(t : Text) : [Nat8] = Blob.toArray(Text.encodeUtf8(t));

func toHex(b : [Nat8]) : Text {
  let digits = Array.fromIter<Char>(Text.toIter("0123456789abcdef"));
  var out = "";
  for (byte in b.vals()) {
    let n = Nat8.toNat(byte);
    out #= Char.toText(digits[n / 16]) # Char.toText(digits[n % 16]);
  };
  out;
};

type Vector = { input : Text; dst : Text; scalar : Text };

let vectors : [Vector] = [
  { input = ""; dst = "ic-vetkd-bls12-381-ibe-hash-to-mask"; scalar = "6d25b5e3885b94a7bd804d45124b4ab7fcedb1a1934a92616df347000f88d1f2" },
  { input = "abc"; dst = "ic-vetkd-bls12-381-ibe-hash-to-mask"; scalar = "046bdda073b85f06ca894cee8f21433550b68f61c08d5f34ddefbad67e683b4e" },
  { input = "a longer input than one hash block, to exercise the expansion loop properly"; dst = "ic-vetkd-bls12-381-ibe-hash-to-mask"; scalar = "0b93ac92dfe8e08f456e2adff61d68633f4385d444bbe486f6a5609676612226" }
];

test(
  "the group order is the published value",
  func() {
    // r = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    assert Scalar.R == 52435875175126190479447740508185965837690552500527637822603658699938581184513;
    // and it is smaller than the base field, which is the point of having both
    assert Scalar.R < 4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787;
  },
);

test(
  "hashToScalar matches the reference",
  func() {
    for (v in vectors.vals()) {
      let s = Scalar.hashToScalar(bytes(v.input), v.dst);
      assert toHex(Scalar.toBytes(s)) == v.scalar;
    };
  },
);

test(
  "serialization round-trips",
  func() {
    for (v in vectors.vals()) {
      let s = Scalar.hashToScalar(bytes(v.input), v.dst);
      assert Scalar.fromBytes(Scalar.toBytes(s)) == ?s;
    };
    assert Scalar.fromBytes(Scalar.toBytes(0)) == ?0;
  },
);

test(
  "out-of-range encodings are rejected",
  func() {
    // r itself must not parse, or one scalar would have two encodings.
    let rBytes = Array.tabulate<Nat8>(
      32,
      func i {
        let shift = (32 - 1 - i : Nat) * 8;
        Nat8.fromNat((Scalar.R / (2 ** shift)) % 256);
      },
    );
    assert Scalar.fromBytes(rBytes) == null;
    assert Scalar.fromBytes([]) == null;
  },
);
