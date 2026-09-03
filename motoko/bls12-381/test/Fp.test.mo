/// Tests for `Fp`, asserted against vectors generated from the Rust reference.
///
/// # Why not a literal port of the reference's own `fp` tests
///
/// Those are written against its internal Montgomery `[u64; 6]` representation
/// (`Fp([0xdc90_6d9b_e3f9_5dc8, ...])`), which this port deliberately does not
/// share, so porting them literally would assert nothing about agreement.
///
/// What matters is that the two implementations agree on *values*. The vectors
/// below are real curve points emitted by `cargo run -p vectorgen`, and the
/// checks are the properties that must hold of them:
///
///   - every coordinate decodes as a canonical field element;
///   - every point satisfies `y^2 = x^3 + 4`, which exercises the modulus,
///     `add`, `mul` and `square` together against data this code had no hand in
///     producing;
///   - serialization round-trips byte for byte.
///
/// The reference's algebraic identity tests port meaningfully, and are here too.

import { test } "mo:test";
import Fp "../src/Fp";
import Array "mo:core/Array";
import Nat8 "mo:core/Nat8";
import Char "mo:core/Char";
import Nat32 "mo:core/Nat32";
import Text "mo:core/Text";
import Blob "mo:core/Blob";

func hexVal(c : Char) : Nat {
  let n = Nat32.toNat(Char.toNat32(c));
  if (n >= 48 and n <= 57) { n - 48 } else if (n >= 97 and n <= 102) {
    n - 87;
  } else if (n >= 65 and n <= 70) { n - 55 } else { 16 };
};

func hexBlob(hex : Text) : Blob {
  let chars = Array.fromIter<Char>(Text.toIter(hex));
  assert chars.size() % 2 == 0;
  let bytes = Array.tabulate<Nat8>(
    chars.size() / 2,
    func(i) = Nat8.fromNat(hexVal(chars[i * 2]) * 16 + hexVal(chars[i * 2 + 1])),
  );
  Blob.fromArray(bytes);
};

/// Parses hex without the canonical-range check, so the modulus itself can be
/// read — it is by definition not less than itself.
func hexToNat(hex : Text) : Nat {
  var acc : Nat = 0;
  for (byte in Blob.toArray(hexBlob(hex)).vals()) {
    acc := acc * 256 + Nat8.toNat(byte);
  };
  acc;
};

func hexToFp(hex : Text) : Fp.Fp {
  switch (Fp.fromBytes(hexBlob(hex))) {
    case (?v) v;
    case null { assert false; 0 };
  };
};

func toHex(b : Blob) : Text {
  let digits = Array.fromIter<Char>(Text.toIter("0123456789abcdef"));
  var out = "";
  for (byte in Blob.toArray(b).vals()) {
    let n = Nat8.toNat(byte);
    out #= Char.toText(digits[n / 16]) # Char.toText(digits[n % 16]);
  };
  out;
};

type Vector = { scalar : Nat; x : Text; y : Text };

/// Real G1 points from the reference; see `test/vectors.json`.
let points : [Vector] = [
  { scalar = 1; x = "17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb"; y = "08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1" },
  { scalar = 2; x = "0572cbea904d67468808c8eb50a9450c9721db309128012543902d0ac358a62ae28f75bb8f1c7c42c39a8c5529bf0f4e"; y = "166a9d8cabc673a322fda673779d8e3822ba3ecb8670e461f73bb9021d5fd76a4c56d9d4cd16bd1bba86881979749d28" },
  { scalar = 3; x = "09ece308f9d1f0131765212deca99697b112d61f9be9a5f1f3780a51335b3ff981747a0b2ca2179b96d2c0c9024e5224"; y = "032b80d3a6f5b09f8a84623389c5f80ca69a0cddabc3097f9d9c27310fd43be6e745256c634af45ca3473b0590ae30d1" },
  { scalar = 7; x = "1928f3beb93519eecf0145da903b40a4c97dca00b21f12ac0df3be9116ef2ef27b2ae6bcd4c5bc2d54ef5a70627efcb7"; y = "108dadbaa4b636445639d5ae3089b3c43a8a1d47818edd1839d7383959a41c10fdc66849cfa1b08c5a11ec7e28981a1c" },
  { scalar = 256; x = "0025cdadf2afc5906b2602574a799f4089d90f36d73f94c1cf317cfc1a207c57f232bca6057924dd34cff5bde87f1930"; y = "00d39b79486e185b221147b7d85eaf2238d756842bd84f57c6f37542a047a44d0c06b5de39f22721d14e54addecaea80" },
  { scalar = 65537; x = "08cab01b6d06a323e18f50141a694e7e71ab18ffdfab536a45ccf0b49a634ee82d00750e9f4c15d806c33a8950664d7f"; y = "0481b238508f2b6e722e0d628a0fc2190216ac8d603c9c02a7773faa21da9e457ae8ed253727c5ce934b8e6060143db1" },
  { scalar = 4294967295; x = "047f5fcce0b9aa0f2bb3de6847337c9ed1bc2184a125c232721e1c81b0f0fee78506790a78c98abff2dd4b01a0756352"; y = "19c0331470bdba1ff74af7b98fbf1599d0c41464763ed2fd42a96052597d7e42d06aad455b01674ea861756e22aae7d2" },
  { scalar = 1234567890123; x = "0eccf3d0c25d8eaac5d87b5ab54d83f71dc0f253ca4aae2fa8c028fe2f2d9b19e97fd2cdbd03696a3dd9239027b76dfa"; y = "0358aca9ee00f8b9deb5c5f87387ede98f1d5f7862930a72c18321a7d1aa47b6ad92d6c48328747549a4f20c9daedc5b" }
];

/// The modulus, from ic_bls12_381 `fp.rs:70`, reassembled from its
/// little-endian `[u64; 6]`.
let MODULUS_HEX = "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab";

test(
  "the modulus matches the reference",
  func() {
    assert Fp.P == hexToNat(MODULUS_HEX);
  },
);

test(
  "reference coordinates decode as canonical field elements",
  func() {
    for (v in points.vals()) {
      assert Fp.fromBytes(hexBlob(v.x)) != null;
      assert Fp.fromBytes(hexBlob(v.y)) != null;
    };
  },
);

test(
  "every reference point satisfies y^2 = x^3 + 4",
  func() {
    for (v in points.vals()) {
      let x = hexToFp(v.x);
      let y = hexToFp(v.y);
      assert Fp.equal(Fp.square(y), Fp.add(Fp.mul(Fp.square(x), x), 4));
    };
  },
);

test(
  "serialization round-trips byte for byte",
  func() {
    for (v in points.vals()) {
      assert toHex(Fp.toBytes(hexToFp(v.x))) == v.x;
      assert toHex(Fp.toBytes(hexToFp(v.y))) == v.y;
    };
  },
);

test(
  "non-canonical encodings are rejected",
  func() {
    // p and p+1 both fit in 48 bytes and must both be refused, or one element
    // would have two encodings and point compression would break.
    assert Fp.fromBytes(Fp.toBytes(0)) == ?0;
    assert Fp.fromBytes(hexBlob(MODULUS_HEX)) == null;
    assert Fp.fromBytes(hexBlob("1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaac")) == null;
    assert Fp.fromBytes(hexBlob("00")) == null;
  },
);

test(
  "addition and subtraction are inverse",
  func() {
    for (v in points.vals()) {
      let a = hexToFp(v.x);
      let b = hexToFp(v.y);
      assert Fp.equal(Fp.sub(Fp.add(a, b), b), a);
      assert Fp.equal(Fp.add(Fp.sub(a, b), b), a);
    };
  },
);

test(
  "negation",
  func() {
    assert Fp.equal(Fp.neg(0), 0);
    for (v in points.vals()) {
      let a = hexToFp(v.x);
      assert Fp.equal(Fp.add(a, Fp.neg(a)), 0);
      assert Fp.equal(Fp.neg(Fp.neg(a)), a);
    };
  },
);

test(
  "squaring and doubling agree with the general operations",
  func() {
    for (v in points.vals()) {
      let a = hexToFp(v.x);
      assert Fp.equal(Fp.square(a), Fp.mul(a, a));
      assert Fp.equal(Fp.double(a), Fp.add(a, a));
    };
  },
);

test(
  "inversion",
  func() {
    assert Fp.inverse(0) == null;
    for (v in points.vals()) {
      let a = hexToFp(v.x);
      switch (Fp.inverse(a)) {
        case (?inv) assert Fp.equal(Fp.mul(a, inv), 1);
        case null assert false;
      };
    };
  },
);

test(
  "square roots",
  func() {
    for (v in points.vals()) {
      // y^2 is a residue by construction, and its root is y or -y.
      let y = hexToFp(v.y);
      switch (Fp.sqrt(Fp.square(y))) {
        case (?r) assert Fp.equal(r, y) or Fp.equal(r, Fp.neg(y));
        case null assert false;
      };
    };
  },
);

test(
  "lexicographically largest picks exactly one of a root pair",
  func() {
    // Point compression stores this bit, so exactly one of y and -y must set
    // it — otherwise decompression cannot recover the right root.
    for (v in points.vals()) {
      let y = hexToFp(v.y);
      if (not Fp.isZero(y)) {
        assert Fp.lexicographicallyLargest(y) != Fp.lexicographicallyLargest(Fp.neg(y));
      };
    };
  },
);
