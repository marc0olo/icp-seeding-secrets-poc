/// Tests for `G1`, against reference vectors.
///
/// This is where the vectors get sharp. Earlier layers could only be checked
/// against algebra; here the reference gives us `k·G` for eight values of `k`,
/// in both compressed and affine form, so the tests can assert:
///
///   - decompressing the reference's bytes yields the reference's coordinates;
///   - **our scalar multiplication reproduces the reference's multiples** — the
///     one check that exercises `add`, `double` and the whole field tower
///     together against an independent implementation;
///   - compression round-trips back to the reference's exact bytes, flags and
///     sort bit included.
///
/// A group law with a wrong constant, or a sort bit read from the wrong
/// position, cannot survive these.

import { test } "mo:test";
import Fp "../src/Fp";
import G1 "../src/G1";
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
  Array.toBlob(
    Array.tabulate<Nat8>(
      chars.size() / 2,
      func(i) = Nat8.fromNat(hexVal(chars[i * 2]) * 16 + hexVal(chars[i * 2 + 1])),
    )
  );
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

func fp(hex : Text) : Fp.Fp {
  switch (Fp.fromBytes(hexBlob(hex))) {
    case (?v) v;
    case null { assert false; 0 };
  };
};

type Vector = { scalar : Nat; x : Text; y : Text; compressed : Text };

let points : [Vector] = [
  { scalar = 1; x = "17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb"; y = "08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1"; compressed = "97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb" },
  { scalar = 2; x = "0572cbea904d67468808c8eb50a9450c9721db309128012543902d0ac358a62ae28f75bb8f1c7c42c39a8c5529bf0f4e"; y = "166a9d8cabc673a322fda673779d8e3822ba3ecb8670e461f73bb9021d5fd76a4c56d9d4cd16bd1bba86881979749d28"; compressed = "a572cbea904d67468808c8eb50a9450c9721db309128012543902d0ac358a62ae28f75bb8f1c7c42c39a8c5529bf0f4e" },
  { scalar = 3; x = "09ece308f9d1f0131765212deca99697b112d61f9be9a5f1f3780a51335b3ff981747a0b2ca2179b96d2c0c9024e5224"; y = "032b80d3a6f5b09f8a84623389c5f80ca69a0cddabc3097f9d9c27310fd43be6e745256c634af45ca3473b0590ae30d1"; compressed = "89ece308f9d1f0131765212deca99697b112d61f9be9a5f1f3780a51335b3ff981747a0b2ca2179b96d2c0c9024e5224" },
  { scalar = 7; x = "1928f3beb93519eecf0145da903b40a4c97dca00b21f12ac0df3be9116ef2ef27b2ae6bcd4c5bc2d54ef5a70627efcb7"; y = "108dadbaa4b636445639d5ae3089b3c43a8a1d47818edd1839d7383959a41c10fdc66849cfa1b08c5a11ec7e28981a1c"; compressed = "b928f3beb93519eecf0145da903b40a4c97dca00b21f12ac0df3be9116ef2ef27b2ae6bcd4c5bc2d54ef5a70627efcb7" },
  { scalar = 256; x = "0025cdadf2afc5906b2602574a799f4089d90f36d73f94c1cf317cfc1a207c57f232bca6057924dd34cff5bde87f1930"; y = "00d39b79486e185b221147b7d85eaf2238d756842bd84f57c6f37542a047a44d0c06b5de39f22721d14e54addecaea80"; compressed = "8025cdadf2afc5906b2602574a799f4089d90f36d73f94c1cf317cfc1a207c57f232bca6057924dd34cff5bde87f1930" },
  { scalar = 65537; x = "08cab01b6d06a323e18f50141a694e7e71ab18ffdfab536a45ccf0b49a634ee82d00750e9f4c15d806c33a8950664d7f"; y = "0481b238508f2b6e722e0d628a0fc2190216ac8d603c9c02a7773faa21da9e457ae8ed253727c5ce934b8e6060143db1"; compressed = "88cab01b6d06a323e18f50141a694e7e71ab18ffdfab536a45ccf0b49a634ee82d00750e9f4c15d806c33a8950664d7f" },
  { scalar = 4294967295; x = "047f5fcce0b9aa0f2bb3de6847337c9ed1bc2184a125c232721e1c81b0f0fee78506790a78c98abff2dd4b01a0756352"; y = "19c0331470bdba1ff74af7b98fbf1599d0c41464763ed2fd42a96052597d7e42d06aad455b01674ea861756e22aae7d2"; compressed = "a47f5fcce0b9aa0f2bb3de6847337c9ed1bc2184a125c232721e1c81b0f0fee78506790a78c98abff2dd4b01a0756352" },
  { scalar = 1234567890123; x = "0eccf3d0c25d8eaac5d87b5ab54d83f71dc0f253ca4aae2fa8c028fe2f2d9b19e97fd2cdbd03696a3dd9239027b76dfa"; y = "0358aca9ee00f8b9deb5c5f87387ede98f1d5f7862930a72c18321a7d1aa47b6ad92d6c48328747549a4f20c9daedc5b"; compressed = "8eccf3d0c25d8eaac5d87b5ab54d83f71dc0f253ca4aae2fa8c028fe2f2d9b19e97fd2cdbd03696a3dd9239027b76dfa" }
];

let IDENTITY_COMPRESSED = "c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

test(
  "the generator is on the curve",
  func() {
    assert G1.isOnCurve(G1.generator);
    assert G1.isOnCurve(G1.affineIdentity);
  },
);

test(
  "the generator matches the reference's k = 1",
  func() {
    let v = points[0];
    assert v.scalar == 1;
    assert Fp.equal(G1.generator.x, fp(v.x));
    assert Fp.equal(G1.generator.y, fp(v.y));
  },
);

test(
  "decompressing reference bytes yields reference coordinates",
  func() {
    for (v in points.vals()) {
      switch (G1.fromCompressed(hexBlob(v.compressed))) {
        case null assert false;
        case (?a) {
          assert not a.infinity;
          assert Fp.equal(a.x, fp(v.x));
          // The sort bit has to select the right root, not merely a root.
          assert Fp.equal(a.y, fp(v.y));
          assert G1.isOnCurve(a);
        };
      };
    };
  },
);

test(
  "compression round-trips to the reference's exact bytes",
  func() {
    for (v in points.vals()) {
      let a : G1.Affine = { x = fp(v.x); y = fp(v.y); infinity = false };
      assert toHex(G1.toCompressed(a)) == v.compressed;
    };
  },
);

test(
  "the identity encoding matches the reference",
  func() {
    assert toHex(G1.toCompressed(G1.affineIdentity)) == IDENTITY_COMPRESSED;
    switch (G1.fromCompressed(hexBlob(IDENTITY_COMPRESSED))) {
      case (?a) assert a.infinity;
      case null assert false;
    };
  },
);

test(
  "scalar multiplication reproduces the reference's multiples",
  func() {
    // The decisive test at this layer: our group law, driven by our field
    // tower, must land on exactly the points the Rust library computed.
    let g = G1.fromAffine(G1.generator);
    for (v in points.vals()) {
      let computed = G1.toAffine(G1.mul(g, v.scalar));
      assert not computed.infinity;
      assert Fp.equal(computed.x, fp(v.x));
      assert Fp.equal(computed.y, fp(v.y));
    };
  },
);

test(
  "group axioms",
  func() {
    let g = G1.fromAffine(G1.generator);
    let two = G1.double(g);
    let three = G1.add(two, g);

    // doubling agrees with adding to self
    assert G1.equal(two, G1.add(g, g));
    // 3G by two routes
    assert G1.equal(three, G1.mul(g, 3));
    // associativity
    assert G1.equal(G1.add(G1.add(g, two), three), G1.add(g, G1.add(two, three)));
    // commutativity
    assert G1.equal(G1.add(g, two), G1.add(two, g));
    // identity
    assert G1.equal(G1.add(g, G1.identity), g);
    assert G1.equal(G1.mul(g, 0), G1.identity);
    assert G1.equal(G1.mul(g, 1), g);
  },
);

test(
  "a point plus its negation is the identity",
  func() {
    // The branch in `add` where x agrees but y does not. Implementations that
    // conflate it with doubling return a wrong point rather than the identity,
    // and ordinary tests never reach it.
    let g = G1.fromAffine(G1.generator);
    assert G1.isIdentity(G1.add(g, G1.neg(g)));
    for (v in points.vals()) {
      let p = G1.mul(g, v.scalar);
      assert G1.isIdentity(G1.add(p, G1.neg(p)));
      assert G1.isIdentity(G1.sub(p, p));
    };
  },
);

test(
  "malformed compressed encodings are rejected",
  func() {
    // Compression flag clear.
    let good = Blob.toArray(hexBlob(points[1].compressed));
    let noFlag = Array.tabulate<Nat8>(48, func i = if (i == 0) { good[0] & 0x7f } else { good[i] });
    assert G1.fromCompressed(Array.toBlob(noFlag)) == null;

    // Infinity flag set but x non-zero.
    let badInfinity = Array.tabulate<Nat8>(48, func i = if (i == 0) { good[0] | 0x40 } else { good[i] });
    assert G1.fromCompressed(Array.toBlob(badInfinity)) == null;

    // Wrong length.
    assert G1.fromCompressed(hexBlob("00")) == null;

    // An x with no corresponding y: x = 1 gives 1 + 4 = 5, a non-residue here.
    let notOnCurve = Array.tabulate<Nat8>(48, func i = if (i == 0) { 0x80 } else if (i == 47) { 1 } else { 0 });
    assert G1.fromCompressed(Array.toBlob(notOnCurve)) == null;
  },
);
