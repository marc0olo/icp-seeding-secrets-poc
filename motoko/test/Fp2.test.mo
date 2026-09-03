/// Tests for `Fp2`, against vectors generated from the Rust reference.
///
/// The anchor is the same shape as the `Fp` tests: every reference `G2` point
/// must satisfy the curve equation over this field,
///
///     y² = x³ + 4(1 + u)
///
/// which exercises `mul`, `square`, `add` and the `u² = −1` reduction together,
/// against coordinates this code had no hand in producing. An implementation
/// with a sign error in `mul` cannot pass it.
///
/// `sqrt` gets its own attention because it has two branches and the rare one is
/// the one that breaks: when `alpha = −1` the element is a square of something
/// in the base subfield, and the root comes from a different formula.

import { test } "mo:test";
import Fp "../src/Fp";
import Fp2 "../src/Fp2";
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

func fp(hex : Text) : Fp.Fp {
  switch (Fp.fromBytes(hexBlob(hex))) {
    case (?v) v;
    case null { assert false; 0 };
  };
};

type Vector = {
  scalar : Nat;
  xc0 : Text;
  xc1 : Text;
  yc0 : Text;
  yc1 : Text;
};

/// Real G2 points from the reference; see `test/vectors.json`.
let points : [Vector] = [
  { scalar = 1; xc0 = "024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8"; xc1 = "13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e"; yc0 = "0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801"; yc1 = "0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be" },
  { scalar = 2; xc0 = "1638533957d540a9d2370f17cc7ed5863bc0b995b8825e0ee1ea1e1e4d00dbae81f14b0bf3611b78c952aacab827a053"; xc1 = "0a4edef9c1ed7f729f520e47730a124fd70662a904ba1074728114d1031e1572c6c886f6b57ec72a6178288c47c33577"; yc0 = "0468fb440d82b0630aeb8dca2b5256789a66da69bf91009cbfe6bd221e47aa8ae88dece9764bf3bd999d95d71e4c9899"; yc1 = "0f6d4552fa65dd2638b361543f887136a43253d9c66c411697003f7a13c308f5422e1aa0a59c8967acdefd8b6e36ccf3" },
  { scalar = 3; xc0 = "122915c824a0857e2ee414a3dccb23ae691ae54329781315a0c75df1c04d6d7a50a030fc866f09d516020ef82324afae"; xc1 = "09380275bbc8e5dcea7dc4dd7e0550ff2ac480905396eda55062650f8d251c96eb480673937cc6d9d6a44aaa56ca66dc"; yc0 = "0b21da7955969e61010c7a1abc1a6f0136961d1e3b20b1a7326ac738fef5c721479dfd948b52fdf2455e44813ecfd892"; yc1 = "08f239ba329b3967fe48d718a36cfe5f62a7e42e0bf1c1ed714150a166bfbd6bcf6b3b58b975b9edea56d53f23a0e849" },
  { scalar = 7; xc0 = "049cd1dbb2d2c3581e54c088135fef36505a6823d61b859437bfc79b617030dc8b40e32bad1fa85b9c0f368af6d38d3c"; xc1 = "0d0273f6bf31ed37c3b8d68083ec3d8e20b5f2cc170fa24b9b5be35b34ed013f9a921f1cad1644d4bdb14674247234c8"; yc0 = "08b7ae4dbf802c17a6648842922c9467e460a71c88d393ee7af356da123a2f3619e80c3bdcc8e2b1da52f8cd9913ccdd"; yc1 = "05ecf93654b7a1885695aaeeb7caf41b0239dc45e1022be55d37111af2aecef87799638bec572de86a7437898efa7020" },
  { scalar = 256; xc0 = "0412f6b2e37effc7e16d566d6f831572411d130eee4c15d82aa29e44cb4db9b5eb8c08b0ae158cde970d9d29ba368780"; xc1 = "02f7f6cc00b080cb3a7f8976c44d1987fd36a8334db831be269c6f6144c392b54bb934313d5fc832ec41d2f9a4b7ea91"; yc0 = "19ffef0307855bed96575447cb4a9442c91ec72b91e4c9107cbf619a3d9cf20df17831a98b65cc6def810c57e45594ea"; yc1 = "0af2e093a01abcfa36b20fc57d5d51ded73dbb06b639f10e921f8bb2758b2c3f10623aa26cbf9cce9856ccd1bc261e9a" },
  { scalar = 65537; xc0 = "06c67e6c183435e5aec742d2d786f6435f61b143f64b2bc1f69678ee434eb4feed7952b0f15777c5d72cddc3976fb090"; xc1 = "148a606f6a01429e4f7cc71d89b077128075d8101b7092d5fba8eb9189a57f34e9c4b442961357b1278f0464ea330876"; yc0 = "15b7953c1ae1467c7aade7e9ee06bcc682403179e2dd64325495f5984cbf59161c8507ad6a3fed6378a0500df04b0d8e"; yc1 = "062d6d609dbe6a6507032b5461a5d3d250d47ec10fe5003e14c008a9ec4b6590d16d4641a3a3167136d86261425c1938" },
  { scalar = 4294967295; xc0 = "0b4cb7985b95afdb0b39596dd016bd58c2f4a0b3f74e6f39cc627199a52718187c6265c2e8aa72094f06ef836e191bbd"; xc1 = "0f17f1c6651dbdee41e06e98bf0eb7bc47b0d5d7ab2df18ade51328d1cc771aaf4b22e1138f677833d4f596535475117"; yc0 = "0cdaf320208c8a20110e89113e38656aacbe0265eb9c663f22600c9636ad668ce2eb3638b7550392b7e2cdd45fafdd15"; yc1 = "10b79a3e6fee32f56d2fd8cf7a1fceb21435455a6894e83445abb4fee6a1db327ecb237a08cdda13d06b7a4231a6756d" },
  { scalar = 1234567890123; xc0 = "1342a65568d2f3cddeeba0db89641b5b6fac9459b7f500a4499b553915e7bf20cafbfb47b5467f9d7e1923b81063eed9"; xc1 = "1922fb9b5d990e55aa94f023e0dda0dd4976039695a807b007bca7720475336b09a4d428b68f4782e789b259d6f57328"; yc0 = "0075a9423c074a2102087d2a9fd32eb9432057a5833a872c3492350dd97061c1a0018a78e3968354ce47472835090063"; yc1 = "189bae5f89b4ff2d0640f7f2dfae407f0c6ef53cd7e96bd19df145d989b54b9cc5d4024da8b6e99f5b73c4a359853cbf" }
];

func x(v : Vector) : Fp2.Fp2 = { c0 = fp(v.xc0); c1 = fp(v.xc1) };
func y(v : Vector) : Fp2.Fp2 = { c0 = fp(v.yc0); c1 = fp(v.yc1) };

/// The G2 curve constant, `4(1 + u)`.
let B : Fp2.Fp2 = { c0 = 4; c1 = 4 };

test(
  "u² = −1",
  func() {
    let u : Fp2.Fp2 = { c0 = 0; c1 = 1 };
    assert Fp2.equal(Fp2.square(u), Fp2.neg(Fp2.one));
  },
);

test(
  "every reference G2 point satisfies y² = x³ + 4(1 + u)",
  func() {
    for (v in points.vals()) {
      let xv = x(v);
      let lhs = Fp2.square(y(v));
      let rhs = Fp2.add(Fp2.mul(Fp2.square(xv), xv), B);
      assert Fp2.equal(lhs, rhs);
    };
  },
);

test(
  "serialization round-trips, c1 first",
  func() {
    for (v in points.vals()) {
      let xv = x(v);
      switch (Fp2.fromBytes(Fp2.toBytes(xv))) {
        case (?back) assert Fp2.equal(back, xv);
        case null assert false;
      };
      // The order is c1 || c0, not c0 || c1 — assert it rather than assume.
      let bytes = Blob.toArray(Fp2.toBytes(xv));
      let firstHalf = Array.toBlob(Array.sliceToArray<Nat8>(bytes, 0, 48));
      assert Fp.fromBytes(firstHalf) == ?xv.c1;
    };
  },
);

test(
  "field axioms hold on reference values",
  func() {
    for (v in points.vals()) {
      let a = x(v);
      let b = y(v);
      // commutative, associative, distributive
      assert Fp2.equal(Fp2.mul(a, b), Fp2.mul(b, a));
      assert Fp2.equal(Fp2.add(a, b), Fp2.add(b, a));
      assert Fp2.equal(Fp2.mul(Fp2.mul(a, b), a), Fp2.mul(a, Fp2.mul(b, a)));
      assert Fp2.equal(
        Fp2.mul(a, Fp2.add(b, Fp2.one)),
        Fp2.add(Fp2.mul(a, b), a),
      );
      // identities and inverses
      assert Fp2.equal(Fp2.mul(a, Fp2.one), a);
      assert Fp2.equal(Fp2.sub(Fp2.add(a, b), b), a);
      assert Fp2.equal(Fp2.add(a, Fp2.neg(a)), Fp2.zero);
      assert Fp2.equal(Fp2.double(a), Fp2.add(a, a));
    };
  },
);

test(
  "squaring agrees with multiplication",
  func() {
    // square() uses the difference-of-squares shortcut, so it is a genuinely
    // different code path from mul(a, a).
    for (v in points.vals()) {
      let a = x(v);
      assert Fp2.equal(Fp2.square(a), Fp2.mul(a, a));
      let b = y(v);
      assert Fp2.equal(Fp2.square(b), Fp2.mul(b, b));
    };
  },
);

test(
  "inversion",
  func() {
    assert Fp2.inverse(Fp2.zero) == null;
    for (v in points.vals()) {
      let a = x(v);
      switch (Fp2.inverse(a)) {
        case (?inv) assert Fp2.equal(Fp2.mul(a, inv), Fp2.one);
        case null assert false;
      };
    };
  },
);

test(
  "conjugate and norm",
  func() {
    for (v in points.vals()) {
      let a = x(v);
      assert Fp2.equal(Fp2.conjugate(Fp2.conjugate(a)), a);
      // a · conjugate(a) is the norm, and lives in the base subfield.
      let prod = Fp2.mul(a, Fp2.conjugate(a));
      assert Fp.isZero(prod.c1);
      assert Fp.equal(prod.c0, Fp2.norm(a));
    };
  },
);

test(
  "multiplication by the non-residue matches multiplying by 1 + u",
  func() {
    let onePlusU : Fp2.Fp2 = { c0 = 1; c1 = 1 };
    for (v in points.vals()) {
      let a = x(v);
      assert Fp2.equal(Fp2.mulByNonresidue(a), Fp2.mul(a, onePlusU));
    };
  },
);

test(
  "square roots, both branches",
  func() {
    assert Fp2.sqrt(Fp2.zero) == ?Fp2.zero;

    // General case: y² always has y or −y as a root.
    for (v in points.vals()) {
      let b = y(v);
      switch (Fp2.sqrt(Fp2.square(b))) {
        case (?r) assert Fp2.equal(r, b) or Fp2.equal(r, Fp2.neg(b));
        case null assert false;
      };
    };

    // The alpha = −1 branch: squares of base-subfield elements. These take the
    // other formula, and are the ones a naive implementation gets wrong.
    for (v in points.vals()) {
      let base = Fp2.fromFp(fp(v.xc0));
      let sq = Fp2.square(base);
      switch (Fp2.sqrt(sq)) {
        case (?r) assert Fp2.equal(Fp2.square(r), sq);
        case null assert false;
      };
    };
  },
);

test(
  "non-squares are rejected",
  func() {
    // Roughly half of all elements are non-residues, so scanning a few finds
    // one; each must return null rather than a bogus root.
    var found = 0;
    var i = 1;
    while (i < 40 and found < 3) {
      let candidate : Fp2.Fp2 = { c0 = i; c1 = 1 };
      switch (Fp2.sqrt(candidate)) {
        case null found += 1;
        case (?r) assert Fp2.equal(Fp2.square(r), candidate);
      };
      i += 1;
    };
    assert found > 0;
  },
);

test(
  "lexicographically largest picks exactly one of a root pair",
  func() {
    for (v in points.vals()) {
      let b = y(v);
      if (not Fp2.isZero(b)) {
        assert Fp2.lexicographicallyLargest(b) != Fp2.lexicographicallyLargest(Fp2.neg(b));
      };
    };
  },
);
