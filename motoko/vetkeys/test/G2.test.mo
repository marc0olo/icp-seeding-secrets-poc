/// Tests for `G2`, against reference vectors — the same shape as `G1`'s.
///
/// The decisive one is again scalar multiplication reproducing the reference's
/// multiples, which here exercises the whole `Fp2` layer through the group law.
/// The `sqrt` used in decompression is the two-branch one, so these vectors also
/// give it real inputs rather than constructed ones.

import { test } "mo:test";
import Fp2 "../src/Fp2";
import G2 "../src/G2";
import Array "mo:core/Array";
import Nat8 "mo:core/Nat8";
import Char "mo:core/Char";
import Nat32 "mo:core/Nat32";
import Text "mo:core/Text";
import Blob "mo:core/Blob";
import Fp "../src/Fp";

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

type Vector = {
  scalar : Nat;
  xc0 : Text;
  xc1 : Text;
  yc0 : Text;
  yc1 : Text;
  compressed : Text;
};

let points : [Vector] = [
  { scalar = 1; xc0 = "024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8"; xc1 = "13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e"; yc0 = "0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801"; yc1 = "0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be"; compressed = "93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8" },
  { scalar = 2; xc0 = "1638533957d540a9d2370f17cc7ed5863bc0b995b8825e0ee1ea1e1e4d00dbae81f14b0bf3611b78c952aacab827a053"; xc1 = "0a4edef9c1ed7f729f520e47730a124fd70662a904ba1074728114d1031e1572c6c886f6b57ec72a6178288c47c33577"; yc0 = "0468fb440d82b0630aeb8dca2b5256789a66da69bf91009cbfe6bd221e47aa8ae88dece9764bf3bd999d95d71e4c9899"; yc1 = "0f6d4552fa65dd2638b361543f887136a43253d9c66c411697003f7a13c308f5422e1aa0a59c8967acdefd8b6e36ccf3"; compressed = "aa4edef9c1ed7f729f520e47730a124fd70662a904ba1074728114d1031e1572c6c886f6b57ec72a6178288c47c335771638533957d540a9d2370f17cc7ed5863bc0b995b8825e0ee1ea1e1e4d00dbae81f14b0bf3611b78c952aacab827a053" },
  { scalar = 3; xc0 = "122915c824a0857e2ee414a3dccb23ae691ae54329781315a0c75df1c04d6d7a50a030fc866f09d516020ef82324afae"; xc1 = "09380275bbc8e5dcea7dc4dd7e0550ff2ac480905396eda55062650f8d251c96eb480673937cc6d9d6a44aaa56ca66dc"; yc0 = "0b21da7955969e61010c7a1abc1a6f0136961d1e3b20b1a7326ac738fef5c721479dfd948b52fdf2455e44813ecfd892"; yc1 = "08f239ba329b3967fe48d718a36cfe5f62a7e42e0bf1c1ed714150a166bfbd6bcf6b3b58b975b9edea56d53f23a0e849"; compressed = "89380275bbc8e5dcea7dc4dd7e0550ff2ac480905396eda55062650f8d251c96eb480673937cc6d9d6a44aaa56ca66dc122915c824a0857e2ee414a3dccb23ae691ae54329781315a0c75df1c04d6d7a50a030fc866f09d516020ef82324afae" },
  { scalar = 7; xc0 = "049cd1dbb2d2c3581e54c088135fef36505a6823d61b859437bfc79b617030dc8b40e32bad1fa85b9c0f368af6d38d3c"; xc1 = "0d0273f6bf31ed37c3b8d68083ec3d8e20b5f2cc170fa24b9b5be35b34ed013f9a921f1cad1644d4bdb14674247234c8"; yc0 = "08b7ae4dbf802c17a6648842922c9467e460a71c88d393ee7af356da123a2f3619e80c3bdcc8e2b1da52f8cd9913ccdd"; yc1 = "05ecf93654b7a1885695aaeeb7caf41b0239dc45e1022be55d37111af2aecef87799638bec572de86a7437898efa7020"; compressed = "8d0273f6bf31ed37c3b8d68083ec3d8e20b5f2cc170fa24b9b5be35b34ed013f9a921f1cad1644d4bdb14674247234c8049cd1dbb2d2c3581e54c088135fef36505a6823d61b859437bfc79b617030dc8b40e32bad1fa85b9c0f368af6d38d3c" },
  { scalar = 256; xc0 = "0412f6b2e37effc7e16d566d6f831572411d130eee4c15d82aa29e44cb4db9b5eb8c08b0ae158cde970d9d29ba368780"; xc1 = "02f7f6cc00b080cb3a7f8976c44d1987fd36a8334db831be269c6f6144c392b54bb934313d5fc832ec41d2f9a4b7ea91"; yc0 = "19ffef0307855bed96575447cb4a9442c91ec72b91e4c9107cbf619a3d9cf20df17831a98b65cc6def810c57e45594ea"; yc1 = "0af2e093a01abcfa36b20fc57d5d51ded73dbb06b639f10e921f8bb2758b2c3f10623aa26cbf9cce9856ccd1bc261e9a"; compressed = "82f7f6cc00b080cb3a7f8976c44d1987fd36a8334db831be269c6f6144c392b54bb934313d5fc832ec41d2f9a4b7ea910412f6b2e37effc7e16d566d6f831572411d130eee4c15d82aa29e44cb4db9b5eb8c08b0ae158cde970d9d29ba368780" },
  { scalar = 65537; xc0 = "06c67e6c183435e5aec742d2d786f6435f61b143f64b2bc1f69678ee434eb4feed7952b0f15777c5d72cddc3976fb090"; xc1 = "148a606f6a01429e4f7cc71d89b077128075d8101b7092d5fba8eb9189a57f34e9c4b442961357b1278f0464ea330876"; yc0 = "15b7953c1ae1467c7aade7e9ee06bcc682403179e2dd64325495f5984cbf59161c8507ad6a3fed6378a0500df04b0d8e"; yc1 = "062d6d609dbe6a6507032b5461a5d3d250d47ec10fe5003e14c008a9ec4b6590d16d4641a3a3167136d86261425c1938"; compressed = "948a606f6a01429e4f7cc71d89b077128075d8101b7092d5fba8eb9189a57f34e9c4b442961357b1278f0464ea33087606c67e6c183435e5aec742d2d786f6435f61b143f64b2bc1f69678ee434eb4feed7952b0f15777c5d72cddc3976fb090" },
  { scalar = 4294967295; xc0 = "0b4cb7985b95afdb0b39596dd016bd58c2f4a0b3f74e6f39cc627199a52718187c6265c2e8aa72094f06ef836e191bbd"; xc1 = "0f17f1c6651dbdee41e06e98bf0eb7bc47b0d5d7ab2df18ade51328d1cc771aaf4b22e1138f677833d4f596535475117"; yc0 = "0cdaf320208c8a20110e89113e38656aacbe0265eb9c663f22600c9636ad668ce2eb3638b7550392b7e2cdd45fafdd15"; yc1 = "10b79a3e6fee32f56d2fd8cf7a1fceb21435455a6894e83445abb4fee6a1db327ecb237a08cdda13d06b7a4231a6756d"; compressed = "af17f1c6651dbdee41e06e98bf0eb7bc47b0d5d7ab2df18ade51328d1cc771aaf4b22e1138f677833d4f5965354751170b4cb7985b95afdb0b39596dd016bd58c2f4a0b3f74e6f39cc627199a52718187c6265c2e8aa72094f06ef836e191bbd" },
  { scalar = 1234567890123; xc0 = "1342a65568d2f3cddeeba0db89641b5b6fac9459b7f500a4499b553915e7bf20cafbfb47b5467f9d7e1923b81063eed9"; xc1 = "1922fb9b5d990e55aa94f023e0dda0dd4976039695a807b007bca7720475336b09a4d428b68f4782e789b259d6f57328"; yc0 = "0075a9423c074a2102087d2a9fd32eb9432057a5833a872c3492350dd97061c1a0018a78e3968354ce47472835090063"; yc1 = "189bae5f89b4ff2d0640f7f2dfae407f0c6ef53cd7e96bd19df145d989b54b9cc5d4024da8b6e99f5b73c4a359853cbf"; compressed = "b922fb9b5d990e55aa94f023e0dda0dd4976039695a807b007bca7720475336b09a4d428b68f4782e789b259d6f573281342a65568d2f3cddeeba0db89641b5b6fac9459b7f500a4499b553915e7bf20cafbfb47b5467f9d7e1923b81063eed9" }
];

let IDENTITY_COMPRESSED = "c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

func vx(v : Vector) : Fp2.Fp2 = { c0 = fp(v.xc0); c1 = fp(v.xc1) };
func vy(v : Vector) : Fp2.Fp2 = { c0 = fp(v.yc0); c1 = fp(v.yc1) };

test(
  "the generator is on the curve and matches the reference",
  func() {
    assert G2.isOnCurve(G2.generator);
    assert G2.isOnCurve(G2.affineIdentity);
    let v = points[0];
    assert v.scalar == 1;
    assert Fp2.equal(G2.generator.x, vx(v));
    assert Fp2.equal(G2.generator.y, vy(v));
  },
);

test(
  "decompressing reference bytes yields reference coordinates",
  func() {
    for (v in points.vals()) {
      switch (G2.fromCompressed(hexBlob(v.compressed))) {
        case null assert false;
        case (?a) {
          assert not a.infinity;
          assert Fp2.equal(a.x, vx(v));
          assert Fp2.equal(a.y, vy(v));
          assert G2.isOnCurve(a);
        };
      };
    };
  },
);

test(
  "compression round-trips to the reference's exact bytes",
  func() {
    for (v in points.vals()) {
      let a : G2.Affine = { x = vx(v); y = vy(v); infinity = false };
      assert toHex(G2.toCompressed(a)) == v.compressed;
    };
  },
);

test(
  "the identity encoding matches the reference",
  func() {
    assert toHex(G2.toCompressed(G2.affineIdentity)) == IDENTITY_COMPRESSED;
    switch (G2.fromCompressed(hexBlob(IDENTITY_COMPRESSED))) {
      case (?a) assert a.infinity;
      case null assert false;
    };
  },
);

test(
  "scalar multiplication reproduces the reference's multiples",
  func() {
    let g = G2.fromAffine(G2.generator);
    for (v in points.vals()) {
      let computed = G2.toAffine(G2.mul(g, v.scalar));
      assert not computed.infinity;
      assert Fp2.equal(computed.x, vx(v));
      assert Fp2.equal(computed.y, vy(v));
    };
  },
);

test(
  "group axioms",
  func() {
    let g = G2.fromAffine(G2.generator);
    let two = G2.double(g);
    assert G2.equal(two, G2.add(g, g));
    assert G2.equal(G2.add(two, g), G2.mul(g, 3));
    assert G2.equal(G2.add(G2.add(g, two), g), G2.add(g, G2.add(two, g)));
    assert G2.equal(G2.add(g, G2.identity), g);
    assert G2.equal(G2.mul(g, 0), G2.identity);
  },
);

test(
  "a point plus its negation is the identity",
  func() {
    let g = G2.fromAffine(G2.generator);
    for (v in points.vals()) {
      let p = G2.mul(g, v.scalar);
      assert G2.isIdentity(G2.add(p, G2.neg(p)));
    };
  },
);

test(
  "malformed compressed encodings are rejected",
  func() {
    let good = Blob.toArray(hexBlob(points[1].compressed));
    let noFlag = Array.tabulate<Nat8>(96, func i = if (i == 0) { good[0] & 0x7f } else { good[i] });
    assert G2.fromCompressed(Array.toBlob(noFlag)) == null;

    let badInfinity = Array.tabulate<Nat8>(96, func i = if (i == 0) { good[0] | 0x40 } else { good[i] });
    assert G2.fromCompressed(Array.toBlob(badInfinity)) == null;

    assert G2.fromCompressed(hexBlob("00")) == null;
  },
);
