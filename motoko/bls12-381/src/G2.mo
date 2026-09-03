/// The curve group `G2`: `y^2 = x^3 + 4(u + 1)` over `F_p2`.
///
/// # ⚠️ EXPERIMENTAL AND UNAUDITED — see ../README.md
///
/// Structurally identical to `G1` — the same Jacobian coordinates and the same
/// group law — but over the quadratic extension, so every field operation is
/// several times dearer. Derived public keys live here.
///
/// Ported from `ic_bls12_381::g2`.

import Fp2 "Fp2";
import Blob "mo:core/Blob";
import Array "mo:core/Array";
import Nat8 "mo:core/Nat8";

module {
  /// The curve constant, `4(u + 1)`.
  public let B : Fp2.Fp2 = { c0 = 4; c1 = 4 };

  public type Point = { x : Fp2.Fp2; y : Fp2.Fp2; z : Fp2.Fp2 };
  public type Affine = { x : Fp2.Fp2; y : Fp2.Fp2; infinity : Bool };

  public let BYTES_COMPRESSED : Nat = 96;

  public let identity : Point = { x = Fp2.one; y = Fp2.one; z = Fp2.zero };

  public let affineIdentity : Affine = {
    x = Fp2.zero;
    y = Fp2.zero;
    infinity = true;
  };

  /// The standard generator, from the BLS12-381 specification.
  public let generator : Affine = {
    x = {
      c0 = 352701069587466618187139116011060144890029952792775240219908644239793785735715026873347600343865175952761926303160;
      c1 = 3059144344244213709971259814753781636986470325476647558659373206291635324768958432433509563104347017837885763365758;
    };
    y = {
      c0 = 1985150602287291935568054521177171638300868978215655730859378665066344726373823718423869104263333984641494340347905;
      c1 = 927553665492332455747201965776037880757740193453592970025027978793976877002675564980949289727957565575433344219582;
    };
    infinity = false;
  };

  public func isIdentity(p : Point) : Bool = Fp2.isZero(p.z);

  public func fromAffine(a : Affine) : Point =
    if (a.infinity) { identity } else { { x = a.x; y = a.y; z = Fp2.one } };

  public func toAffine(p : Point) : Affine {
    if (isIdentity(p)) { return affineIdentity };
    switch (Fp2.inverse(p.z)) {
      case null affineIdentity;
      case (?zInv) {
        let zInv2 = Fp2.square(zInv);
        let zInv3 = Fp2.mul(zInv2, zInv);
        {
          x = Fp2.mul(p.x, zInv2);
          y = Fp2.mul(p.y, zInv3);
          infinity = false;
        };
      };
    };
  };

  public func isOnCurve(a : Affine) : Bool {
    if (a.infinity) { return true };
    Fp2.equal(Fp2.square(a.y), Fp2.add(Fp2.mul(Fp2.square(a.x), a.x), B));
  };

  public func equalAffine(a : Affine, b : Affine) : Bool {
    if (a.infinity or b.infinity) { return a.infinity == b.infinity };
    Fp2.equal(a.x, b.x) and Fp2.equal(a.y, b.y);
  };

  public func equal(p : Point, q : Point) : Bool =
    equalAffine(toAffine(p), toAffine(q));

  public func neg(p : Point) : Point = { x = p.x; y = Fp2.neg(p.y); z = p.z };

  public func negAffine(a : Affine) : Affine =
    if (a.infinity) { a } else {
      { x = a.x; y = Fp2.neg(a.y); infinity = false };
    };

  public func double(p : Point) : Point {
    if (isIdentity(p)) { return identity };

    let a = Fp2.square(p.x);
    let b = Fp2.square(p.y);
    let c = Fp2.square(b);
    var d = Fp2.sub(Fp2.square(Fp2.add(p.x, b)), Fp2.add(a, c));
    d := Fp2.double(d);
    let e = Fp2.add(Fp2.double(a), a);
    let f = Fp2.square(e);

    let x3 = Fp2.sub(f, Fp2.double(d));
    let y3 = Fp2.sub(
      Fp2.mul(e, Fp2.sub(d, x3)),
      Fp2.double(Fp2.double(Fp2.double(c))),
    );
    let z3 = Fp2.double(Fp2.mul(p.y, p.z));

    if (Fp2.isZero(z3)) { identity } else { { x = x3; y = y3; z = z3 } };
  };

  public func add(p : Point, q : Point) : Point {
    if (isIdentity(p)) { return q };
    if (isIdentity(q)) { return p };

    let z1z1 = Fp2.square(p.z);
    let z2z2 = Fp2.square(q.z);
    let u1 = Fp2.mul(p.x, z2z2);
    let u2 = Fp2.mul(q.x, z1z1);
    let s1 = Fp2.mul(p.y, Fp2.mul(q.z, z2z2));
    let s2 = Fp2.mul(q.y, Fp2.mul(p.z, z1z1));

    if (Fp2.equal(u1, u2)) {
      if (Fp2.equal(s1, s2)) { return double(p) } else { return identity };
    };

    let h = Fp2.sub(u2, u1);
    let i = Fp2.square(Fp2.double(h));
    let j = Fp2.mul(h, i);
    let r = Fp2.double(Fp2.sub(s2, s1));
    let v = Fp2.mul(u1, i);

    let x3 = Fp2.sub(Fp2.sub(Fp2.square(r), j), Fp2.double(v));
    let y3 = Fp2.sub(Fp2.mul(r, Fp2.sub(v, x3)), Fp2.double(Fp2.mul(s1, j)));
    let z3 = Fp2.mul(
      Fp2.sub(Fp2.sub(Fp2.square(Fp2.add(p.z, q.z)), z1z1), z2z2),
      h,
    );

    { x = x3; y = y3; z = z3 };
  };

  public func sub(p : Point, q : Point) : Point = add(p, neg(q));

  public func mul(p : Point, k : Nat) : Point {
    var result = identity;
    var addend = p;
    var n = k;
    while (n > 0) {
      if (n % 2 == 1) { result := add(result, addend) };
      addend := double(addend);
      n /= 2;
    };
    result;
  };

  /// 96 bytes: `x.c1 || x.c0`, with the same three flag bits `G1` uses in the
  /// top of the first byte.
  public func toCompressed(a : Affine) : Blob {
    if (a.infinity) {
      return Array.toBlob(
        Array.tabulate<Nat8>(
          BYTES_COMPRESSED,
          func i = if (i == 0) { 0xc0 } else { 0 },
        )
      );
    };

    let xBytes = Fp2.toBytes(a.x).toArray();
    let sortBit : Nat8 = if (Fp2.lexicographicallyLargest(a.y)) { 0x20 } else {
      0;
    };
    Array.toBlob(
      Array.tabulate(
        BYTES_COMPRESSED,
        func i = if (i == 0) { xBytes[0] | 0x80 | sortBit } else { xBytes[i] },
      )
    );
  };

  public func fromCompressed(b : Blob) : ?Affine {
    let arr = b.toArray();
    if (arr.size() != BYTES_COMPRESSED) { return null };

    let flags = arr[0];
    let compressed = (flags & 0x80) != 0;
    let infinity = (flags & 0x40) != 0;
    let sortBit = (flags & 0x20) != 0;

    if (not compressed) { return null };

    let masked = Array.tabulate(
      BYTES_COMPRESSED,
      func i = if (i == 0) { arr[0] & 0x1f } else { arr[i] },
    );

    let x = switch (Fp2.fromBytes(masked.toBlob())) {
      case (?v) v;
      case null { return null };
    };

    if (infinity) {
      if (sortBit or not Fp2.isZero(x)) { return null };
      return ?affineIdentity;
    };

    let ySquared = Fp2.add(Fp2.mul(Fp2.square(x), x), B);
    switch (Fp2.sqrt(ySquared)) {
      case null null;
      case (?y) {
        let y2 = if (Fp2.lexicographicallyLargest(y) != sortBit) { Fp2.neg(y) } else {
          y;
        };
        ?{ x; y = y2; infinity = false };
      };
    };
  };
}
