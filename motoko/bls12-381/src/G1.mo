/// The curve group `G1`: `y^2 = x^3 + 4` over `F_p`.
///
/// # ⚠️ EXPERIMENTAL AND UNAUDITED — see ../README.md
///
/// Points are held in Jacobian projective coordinates `(X, Y, Z)` representing
/// the affine point `(X/Z^2, Y/Z^3)`, with `Z = 0` meaning the identity. That
/// avoids a field inversion — 43 million instructions here — on every addition.
///
/// Ported from `ic_bls12_381::g1`.

import Fp "Fp";
import Blob "mo:core/Blob";
import Array "mo:core/Array";
import Nat8 "mo:core/Nat8";

module {
  /// The curve constant `b`.
  public let B : Fp.Fp = 4;

  /// A point in Jacobian coordinates. `z = 0` is the identity.
  public type Point = { x : Fp.Fp; y : Fp.Fp; z : Fp.Fp };

  /// A point in affine coordinates, or the identity.
  public type Affine = { x : Fp.Fp; y : Fp.Fp; infinity : Bool };

  public let BYTES_COMPRESSED : Nat = 48;

  public let identity : Point = { x = Fp.one; y = Fp.one; z = Fp.zero };

  public let affineIdentity : Affine = {
    x = Fp.zero;
    y = Fp.zero;
    infinity = true;
  };

  /// The standard generator, from the BLS12-381 specification.
  public let generator : Affine = {
    x = 3685416753713387016781088315183077757961620795782546409894578378688607592378376318836054947676345821548104185464507;
    y = 1339506544944476473020471379941921221584933875938349620426543736416511423956333506472724655353366534992391756441569;
    infinity = false;
  };

  public func isIdentity(p : Point) : Bool = Fp.isZero(p.z);

  public func fromAffine(a : Affine) : Point =
    if (a.infinity) { identity } else { { x = a.x; y = a.y; z = Fp.one } };

  /// Normalises to affine, which costs one inversion.
  public func toAffine(p : Point) : Affine {
    if (isIdentity(p)) { return affineIdentity };
    switch (Fp.inverse(p.z)) {
      case null affineIdentity;
      case (?zInv) {
        let zInv2 = Fp.square(zInv);
        let zInv3 = Fp.mul(zInv2, zInv);
        {
          x = Fp.mul(p.x, zInv2);
          y = Fp.mul(p.y, zInv3);
          infinity = false;
        };
      };
    };
  };

  /// Is the affine point actually on the curve?
  public func isOnCurve(a : Affine) : Bool {
    if (a.infinity) { return true };
    Fp.equal(Fp.square(a.y), Fp.add(Fp.mul(Fp.square(a.x), a.x), B));
  };

  public func equalAffine(a : Affine, b : Affine) : Bool {
    if (a.infinity or b.infinity) { return a.infinity == b.infinity };
    Fp.equal(a.x, b.x) and Fp.equal(a.y, b.y);
  };

  public func equal(p : Point, q : Point) : Bool =
    equalAffine(toAffine(p), toAffine(q));

  public func neg(p : Point) : Point = { x = p.x; y = Fp.neg(p.y); z = p.z };

  public func negAffine(a : Affine) : Affine =
    if (a.infinity) { a } else { { x = a.x; y = Fp.neg(a.y); infinity = false } };

  /// Point doubling, `dbl-2009-l` from the EFD.
  public func double(p : Point) : Point {
    if (isIdentity(p)) { return identity };

    let a = Fp.square(p.x);
    let b = Fp.square(p.y);
    let c = Fp.square(b);
    var d = Fp.sub(Fp.square(Fp.add(p.x, b)), Fp.add(a, c));
    d := Fp.double(d);
    let e = Fp.add(Fp.double(a), a);
    let f = Fp.square(e);

    let x3 = Fp.sub(f, Fp.double(d));
    let y3 = Fp.sub(
      Fp.mul(e, Fp.sub(d, x3)),
      Fp.double(Fp.double(Fp.double(c))),
    );
    let z3 = Fp.double(Fp.mul(p.y, p.z));

    if (Fp.isZero(z3)) { identity } else { { x = x3; y = y3; z = z3 } };
  };

  /// Point addition, `add-2007-bl` from the EFD.
  public func add(p : Point, q : Point) : Point {
    if (isIdentity(p)) { return q };
    if (isIdentity(q)) { return p };

    let z1z1 = Fp.square(p.z);
    let z2z2 = Fp.square(q.z);
    let u1 = Fp.mul(p.x, z2z2);
    let u2 = Fp.mul(q.x, z1z1);
    let s1 = Fp.mul(p.y, Fp.mul(q.z, z2z2));
    let s2 = Fp.mul(q.y, Fp.mul(p.z, z1z1));

    if (Fp.equal(u1, u2)) {
      // Same x. Either the same point — double it — or a point and its
      // negation, whose sum is the identity. Conflating these is a classic
      // source of wrong answers on inputs that rarely come up in testing.
      if (Fp.equal(s1, s2)) { return double(p) } else { return identity };
    };

    let h = Fp.sub(u2, u1);
    let i = Fp.square(Fp.double(h));
    let j = Fp.mul(h, i);
    let r = Fp.double(Fp.sub(s2, s1));
    let v = Fp.mul(u1, i);

    let x3 = Fp.sub(Fp.sub(Fp.square(r), j), Fp.double(v));
    let y3 = Fp.sub(
      Fp.mul(r, Fp.sub(v, x3)),
      Fp.double(Fp.mul(s1, j)),
    );
    let z3 = Fp.mul(
      Fp.sub(Fp.sub(Fp.square(Fp.add(p.z, q.z)), z1z1), z2z2),
      h,
    );

    { x = x3; y = y3; z = z3 };
  };

  public func sub(p : Point, q : Point) : Point = add(p, neg(q));

  /// Scalar multiplication by double-and-add.
  ///
  /// The ladder is data-dependent, so this leaks the scalar through timing. It
  /// is used here only with public scalars; see the crate warning.
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

  /// Serializes to the 48-byte compressed form.
  ///
  /// The top three bits of the first byte are flags: bit 7 compression (always
  /// set here), bit 6 infinity, bit 5 the sort bit that selects which of the two
  /// roots `y` is (`g1.rs:337`).
  public func toCompressed(a : Affine) : Blob {
    if (a.infinity) {
      let bytes = Array.tabulate<Nat8>(
        BYTES_COMPRESSED,
        func i = if (i == 0) { 0xc0 } else { 0 },
      );
      return bytes.toBlob();
    };

    let xBytes = Fp.toBytes(a.x).toArray();
    let sortBit : Nat8 = if (Fp.lexicographicallyLargest(a.y)) { 0x20 } else { 0 };
    let bytes = Array.tabulate(
      BYTES_COMPRESSED,
      func i = if (i == 0) { xBytes[0] | 0x80 | sortBit } else { xBytes[i] },
    );
    bytes.toBlob();
  };

  /// Parses the 48-byte compressed form, recovering `y` from `x`.
  ///
  /// Rejects anything the reference rejects: a clear compression flag, an
  /// infinity encoding with a non-zero `x` or a set sort bit, a non-canonical
  /// `x`, or an `x` for which `x^3 + 4` is not a square.
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

    let x = switch (Fp.fromBytes(masked.toBlob())) {
      case (?v) v;
      case null { return null };
    };

    if (infinity) {
      // The identity encoding is exact: x must be zero and the sort bit clear.
      if (sortBit or not Fp.isZero(x)) { return null };
      return ?affineIdentity;
    };

    let ySquared = Fp.add(Fp.mul(Fp.square(x), x), B);
    switch (Fp.sqrt(ySquared)) {
      case null null;
      case (?y) {
        // sqrt returns one of the pair; the sort bit says which was meant.
        let y2 = if (Fp.lexicographicallyLargest(y) != sortBit) { Fp.neg(y) } else {
          y;
        };
        ?{ x; y = y2; infinity = false };
      };
    };
  };
}
