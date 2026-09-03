/// The hash constructions the IBE scheme needs: HKDF-SHA256, SHAKE256 and
/// `expand_message_xmd`.
///
/// # ⚠️ EXPERIMENTAL AND UNAUDITED — see ../README.md
///
/// SHAKE256 is built on the `sha3` package's exposed Keccak permutation rather
/// than a fresh one — reusing an existing implementation of the hard part is
/// better than writing a second. The package ships SHA3 and Keccak with fixed
/// output lengths but no XOF, which is exactly what the IBE ciphertext mask
/// needs, so the sponge is driven directly here.

import Sha256 "mo:sha2/Sha256";
import Sha3 "mo:sha3";
import Array "mo:core/Array";
import VarArray "mo:core/VarArray";
import Nat8 "mo:core/Nat8";
import Nat64 "mo:core/Nat64";
import Blob "mo:core/Blob";
import Text "mo:core/Text";
import Nat "mo:core/Nat";

module {
  public func sha256(data : [Nat8]) : [Nat8] =
    Blob.toArray(Sha256.fromArray(#sha256, data));

  /// HMAC-SHA256, per RFC 2104.
  public func hmacSha256(key : [Nat8], message : [Nat8]) : [Nat8] {
    let blockSize = 64;
    let k = if (key.size() > blockSize) { sha256(key) } else { key };
    let padded = Array.tabulate<Nat8>(
      blockSize,
      func i = if (i < k.size()) { k[i] } else { 0 },
    );
    let inner = Array.tabulate<Nat8>(blockSize, func i = padded[i] ^ 0x36);
    let outer = Array.tabulate<Nat8>(blockSize, func i = padded[i] ^ 0x5c);
    let innerHash = sha256(Array.concat<Nat8>(inner, message));
    sha256(Array.concat<Nat8>(outer, innerHash));
  };

  /// HKDF-SHA256 with an empty salt, matching `ic-vetkeys`' `hkdf`
  /// (`utils/mod.rs:224`), which passes `None` for the salt.
  public func hkdf(input : [Nat8], domainSep : Text, len : Nat) : [Nat8] {
    // Extract: an absent salt is a block of zeros.
    let salt = Array.tabulate<Nat8>(32, func _ = 0);
    let prk = hmacSha256(salt, input);

    // Expand.
    let info = Blob.toArray(Text.encodeUtf8(domainSep));
    var okm : [Nat8] = [];
    var previous : [Nat8] = [];
    var counter : Nat8 = 1;
    while (okm.size() < len) {
      let block = hmacSha256(
        prk,
        Array.concat<Nat8>(Array.concat<Nat8>(previous, info), [counter]),
      );
      okm := Array.concat<Nat8>(okm, block);
      previous := block;
      counter += 1;
    };
    Array.sliceToArray<Nat8>(okm, 0, len);
  };

  /// SHAKE256 as an extendable-output function.
  ///
  /// Rate is 136 bytes and the domain separator is `0x1f`, which is what
  /// distinguishes SHAKE from SHA3 (`0x06`) and raw Keccak (`0x01`).
  public func shake256(input : [Nat8], outputLen : Nat) : [Nat8] {
    let rate = 136;
    let st = VarArray.repeat<Nat64>(0, 25);

    // Absorb.
    var pt = 0;
    for (d in input.vals()) {
      Sha3.set_nat8(st, pt, Sha3.get_nat8(st, pt) ^ d);
      pt += 1;
      if (pt >= rate) { Sha3.keccakf(st); pt := 0 };
    };

    // Pad: 0x1f at the cursor, 0x80 at the end of the rate.
    Sha3.set_nat8(st, pt, Sha3.get_nat8(st, pt) ^ 0x1f);
    Sha3.set_nat8(st, rate - 1, Sha3.get_nat8(st, rate - 1) ^ 0x80);
    Sha3.keccakf(st);

    // Squeeze.
    var out : [Nat8] = [];
    while (out.size() < outputLen) {
      let take = Nat.min(rate, outputLen - out.size() : Nat);
      out := Array.concat<Nat8>(
        out,
        Array.tabulate<Nat8>(take, func i = Sha3.get_nat8(st, i)),
      );
      if (out.size() < outputLen) { Sha3.keccakf(st) };
    };
    Array.sliceToArray<Nat8>(out, 0, outputLen);
  };

  /// `expand_message_xmd` with SHA-256, from RFC 9380 section 5.3.1.
  ///
  /// This is what `hash_to_scalar` is built on, and its output has to match the
  /// reference byte for byte or every derived scalar differs.
  public func expandMessageXmd(msg : [Nat8], dst : [Nat8], lenInBytes : Nat) : [Nat8] {
    let bInBytes = 32; // SHA-256 output
    let sInBytes = 64; // SHA-256 block
    let ell = (lenInBytes + bInBytes - 1) / bInBytes;
    assert ell <= 255;

    // DST longer than 255 bytes is hashed down; short ones are used as-is.
    let dstPrime = Array.concat<Nat8>(dst, [Nat.toNat8(dst.size())]);
    let zPad = Array.tabulate<Nat8>(sInBytes, func _ = 0);
    let lIBStr : [Nat8] = [
      Nat.toNat8(lenInBytes / 256),
      Nat.toNat8(lenInBytes % 256),
    ];

    let msgPrime = Array.concat<Nat8>(
      Array.concat<Nat8>(
        Array.concat<Nat8>(zPad, msg),
        Array.concat<Nat8>(lIBStr, [0 : Nat8]),
      ),
      dstPrime,
    );

    let b0 = sha256(msgPrime);
    var bi = sha256(
      Array.concat<Nat8>(Array.concat<Nat8>(b0, [1 : Nat8]), dstPrime)
    );
    var out = bi;

    var i : Nat8 = 2;
    while (out.size() < lenInBytes) {
      let xored = Array.tabulate<Nat8>(bInBytes, func j = b0[j] ^ bi[j]);
      bi := sha256(
        Array.concat<Nat8>(Array.concat<Nat8>(xored, [i]), dstPrime)
      );
      out := Array.concat<Nat8>(out, bi);
      i += 1;
    };
    Array.sliceToArray<Nat8>(out, 0, lenInBytes);
  };
}
