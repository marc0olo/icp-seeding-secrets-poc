/// Tests for the hash constructions, against values computed with Python's
/// `hashlib`/`hmac` — an implementation with no relationship to this one or to
/// `ic_bls12_381`.
///
/// These matter more than they look. Every derived scalar and every ciphertext
/// mask in the IBE scheme comes out of these functions, so a byte wrong here
/// produces a decryption that fails with no indication of why.

import { test } "mo:test";
import Hash "../src/Hash";
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

test(
  "sha256",
  func() {
    assert toHex(Hash.sha256(bytes("abc")))
    == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
  },
);

test(
  "hmac-sha256",
  func() {
    assert toHex(Hash.hmacSha256(bytes("key"), bytes("abc")))
    == "9c196e32dc0175f86f4b1cb89289d6619de6bee699e4c378e68309ed97a1a6ab";
  },
);

test(
  "shake256 as an XOF",
  func() {
    // Built on the sha3 package's Keccak permutation, driven as a sponge. The
    // 0x1f domain byte is what makes it SHAKE rather than SHA3 — get it wrong
    // and every output differs.
    assert toHex(Hash.shake256(bytes("abc"), 32))
    == "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739";

    // Longer than the 136-byte rate would be, exercising the squeeze loop, and
    // on empty input.
    assert toHex(Hash.shake256([], 64))
    == "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"
    # "d75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be";
  },
);

test(
  "hkdf-sha256 with an absent salt",
  func() {
    // ic-vetkeys passes None for the salt, which RFC 5869 defines as a block of
    // zeros. Reading that as an empty byte string instead is a classic slip and
    // produces entirely different output.
    assert toHex(Hash.hkdf(bytes("abc"), "ds", 32))
    == "af6d4a916e044446945b520ec6b3c70a31281a9c571bf86dc0a186871407eddf";
  },
);

test(
  "hkdf produces the requested length across block boundaries",
  func() {
    for (n in [1, 31, 32, 33, 64, 100].vals()) {
      assert Hash.hkdf(bytes("input"), "sep", n).size() == n;
    };
    // A longer request must extend the shorter one, not restart it.
    let short = Hash.hkdf(bytes("input"), "sep", 32);
    let long = Hash.hkdf(bytes("input"), "sep", 64);
    for (i in [0, 15, 31].vals()) { assert short[i] == long[i] };
  },
);

test(
  "expand_message_xmd produces the requested length",
  func() {
    for (n in [32, 48, 64, 96].vals()) {
      assert Hash.expandMessageXmd(bytes("msg"), bytes("DST"), n).size() == n;
    };
  },
);
