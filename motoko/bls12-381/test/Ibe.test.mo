/// The finish line.
///
/// `test/vectors.json` carries a complete IBE triple produced by the Rust
/// reference — a derived public key, an identity, a vetKey, a ciphertext, and
/// the plaintext it must yield. The generator decrypts it in Rust before
/// emitting it, so a failure here is this implementation's, not the vector's.
///
/// If this passes, the port works: the field tower, both group laws, the Miller
/// loop, the final exponentiation, HKDF, SHAKE256, `expand_message_xmd` and
/// every serialization format all have to be right simultaneously for the
/// authenticated check at the end of `decrypt` to succeed.

import { test } "mo:test";
import G1 "../src/G1";
import Ibe "../src/Ibe";
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

func hexBytes(hex : Text) : [Nat8] {
  let chars = Array.fromIter<Char>(Text.toIter(hex));
  assert chars.size() % 2 == 0;
  Array.tabulate<Nat8>(
    chars.size() / 2,
    func(i) = Nat8.fromNat(hexVal(chars[i * 2]) * 16 + hexVal(chars[i * 2 + 1])),
  );
};

func utf8(t : Text) : [Nat8] = Blob.toArray(Text.encodeUtf8(t));

let VETKEY = "887e66122b2ab97ad8ade759ec0d80a395b889f990fb3623d3a9d27c5a825a7b5f5693664b2e15137015640041341558";
let CIPHERTEXT = "4943204942450001acb3eb5f0f0f8e8026deca9ee0d9616df6cb80afcff012cd67427b6ce233e2829233d93b0ffbbcc23ef7f80e3928c43c0a6be487f9bfc88b4722c19e83e0abc441ca9799d84c50103d43d8f893624bd593b708cdd54e8be53825d738f8592b306a7913b4bf582dfef541fba06bc05df63134ee224ea732b1fb715073e9a44e6b0bbe03639e88526c7352dac8a09c95";
let PLAINTEXT = "a sealed secret";

func vetkey() : G1.Affine {
  switch (G1.fromCompressed(Array.toBlob(hexBytes(VETKEY)))) {
    case (?p) p;
    case null { assert false; G1.affineIdentity };
  };
};

test(
  "the vetKey is a valid G1 point",
  func() {
    let k = vetkey();
    assert not k.infinity;
    assert G1.isOnCurve(k);
  },
);

test(
  "the ciphertext parses",
  func() {
    switch (Ibe.deserialize(hexBytes(CIPHERTEXT))) {
      case null assert false;
      case (?ct) {
        assert ct.c3.size() == utf8(PLAINTEXT).size();
        assert not ct.c1.infinity;
      };
    };
  },
);

test(
  "a ciphertext with a corrupted header is rejected",
  func() {
    let bytes = hexBytes(CIPHERTEXT);
    let corrupted = Array.tabulate<Nat8>(
      bytes.size(),
      func i = if (i == 1) { bytes[i] ^ 0xff } else { bytes[i] },
    );
    assert Ibe.deserialize(corrupted) == null;
    // Too short to hold the overhead at all.
    assert Ibe.deserialize([1, 2, 3]) == null;
  },
);

test(
  "DECRYPTS THE REFERENCE CIPHERTEXT",
  func() {
    // The whole port, in one assertion.
    switch (Ibe.deserialize(hexBytes(CIPHERTEXT))) {
      case null assert false;
      case (?ct) {
        switch (Ibe.decrypt(ct, vetkey())) {
          case null assert false;
          case (?msg) {
            let expected = utf8(PLAINTEXT);
            assert msg.size() == expected.size();
            for (i in msg.keys()) { assert msg[i] == expected[i] };
          };
        };
      };
    };
  },
);

test(
  "a tampered ciphertext is rejected rather than mis-decrypted",
  func() {
    // The authenticated check at the end of decrypt: flip one bit of the masked
    // message and the recomputed scalar no longer matches c1. Without that
    // check this would return plausible garbage.
    let bytes = hexBytes(CIPHERTEXT);
    let last : Nat = bytes.size() - 1;
    let tampered = Array.tabulate<Nat8>(
      bytes.size(),
      func i = if (i == last) { bytes[i] ^ 0x01 } else { bytes[i] },
    );
    switch (Ibe.deserialize(tampered)) {
      case null assert false;
      case (?ct) assert Ibe.decrypt(ct, vetkey()) == null;
    };
  },
);

test(
  "the wrong vetKey is rejected",
  func() {
    switch (Ibe.deserialize(hexBytes(CIPHERTEXT))) {
      case null assert false;
      case (?ct) {
        // The generator is a perfectly valid G1 point, just not this key.
        assert Ibe.decrypt(ct, G1.generator) == null;
      };
    };
  },
);
