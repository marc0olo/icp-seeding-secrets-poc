/// Golden vectors for the wire format.
///
/// These are the same values `rust/core/tests/golden.rs` and
/// `seed/src/format.test.ts` assert. Three implementations, identical bytes —
/// which is the only thing that makes them interoperable. A divergence here
/// means this canister derives a different keypair, so every ciphertext the
/// seeder produces is one it cannot open. `set` would catch that — it decrypts
/// before storing — but as an opaque `InvalidCiphertext` on every seal, with
/// nothing pointing at the byte that moved. These vectors are what name it.

import { test } "mo:test";
import Format "../src/lib/Format";
import Blob "mo:core/Blob";
import Text "mo:core/Text";
import Nat8 "mo:core/Nat8";
import Nat "mo:core/Nat";

test(
  "context and key label golden vectors",
  func() {
    assert Format.toHex(Format.CONTEXT) == "6963702d7365616c65642d736563726574732d7631";
    assert Format.toHex(Format.KEY_LABEL) == "6963702d7365616c65642d736563726574732d76312e6b657973";
    // The literals must match the text they claim to encode.
    assert Format.CONTEXT == Blob.toArray(Text.encodeUtf8(Format.SUITE_TEXT));
    assert Format.KEY_LABEL == Blob.toArray(Text.encodeUtf8(Format.KEY_LABEL_TEXT));
  },
);

test(
  "the context and the key label are different bytes",
  func() {
    // They select different things — the context selects the keypair, the label
    // selects a key within it — so they must never be the same.
    assert Format.CONTEXT != Format.KEY_LABEL;
  },
);

test(
  "secret name validation",
  func() {
    let good = ["A", "a", "0", "_", ".", "-", "DUMMY_API_KEY", "a.b-c_1"];
    for (n in good.vals()) {
      assert (switch (Format.validateSecretName(n)) { case (#ok) true; case (#err(_)) false });
    };
    assert (switch (Format.validateSecretName("")) { case (#err(#EmptyName)) true; case (_) false });
    // Unicode confusables are exactly what the charset exists to exclude.
    let bad = ["a b", "a/b", "a:b", "naïve", "а"]; // last is Cyrillic 'а'
    for (n in bad.vals()) {
      assert (switch (Format.validateSecretName(n)) { case (#err(#InvalidNameChar(_))) true; case (_) false });
    };
    var long = "";
    for (_ in Nat.range(0, 64)) { long #= "a" };
    assert (switch (Format.validateSecretName(long)) { case (#ok) true; case (_) false });
    assert (switch (Format.validateSecretName(long # "a")) { case (#err(#NameTooLong(65))) true; case (_) false });
  },
);
