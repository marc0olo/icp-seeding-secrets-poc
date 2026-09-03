/// Golden vectors for the wire format.
///
/// These are the same values `rust/core/tests/golden.rs` and
/// `seed/src/format.test.ts` assert. Three implementations, identical bytes —
/// which is the only thing that makes them interoperable. A divergence here
/// means this canister derives a different keypair, and every ciphertext the
/// existing seeder produces becomes undecryptable without any error at seal
/// time.

import { test } "mo:test";
import Format "../src/Format";
import Blob "mo:core/Blob";
import Text "mo:core/Text";
import Nat8 "mo:core/Nat8";
import Nat "mo:core/Nat";

test(
  "the suite label is pinned",
  func() {
    assert Format.toHex(Format.SUITE) == "6963702d7365616c65642d736563726574732d7631";
    assert Format.SUITE.size() == 21;
    // The literal must match the text it claims to encode.
    assert Format.SUITE == Blob.toArray(Text.encodeUtf8(Format.SUITE_TEXT));
  },
);

func ctx(sep : Text) : [Nat8] = switch (Format.context(sep)) {
  case (#ok(b)) b;
  case (#err(_)) { assert false; [] };
};

test(
  "context golden vectors",
  func() {
    assert Format.toHex(ctx("")) == "01156963702d7365616c65642d736563726574732d763100";
    assert Format.toHex(ctx("demo")) == "01156963702d7365616c65642d736563726574732d76310464656d6f";
  },
);

test(
  "identity golden vectors",
  func() {
    assert Format.toHex(Format.identity(0)) == "01156963702d7365616c65642d736563726574732d763100000000";
    assert Format.toHex(Format.identity(1)) == "01156963702d7365616c65642d736563726574732d763100000001";
    assert Format.toHex(Format.identity(4294967295)) == "01156963702d7365616c65642d736563726574732d7631ffffffff";
  },
);

test(
  "the context encoding is unambiguous",
  func() {
    // Length prefixes exist so no two distinct inputs collide.
    let a = ctx("x");
    let b = ctx("");
    assert a != b;
    assert a.size() == b.size() + 1;
  },
);

test(
  "the app separator length is bounded",
  func() {
    var ok = "";
    for (_ in Nat.range(0, 255)) { ok #= "a" };
    assert (switch (Format.context(ok)) { case (#ok(_)) true; case (#err(_)) false });
    assert (switch (Format.context(ok # "a")) { case (#err(#AppSeparatorTooLong(256))) true; case (_) false });
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
