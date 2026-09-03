/// Tests for offline derived-public-key computation.
///
/// The vectors come from `vectorgen`, which computes them through
/// `sealed_secrets_core::derive_public_key` — the same path the Rust canister
/// takes. Agreeing with them means a Motoko canister derives the identical key
/// the Rust one does, and therefore checks the subnet's reply against the same
/// constant.

import { test } "mo:test";
import G2 "../src/G2";
import PublicKey "../src/PublicKey";
import Array "mo:core/Array";
import Nat "mo:core/Nat";
import Nat8 "mo:core/Nat8";
import Char "mo:core/Char";
import Nat32 "mo:core/Nat32";
import Text "mo:core/Text";
import Iter "mo:core/Iter";
import Blob "mo:core/Blob";

func hexVal(c : Char) : Nat {
  let n = Nat32.toNat(Char.toNat32(c));
  if (n >= 48 and n <= 57) { n - 48 } else if (n >= 97 and n <= 102) {
    n - 87;
  } else if (n >= 65 and n <= 70) { n - 55 } else { 16 };
};

func hexBytes(hex : Text) : [Nat8] {
  let chars = Iter.toArray<Char>(Text.toIter(hex));
  assert chars.size() % 2 == 0;
  Array.tabulate<Nat8>(
    chars.size() / 2,
    func(i) = Nat.toNat8(hexVal(chars[i * 2]) * 16 + hexVal(chars[i * 2 + 1])),
  );
};

func toHex(b : Blob) : Text {
  let digits = Iter.toArray<Char>(Text.toIter("0123456789abcdef"));
  var out = "";
  for (byte in Blob.toArray(b).vals()) {
    let n = Nat8.toNat(byte);
    out #= Char.toText(digits[n / 16]) # Char.toText(digits[n % 16]);
  };
  out;
};

type Vector = {
  source : PublicKey.KeySource;
  keyName : Text;
  canisterId : Text;
  context : Text;
  expected : Text;
};

let vectors : [Vector] = [
  { source = #Mainnet; keyName = "key_1"; canisterId = "00000000000000000101"; context = "01156963702d7365616c65642d736563726574732d763100"; expected = "a163d3160505c1144b654f4e384d7fe1b43f95733bf1518a515578024d3804c28a91ad83ead4552deb4f3a0c7c6e2f1e0cdf045744abf52e3cff5d8440bb5ee78fc2df155f35dbd5201767426ca6ba5796d89a3766a9f12b2a7483b5348f552a" },
  { source = #Mainnet; keyName = "test_key_1"; canisterId = "00000000000000010101"; context = "01156963702d7365616c65642d736563726574732d763100"; expected = "aef30c2eeca9a466dd31b56b122547d1571d04aea90c7924cd7d08022042497451e7ebd00b4e40e4334ee2c4be8e4714097d0716158a31d1ab75152e6eb1cc89fd273869306c2054de6c2bc191c8ceeb4fadeac97a7afd6b6142a8e7d3895d1c" },
  { source = #PocketIc; keyName = "key_1"; canisterId = "00000000000000000101"; context = "01156963702d7365616c65642d736563726574732d763100"; expected = "913a2d8245103febc15b48154fbba011343293f18909648ceeb4c8de6cf7d1642a37182fdd55d4ddfda676d5924ffece053f156aa89f84d76aab5f7e3a5902e62d0befc56b74eec7ea3ae1dff9e0940e2f3f3b7196acbe34ab767daf9ed48527" },
  { source = #PocketIc; keyName = "test_key_1"; canisterId = "00000000000000020101"; context = "01156963702d7365616c65642d736563726574732d76310464656d6f"; expected = "af43dae7da1ec0a7dc3806b8dbd46fd56ea8047782a35ee255d801dc6a8e0f48021588d7a26bf0bca2dde12f6473db0d0c9e08c8727d631a20f78324c8d051ac62592be719e557c216591269c4c0bb2bb2c12a5f6fb56376d85991215269dd6e" },
];

func derive(v : Vector) : G2.Affine {
  let mpk = switch (PublicKey.masterPublicKey(v.source, v.keyName)) {
    case (?k) k;
    case null { assert false; G2.affineIdentity };
  };
  PublicKey.deriveSubKey(
    PublicKey.deriveCanisterKey(mpk, hexBytes(v.canisterId)),
    hexBytes(v.context),
  );
};

test(
  "master public keys decompress to valid points",
  func() {
    for (s in ([#Mainnet, #PocketIc] : [PublicKey.KeySource]).vals()) {
      for (n in ["key_1", "test_key_1"].vals()) {
        switch (PublicKey.masterPublicKey(s, n)) {
          case (?k) { assert G2.isOnCurve(k); assert not k.infinity };
          case null assert false;
        };
      };
    };
    switch (PublicKey.masterPublicKey(#PocketIc, "dfx_test_key")) {
      case (?k) assert G2.isOnCurve(k);
      case null assert false;
    };
  },
);

test(
  "unknown key names are rejected rather than guessed",
  func() {
    assert PublicKey.masterPublicKey(#Mainnet, "nonexistent") == null;
    assert PublicKey.masterPublicKey(#Mainnet, "") == null;
    // dfx_test_key is PocketIC-only, as in the reference.
    assert PublicKey.masterPublicKey(#Mainnet, "dfx_test_key") == null;
    assert PublicKey.masterPublicKey(#PocketIc, "dfx_test_key") != null;
  },
);

test(
  "the same key name is a different key on each network",
  func() {
    // The trap this guards: selecting the master-key table by key *name*. Both
    // tables have a key_1 and they are unrelated.
    let a = PublicKey.masterPublicKey(#Mainnet, "key_1");
    let b = PublicKey.masterPublicKey(#PocketIc, "key_1");
    switch (a, b) {
      case (?x, ?y) assert not G2.equalAffine(x, y);
      case _ assert false;
    };
  },
);

test(
  "derivation matches the Rust reference",
  func() {
    for (v in vectors.vals()) {
      assert toHex(G2.toCompressed(derive(v))) == v.expected;
    };
  },
);

test(
  "an empty context is the identity derivation",
  func() {
    let mpk = switch (PublicKey.masterPublicKey(#Mainnet, "key_1")) {
      case (?k) k;
      case null { assert false; G2.affineIdentity };
    };
    let canisterKey = PublicKey.deriveCanisterKey(mpk, hexBytes("00000000000000000101"));
    assert G2.equalAffine(PublicKey.deriveSubKey(canisterKey, []), canisterKey);
  },
);

test(
  "derivation is bound to the canister and to the context",
  func() {
    let mpk = switch (PublicKey.masterPublicKey(#Mainnet, "key_1")) {
      case (?k) k;
      case null { assert false; G2.affineIdentity };
    };
    let a = PublicKey.deriveCanisterKey(mpk, hexBytes("00000000000000000101"));
    let b = PublicKey.deriveCanisterKey(mpk, hexBytes("00000000000000010101"));
    assert not G2.equalAffine(a, b);
    assert not G2.equalAffine(PublicKey.deriveSubKey(a, hexBytes("aa")), a);
    assert not G2.equalAffine(
      PublicKey.deriveSubKey(a, hexBytes("aa")),
      PublicKey.deriveSubKey(a, hexBytes("bb")),
    );
  },
);

test(
  "the length prefix makes the two inputs unambiguous",
  func() {
    // Without length prefixing, deriving with canister "ab" then context "c"
    // would hash the same bytes as canister "a" then context "bc".
    let mpk = switch (PublicKey.masterPublicKey(#Mainnet, "key_1")) {
      case (?k) k;
      case null { assert false; G2.affineIdentity };
    };
    let x = PublicKey.deriveSubKey(PublicKey.deriveCanisterKey(mpk, hexBytes("abcd")), hexBytes("ef"));
    let y = PublicKey.deriveSubKey(PublicKey.deriveCanisterKey(mpk, hexBytes("ab")), hexBytes("cdef"));
    assert not G2.equalAffine(x, y);
  },
);
