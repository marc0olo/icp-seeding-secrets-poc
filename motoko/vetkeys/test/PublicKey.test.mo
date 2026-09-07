/// Tests for offline derived-public-key computation.
///
/// The vectors come from `vectorgen`, which derives them with `ic-vetkeys` —
/// the audited Rust implementation. Agreeing with them means a Motoko canister
/// derives the identical key a Rust one does, under the same context the
/// canisters in this repo use.

import { test } "mo:test";
import G2 "mo:sealed-secrets-bls/G2";
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
  { source = #Mainnet; keyName = "key_1"; canisterId = "00000000000000000101"; context = "64756d6d792d7365637265742d706f63"; expected = "a487b4d783a87f9e8d63fee0fcb6d94cd7507665960dc6e09555173fc74a6a4ddd3ab45bb494903687ed133b96abb71004f67b0fd4a5bf8e1b83aa0e238f5faf0a2ff589de7ab47a81e1f5a7db3ba2783e758d7ee7d40214204bb644362ff73c" },
  { source = #Mainnet; keyName = "test_key_1"; canisterId = "00000000000000010101"; context = "64756d6d792d7365637265742d706f63"; expected = "b4f53f3ce01c85ce3299d044ce32f924f79796b6cd2a84cdc74c0ac31ffdd022dd27a87d567806e17333d05ed2924190059c2b81433b1b500a4f90180327b5db855bb4fa82405f874f17b940b8ffd9ce45618184284d7faa83a9e5fa7e5a7360" },
  { source = #PocketIc; keyName = "key_1"; canisterId = "00000000000000000101"; context = "64756d6d792d7365637265742d706f63"; expected = "8b9e87a030deed4f85f89d48a6271070898fb1e9a5e1099536aa21f96b444498db0813c98ddc9d7e9356feb689f37b2e033859f1c03690007de3dee4e8ebb7e1a2da3546452cb684ce698bdae3571afecfc1c107ee86f43c45a6f49e4f9054fb" },
  { source = #PocketIc; keyName = "test_key_1"; canisterId = "00000000000000020101"; context = "64756d6d792d7365637265742d706f63"; expected = "b644f8c5a4a28ef28669c013e26dc73976241aea7e2c0e471c2d192b9776c614cacb719364d5efe145a7c5c00181a2e70bb4d2e5280ed4355cd2a0291d99e06630500b7cb3cd2d99174e572a0b5414c11ec11833aa3ad0e3d0e78dcda64713c4" },
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
