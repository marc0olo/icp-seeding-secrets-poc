/// Offline derived-public-key computation.
///
/// # ⚠️ EXPERIMENTAL AND UNAUDITED — see ../README.md
///
/// Given a master public key that is *compiled into the canister*, this computes
/// the public key belonging to a (canister, context) pair without asking anyone.
/// That is the whole point: `VetKey.decryptAndVerify` is only as trustworthy as
/// the derived public key handed to it, and a canister that fetches that key
/// from `vetkd_public_key` is asking the subnet to vouch for itself. Deriving it
/// here closes the loop against a constant an auditor can read in the source.
///
/// Ported from `ic_vetkeys::MasterPublicKey` (`utils/mod.rs:355`) and
/// `DerivedPublicKey::derive_sub_key` (`:486`).

import G2 "G2";
import Scalar "Scalar";
import Array "mo:core/Array";
import Nat "mo:core/Nat";
import Nat32 "mo:core/Nat32";
import Iter "mo:core/Iter";
import Char "mo:core/Char";
import Text "mo:core/Text";
import Blob "mo:core/Blob";

module {
  /// Which table of master keys to use.
  ///
  /// **Never infer this from the key name.** `key_1` exists in both tables and
  /// they are different keys. Selecting by name is a live bug in `ic-vetkeys`'
  /// own `compute_vrf` (`utils/mod.rs:411` against `:422`), and the failure mode
  /// is quiet: everything works on the network you tested, and the ciphertext is
  /// permanently undecryptable on the other one.
  public type KeySource = { #Mainnet; #PocketIc };

  let DS_CANISTER_ID = "ic-vetkd-bls12-381-g2-canister-id";
  let DS_CONTEXT = "ic-vetkd-bls12-381-g2-context";

  // The published master public keys, compressed `G2`, copied verbatim from
  // `ic_vetkeys` (`utils/mod.rs:21-29`). Kept as hex rather than decoded
  // coordinates so they can be diffed against upstream by eye.
  let MAINNET_KEY_1 = "a9caf9ae8af0c7c7272f8a122133e2e0c7c0899b75e502bda9e109ca8193ded3ef042ed96db1125e1bdaad77d8cc60d917e122fe2501c45b96274f43705edf0cfd455bc66c3c060faa2fcd15486e76351edf91fecb993797273bbc8beaa47404";
  let MAINNET_TEST_KEY_1 = "ad86e8ff845912f022a0838a502d763fdea547c9948f8cb20ea7738dd52c1c38dcb4c6ca9ac29f9ac690fc5ad7681cb41922b8dffbd65d94bff141f5fb5b6624eccc03bf850f222052df888cf9b1e47203556d7522271cbb879b2ef4b8c2bfb1";
  let POCKETIC_KEY_1 = "8c800b5cff00463d26e8167369168827f1e48f4d8d60f71dd6a295580f65275b5f5f8e6a792c876b2c72492136530d0710a27522ee63977a76216c3cef9e70bfcb45b88736fc62142e7e0737848ce06cbb1f45a4a6a349b142ae5cf7853561e0";
  let POCKETIC_TEST_KEY_1 = "9069b82c7aae418cef27678291e7f2cb1a008a500eceba7199bffca12421b07c158987c6a22618af3d1958738b2835691028801f7663d311799733286c557c8979184bb62cb559a4d582fca7d2e48b860f08ed6641aef66a059ec891889a6218";
  let POCKETIC_DFX_TEST_KEY = "b181c14cf9d04ba45d782c0067a44b0aaa9fc2acf94f1a875f0dae801af4f80339a7e6bf8b09fcf993824c8df3080b3f1409b688ca08cbd44d2cb28db9899f4aa3b5f06b9174240448e10be2f01f9f80079ea5431ce2d11d1c8d1c775333315f";

  /// The master public key for a source and key name, or `null` if unknown.
  ///
  /// Decompressing costs an `Fp2` square root — on the order of 100 million
  /// instructions. A canister should do this once and cache the result, which it
  /// wants to do anyway.
  ///
  /// `dfx_test_key` is PocketIC-only, matching the reference.
  public func masterPublicKey(source : KeySource, keyName : Text) : ?G2.Affine {
    let hex = switch (source, keyName) {
      case (#Mainnet, "key_1") MAINNET_KEY_1;
      case (#Mainnet, "test_key_1") MAINNET_TEST_KEY_1;
      case (#PocketIc, "key_1") POCKETIC_KEY_1;
      case (#PocketIc, "test_key_1") POCKETIC_TEST_KEY_1;
      case (#PocketIc, "dfx_test_key") POCKETIC_DFX_TEST_KEY;
      case _ { return null };
    };
    G2.fromCompressed(Array.toBlob(hexBytes(hex)));
  };

  /// Derives the key belonging to a canister (`utils/mod.rs:392`).
  public func deriveCanisterKey(mpk : G2.Affine, canisterId : [Nat8]) : G2.Affine =
    offsetBy(mpk, canisterId, DS_CANISTER_ID);

  /// Derives a further key under an application context (`utils/mod.rs:486`).
  ///
  /// An empty context returns the key unchanged, as the reference does — so
  /// `deriveSubKey(k, [])` and "no sub-key at all" are the same key, and a
  /// caller cannot accidentally create a second namespace by passing `[]`.
  public func deriveSubKey(key : G2.Affine, context : [Nat8]) : G2.Affine =
    if (context.size() == 0) { key } else { offsetBy(key, context, DS_CONTEXT) };

  /// `key + g2·H(key ‖ input)` — the shared shape of both derivations.
  ///
  /// Adding to the original point rather than replacing it is what makes
  /// derivation one-way: the subnet can produce the matching secret because it
  /// knows the master secret, while knowing a derived public key tells you
  /// nothing about its siblings.
  func offsetBy(point : G2.Affine, input : [Nat8], domainSep : Text) : G2.Affine {
    let serialized = Blob.toArray(G2.toCompressed(point));
    let offset = hashToScalarTwoInputs(serialized, input, domainSep);
    G2.toAffine(
      G2.add(G2.mul(G2.fromAffine(G2.generator), offset), G2.fromAffine(point))
    );
  };

  /// Hashes two inputs to a scalar, each length-prefixed (`utils/mod.rs:262`).
  ///
  /// The prefixes are what make the encoding unambiguous: without them
  /// `("ab", "c")` and `("a", "bc")` would hash identically, and a caller able to
  /// choose one input could shift the boundary to land on another pair's key.
  func hashToScalarTwoInputs(a : [Nat8], b : [Nat8], domainSep : Text) : Scalar.Scalar {
    let combined = Array.flatten<Nat8>([beU64(a.size()), a, beU64(b.size()), b]);
    Scalar.hashToScalar(combined, domainSep);
  };

  /// A length as eight big-endian bytes, matching `(len as u64).to_be_bytes()`.
  func beU64(n : Nat) : [Nat8] =
    Array.tabulate<Nat8>(8, func i = Nat.toNat8((n / (256 ** (7 - i : Nat))) % 256));

  func hexBytes(hex : Text) : [Nat8] {
    let chars = Iter.toArray<Char>(Text.toIter(hex));
    Array.tabulate<Nat8>(
      chars.size() / 2,
      func(i) = Nat.toNat8(hexVal(chars[i * 2]) * 16 + hexVal(chars[i * 2 + 1])),
    );
  };

  func hexVal(c : Char) : Nat {
    let n = Nat32.toNat(Char.toNat32(c));
    if (n >= 48 and n <= 57) { n - 48 } else if (n >= 97 and n <= 102) {
      n - 87;
    } else { 16 };
  };
}
