/// The sealed-secrets wire format.
///
/// The Motoko counterpart of `rust/core`. Pure computation — no canister APIs —
/// so it can be tested directly, and so the encodings it produces can be pinned
/// against the same golden vectors the Rust and TypeScript sides assert.
///
/// Those vectors are the contract. If any byte here diverges, this canister
/// derives a different keypair and every ciphertext sealed by the existing
/// TypeScript seeder becomes undecryptable — silently, since a wrong context
/// produces a perfectly well-formed ciphertext that simply never opens.

import Array "mo:core/Array";
import Nat "mo:core/Nat";
import Nat8 "mo:core/Nat8";
import Nat32 "mo:core/Nat32";
import Char "mo:core/Char";
import Text "mo:core/Text";
import Blob "mo:core/Blob";
import Iter "mo:core/Iter";

module {
  /// Ciphersuite label.
  ///
  /// Bumping this is a hard protocol break: it changes both the vetKD context
  /// (and so the keypair) and the IBE identity, orphaning every sealed
  /// ciphertext.
  public let SUITE_TEXT : Text = "icp-sealed-secrets-v1";

  /// `SUITE_TEXT` as bytes.
  ///
  /// Spelled out rather than computed because Motoko requires module-level
  /// values to be static expressions, and `Text.encodeUtf8` is not one.
  /// `test/Format.test.mo` asserts the two agree, so a transcription slip here
  /// fails a test rather than silently changing the protocol.
  public let SUITE : [Nat8] = [
    0x69, 0x63, 0x70, 0x2d, // icp-
    0x73, 0x65, 0x61, 0x6c, 0x65, 0x64, 0x2d, // sealed-
    0x73, 0x65, 0x63, 0x72, 0x65, 0x74, 0x73, 0x2d, // secrets-
    0x76, 0x31 // v1
  ];

  public let CONTEXT_FORMAT_VERSION : Nat8 = 0x01;
  public let IDENTITY_FORMAT_VERSION : Nat8 = 0x01;

  /// Fixed overhead `IbeCiphertext` adds: 8-byte header, 32-byte seed, 96-byte
  /// `G2` element.
  public let IBE_OVERHEAD : Nat = 136;

  public let MAX_NAME_LEN : Nat = 64;
  public let MAX_APP_SEPARATOR_LEN : Nat = 255;

  public type FormatError = {
    #AppSeparatorTooLong : Nat;
    #EmptyName;
    #NameTooLong : Nat;
    #InvalidNameChar : Char;
  };

  /// The vetKD `context`:
  ///
  /// ```text
  /// context := 0x01 || u8(len(SUITE)) || SUITE || u8(len(app_separator)) || app_separator
  /// ```
  ///
  /// Both variable-length fields are length-prefixed, so no two distinct
  /// `(SUITE, app_separator)` pairs encode to the same bytes.
  public func context(appSeparator : Text) : { #ok : [Nat8]; #err : FormatError } {
    let sep = Blob.toArray(Text.encodeUtf8(appSeparator));
    if (sep.size() > MAX_APP_SEPARATOR_LEN) {
      return #err(#AppSeparatorTooLong(sep.size()));
    };
    #ok(
      Array.flatten<Nat8>([
        [CONTEXT_FORMAT_VERSION, Nat.toNat8(SUITE.size())],
        SUITE,
        [Nat.toNat8(sep.size())],
        sep,
      ])
    );
  };

  /// The IBE identity, which is also the `input` to `vetkd_derive_key`:
  ///
  /// ```text
  /// identity := 0x01 || u8(len(SUITE)) || SUITE || be_u32(epoch)
  /// ```
  ///
  /// Note what is *absent*: the secret's name. One identity serves every secret
  /// in the canister, so a single `vetkd_derive_key` call unlocks all of them.
  /// Per-secret identities would multiply that cost by N and buy nothing —
  /// there is no privilege boundary inside a canister, since its code can derive
  /// the key for any identity whenever it likes.
  public func identity(epoch : Nat32) : [Nat8] {
    let e = Nat32.toNat(epoch);
    Array.flatten<Nat8>([
      [IDENTITY_FORMAT_VERSION, Nat.toNat8(SUITE.size())],
      SUITE,
      Array.tabulate<Nat8>(4, func i = Nat.toNat8((e / (256 ** (3 - i : Nat))) % 256)),
    ]);
  };

  /// Accepts `[A-Za-z0-9_.-]{1,64}`.
  ///
  /// The charset matches environment-variable conventions and, more to the
  /// point, sidesteps the Unicode confusables and normalisation differences an
  /// arbitrary Candid `text` would admit — two names that look identical must
  /// not become two different entries.
  public func validateSecretName(name : Text) : { #ok; #err : FormatError } {
    let bytes = Blob.toArray(Text.encodeUtf8(name));
    if (bytes.size() == 0) { return #err(#EmptyName) };
    if (bytes.size() > MAX_NAME_LEN) { return #err(#NameTooLong(bytes.size())) };
    for (c in Text.toIter(name)) {
      if (not isAllowed(c)) { return #err(#InvalidNameChar(c)) };
    };
    #ok;
  };

  func isAllowed(c : Char) : Bool {
    let n = Nat32.toNat(Char.toNat32(c));
    (n >= 48 and n <= 57) // 0-9
    or (n >= 65 and n <= 90) // A-Z
    or (n >= 97 and n <= 122) // a-z
    or n == 95 // _
    or n == 46 // .
    or n == 45 // -
  };

  /// Renders a `FormatError` for a Candid `text` field.
  public func errorText(e : FormatError) : Text {
    switch (e) {
      case (#AppSeparatorTooLong(n)) "application domain separator is " # Nat.toText(n) # " bytes, maximum is " # Nat.toText(MAX_APP_SEPARATOR_LEN);
      case (#EmptyName) "secret name must not be empty";
      case (#NameTooLong(n)) "secret name is " # Nat.toText(n) # " bytes, maximum is " # Nat.toText(MAX_NAME_LEN);
      case (#InvalidNameChar(c)) "secret name contains '" # Char.toText(c) # "'; only A-Z a-z 0-9 _ . - are allowed";
    };
  };

  /// Lowercase hex, for logging and for the tests that pin these encodings.
  public func toHex(bytes : [Nat8]) : Text {
    let digits = Iter.toArray<Char>(Text.toIter("0123456789abcdef"));
    var out = "";
    for (b in bytes.vals()) {
      let n = Nat8.toNat(b);
      out #= Char.toText(digits[n / 16]) # Char.toText(digits[n % 16]);
    };
    out;
  };
}
