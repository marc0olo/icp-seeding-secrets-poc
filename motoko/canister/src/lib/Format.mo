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

import Nat "mo:core/Nat";
import Nat8 "mo:core/Nat8";
import Nat32 "mo:core/Nat32";
import Char "mo:core/Char";
import Text "mo:core/Text";
import Blob "mo:core/Blob";
import Iter "mo:core/Iter";

module {
  /// Ciphersuite label, and the version of this protocol.
  ///
  /// Bumping it is a hard break: it changes both the vetKD context (and so the
  /// keypair) and the key label, orphaning every sealed ciphertext.
  public let SUITE_TEXT : Text = "icp-sealed-secrets-v1";

  /// The vetKD `context`: which keypair this canister derives under.
  ///
  /// A constant of the standard, not configuration. The derivation is master key
  /// -> canister id -> context, so the canister id already separates canisters
  /// and the suite already separates sealed secrets from any other use of vetKD
  /// in the same canister. There is nothing left for a client to be told.
  ///
  /// Spelled out as bytes rather than computed because Motoko requires
  /// module-level values to be static expressions and `Text.encodeUtf8` is not
  /// one. `test/Format.test.mo` asserts these agree with the text, so a
  /// transcription slip fails a test rather than silently changing the protocol.
  public let CONTEXT : [Nat8] = [
    0x69, 0x63, 0x70, 0x2d, 0x73, 0x65, 0x61, 0x6c, // icp-seal
    0x65, 0x64, 0x2d, 0x73, 0x65, 0x63, 0x72, 0x65, // ed-secre
    0x74, 0x73, 0x2d, 0x76, 0x31 // ts-v1
  ];

  /// The `input` to `vetkd_derive_key`: which key to derive under that keypair.
  ///
  /// In vetKD terms the IBE identity. Called a *label* because on ICP "identity"
  /// means a caller's principal, and this is neither that nor a key.
  ///
  /// Distinct from `CONTEXT` so the two cannot be confused at a call site, and
  /// deliberately independent of the secret's name: one label serves every
  /// secret, so a single `vetkd_derive_key` unlocks all of them. Per-secret
  /// labels would multiply the cost by N and buy nothing — there is no privilege
  /// boundary inside a canister, since its code can derive the key for any label
  /// whenever it likes.
  public let KEY_LABEL_TEXT : Text = "icp-sealed-secrets-v1.keys";

  public let KEY_LABEL : [Nat8] = [
    0x69, 0x63, 0x70, 0x2d, 0x73, 0x65, 0x61, 0x6c, // icp-seal
    0x65, 0x64, 0x2d, 0x73, 0x65, 0x63, 0x72, 0x65, // ed-secre
    0x74, 0x73, 0x2d, 0x76, 0x31, 0x2e, 0x6b, 0x65, // ts-v1.ke
    0x79, 0x73 // ys
  ];

  /// Fixed overhead `IbeCiphertext` adds: 8-byte header, 32-byte seed, 96-byte
  /// `G2` element.
  public let IBE_OVERHEAD : Nat = 136;

  public let MAX_NAME_LEN : Nat = 64;

  public type FormatError = {
    #EmptyName;
    #NameTooLong : Nat;
    #InvalidNameChar : Char;
  };

  /// Accepts `[A-Za-z0-9_.-]{1,64}`.
  ///
  /// The charset matches environment-variable conventions and, more to the
  /// point, sidesteps the Unicode confusables and normalisation differences an
  /// arbitrary Candid `text` would admit — two names that look identical must
  /// not become two different entries.
  public func validateSecretName(name : Text) : { #ok; #err : FormatError } {
    let bytes = name.encodeUtf8().toArray();
    if (bytes.size() == 0) { return #err(#EmptyName) };
    if (bytes.size() > MAX_NAME_LEN) { return #err(#NameTooLong(bytes.size())) };
    for (c in name.toIter()) {
      if (not isAllowed(c)) { return #err(#InvalidNameChar(c)) };
    };
    #ok;
  };

  func isAllowed(c : Char) : Bool {
    let n = c.toNat32().toNat();
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
      case (#EmptyName) "secret name must not be empty";
      case (#NameTooLong(n)) "secret name is " # n.toText() # " bytes, maximum is " # MAX_NAME_LEN.toText();
      case (#InvalidNameChar(c)) "secret name contains '" # c.toText() # "'; only A-Z a-z 0-9 _ . - are allowed";
    };
  };

  /// Lowercase hex, for logging and for the tests that pin these encodings.
  public func toHex(bytes : [Nat8]) : Text {
    let digits = Text.toIter("0123456789abcdef").toArray();
    var out = "";
    for (b in bytes.vals()) {
      let n = b.toNat();
      out #= digits[n / 16].toText() # digits[n % 16].toText();
    };
    out;
  };
}
