/// Persisted state: configuration and the sealed ciphertexts.
///
/// Mirrors `rust/canister/src/store.rs`, with one structural difference. There,
/// `Config` and `SealedRecord` need `Storable` implementations that encode
/// themselves to bytes for `StableBTreeMap`. Under Motoko's enhanced orthogonal
/// persistence there is nothing to encode — these are ordinary records that the
/// runtime keeps as they are.

import Map "mo:core/Map";

module {
  /// 4 KiB, i.e. roughly 3.9 KiB of plaintext once IBE's fixed 136-byte overhead
  /// is deducted — comfortably covering API keys, tokens and small PEMs.
  public let DEFAULT_MAX_CIPHERTEXT_LEN : Nat64 = 4096;

  /// Bounds the cost of `selfTest` and the size of a `list` response.
  public let DEFAULT_MAX_SECRETS : Nat64 = 256;

  /// Configuration pinned at first init.
  ///
  /// Kept across upgrades rather than re-read from the install argument, which
  /// matches the Rust canister's `StableCell::init`. The consequence is the same
  /// in both: editing a constant in source and upgrading is a silent no-op,
  /// which is why `selfTest` reports the *effective* config read back from here
  /// rather than whatever the source says.
  public type Config = {
    keyName : Text;
    epoch : Nat32;
    maxCiphertextLen : Nat64;
    maxSecrets : Nat64;
  };

  public func defaultConfig(keyName : Text) : Config = {
    keyName = if (keyName == "") { "key_1" } else { keyName };
    epoch = 0;
    maxCiphertextLen = DEFAULT_MAX_CIPHERTEXT_LEN;
    maxSecrets = DEFAULT_MAX_SECRETS;
  };

  /// One sealed secret at rest.
  public type SealedRecord = {
    /// Epoch the ciphertext was sealed under.
    ///
    /// Held per record so bumping the epoch does not invalidate existing
    /// secrets: the canister simply derives one extra vetKey per distinct epoch
    /// still in use.
    epoch : Nat32;
    /// Increments on overwrite. Part of the plaintext cache key, so a new seal
    /// invalidates the cached plaintext automatically.
    revision : Nat64;
    createdAtNs : Nat64;
    updatedAtNs : Nat64;
    ciphertextSha256 : Blob;
    ciphertext : Blob;
  };

  public type Secrets = Map.Map<Text, SealedRecord>;

  public func emptySecrets() : Secrets = Map.empty<Text, SealedRecord>();
}
