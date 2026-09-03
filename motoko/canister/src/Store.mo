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

  /// One secret at rest.
  ///
  /// **Holds the plaintext, not the ciphertext.** The secret arrives sealed and
  /// is decrypted once, at `set`, after which the ciphertext is discarded and
  /// only its digest and length are kept.
  ///
  /// Sealing protects the secret *in transit* — it never appears in an ingress
  /// message, a Candid argument, shell history or a CI log. It was never what
  /// protects it at rest: the plaintext reaches the heap the moment the canister
  /// uses the secret, and the heap is replicated state, checkpointed to disk on
  /// every node. Only SEV-SNP moves "node operators can read this" to "cannot".
  ///
  /// What storing the plaintext buys, in exchange: the secret survives the
  /// subnet losing its vetKD key, where a stored ciphertext would be unreadable
  /// forever. And it removes the plaintext cache along with every staleness
  /// question that came with it.
  public type SealedRecord = {
    /// Epoch the secret was sealed under, recorded for `list`.
    epoch : Nat32;
    /// Increments on overwrite.
    revision : Nat64;
    createdAtNs : Nat64;
    updatedAtNs : Nat64;
    /// SHA-256 of the submitted ciphertext, so a client can still confirm its
    /// upload landed byte for byte.
    ///
    /// A digest of a *randomised* ciphertext reveals nothing about the
    /// plaintext, which is why it stays safe to expose where a digest of the
    /// plaintext would be an offline guessing oracle for a low-entropy secret.
    ciphertextSha256 : Blob;
    /// Length of the submitted ciphertext, for `list`.
    ciphertextLen : Nat64;
    /// The decrypted secret.
    plaintext : Blob;
  };

  public type Secrets = Map.Map<Text, SealedRecord>;

  public func emptySecrets() : Secrets = Map.empty<Text, SealedRecord>();
}
