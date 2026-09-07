/// Persisted state: configuration and the sealed ciphertexts.
///
/// Mirrors `rust/canister/src/store.rs`, with one structural difference. There,
/// `Config` and `SealedRecord` need `Storable` implementations that encode
/// themselves to bytes for `StableBTreeMap`. Under Motoko's enhanced orthogonal
/// persistence there is nothing to encode — these are ordinary records that the
/// runtime keeps as they are.

import Map "mo:core/Map";

module {
  /// Configuration pinned at first init: the vetKD key name, and nothing else.
  ///
  /// Everything else about the derivation is a constant of the standard — see
  /// `lib/Format.mo`. The key name cannot be, since mainnet and a local network
  /// both have a `key_1` backed by different master keys, and only the deployer
  /// knows which network this is.
  ///
  /// Kept across upgrades rather than re-read from the install argument, which
  /// matches the Rust canister's `StableCell::init`: editing the constant in
  /// source and upgrading is a silent no-op, deliberately, so that an upgrade
  /// cannot change the derivation under stored secrets.
  public type Config = {
    keyName : Text;
  };

  public func defaultConfig(keyName : Text) : Config = {
    keyName = if (keyName == "") { "key_1" } else { keyName };
  };

  /// One secret at rest.
  ///
  /// **Holds the plaintext, not the ciphertext.** The secret arrives sealed and
  /// is decrypted once, at `set`, after which the ciphertext is discarded and
  /// only its digest is kept.
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
    /// The decrypted secret.
    plaintext : Blob;
  };

  public type Secrets = Map.Map<Text, SealedRecord>;

  public func emptySecrets() : Secrets = Map.empty();
}
