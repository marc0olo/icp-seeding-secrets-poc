/// Candid types on the wire.
///
/// Mirrors `rust/canister/src/types.rs` field for field, so one client can drive
/// either canister. This interface is a starting proposal for discussion, not a
/// frozen standard.

module {
  /// Everything a client needs to seal a secret for this canister, and to check
  /// it is sealing to the right key.
  public type SealedSecretInfo = {
    /// Version of this interface. Currently 1.
    standard_version : Nat32;
    /// The exact vetKD `context` bytes this canister derives under.
    context : Blob;
    /// The exact key-label bytes for the current epoch — the vetKD `input`,
    /// i.e. the IBE identity every secret here is sealed to.
    key_label : Blob;
    /// The current epoch. New seals must target this value.
    epoch : Nat32;
    /// The vetKD key name, e.g. `key_1`.
    key_name : Text;
    /// The 96-byte derived public key to encrypt to.
    ///
    /// A client must treat this as a *cross-check* against its own offline
    /// derivation, never as the key to encrypt to. This reply crosses boundary
    /// nodes, so trusting it would let anyone able to tamper with it substitute
    /// a key they control.
    public_key : Blob;
    /// Largest ciphertext this canister will accept.
    max_ciphertext_len : Nat64;
    /// Largest number of secrets this canister will hold.
    max_secrets : Nat64;
  };

  /// One stored secret, as reported by `list`.
  ///
  /// Carries nothing derived from the plaintext: a digest of the plaintext would
  /// be an offline guessing oracle for low-entropy secrets, whereas a digest of
  /// a randomised ciphertext reveals nothing.
  public type SealedSecretEntry = {
    name : Text;
    /// The epoch its ciphertext was sealed under.
    epoch : Nat32;
    /// Increments on every overwrite.
    revision : Nat64;
    ciphertext_len : Nat64;
    /// SHA-256 of the ciphertext, so a client can confirm its upload landed.
    ciphertext_sha256 : Blob;
    created_at_ns : Nat64;
    updated_at_ns : Nat64;
  };

  /// Typed errors, so tooling can branch on the cause rather than parse prose.
  public type SealedSecretsError = {
    #Unauthorized;
    #NotFound;
    /// Empty, too long, or characters outside `[A-Za-z0-9_.-]`.
    #InvalidName : Text;
    /// Not a well-formed IBE ciphertext, or does not decrypt under this
    /// canister's key — most often a wrong context, epoch or key id.
    #InvalidCiphertext : Text;
    #TooLarge : { max : Nat64 };
    #TooMany : { max : Nat64 };
    /// The subnet could not derive the key. Usually means this subnet holds no
    /// NI-DKG transcript for the requested vetKD key.
    #VetKdUnavailable : { key_name : Text; detail : Text };
    #Internal : Text;
  };

  public type Result<T> = { #Ok : T; #Err : SealedSecretsError };
}
