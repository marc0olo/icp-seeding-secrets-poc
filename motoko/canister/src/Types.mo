/// Candid types on the wire.
///
/// Mirrors `rust/canister/src/types.rs` field for field, so one client can drive
/// either canister. This interface is a starting proposal for discussion, not a
/// frozen standard.

module {
  /// One stored secret, as reported by `list`.
  ///
  /// Carries nothing derived from the plaintext: a digest of the plaintext would
  /// be an offline guessing oracle for low-entropy secrets, whereas a digest of
  /// a randomised ciphertext reveals nothing.
  public type SealedSecretEntry = {
    name : Text;
    /// Increments on every overwrite.
    revision : Nat64;
    /// SHA-256 of the ciphertext that was submitted, so a client can confirm the
    /// stored value is the one *it* uploaded.
    ///
    /// Not a way to check the value is correct: IBE is randomised, so sealing
    /// the same secret twice gives different digests. That question is
    /// `icp_sealed_secret_matches`.
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
    /// canister's key — most often a wrong key name or master key table.
    #InvalidCiphertext : Text;
    /// The subnet could not derive the key. Usually means this subnet holds no
    /// NI-DKG transcript for the requested vetKD key.
    #VetKdUnavailable : { key_name : Text; detail : Text };
    #Internal : Text;
  };

  public type Result<T> = { #Ok : T; #Err : SealedSecretsError };
}
