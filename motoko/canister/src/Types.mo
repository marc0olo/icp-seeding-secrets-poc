/// Candid types on the wire.
///
/// Mirrors `rust/canister/src/types.rs` field for field, so one client can drive
/// either canister. This interface is a starting proposal for discussion, not a
/// frozen standard.

module {
  /// Which table of hardcoded master public keys to check the subnet's answer
  /// against.
  ///
  /// A `selfTest` *argument*, not configuration. The canister obtains its public
  /// key from `vetkd_public_key`, which is authoritative; comparing that against
  /// a constant compiled into this Wasm is an on-demand audit, and the caller is
  /// the one who knows which network they believe they are on.
  public type KeySource = { #Mainnet; #PocketIc };

  /// Everything a client needs to seal a secret for this canister, and to check
  /// it is sealing to the right key.
  public type SealedSecretInfo = {
    /// Version of this interface. Currently 1.
    standard_version : Nat32;
    /// The exact vetKD `context` bytes this canister derives under.
    context : Blob;
    /// The exact IBE identity bytes for the current epoch.
    identity : Blob;
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

  /// The result of `selfTest`: a deploy-time health check that exercises the
  /// whole decryption path, so failures surface here rather than in production.
  public type SelfTestReport = {
    vetkd_public_key_ok : Bool;
    vetkd_derive_ok : Bool;
    /// Whether the subnet's public key matched the master key compiled into this
    /// Wasm, for the `expected_source` the caller supplied. `null` when none was
    /// supplied, or when no master key is compiled in for this key name under
    /// that source.
    ///
    /// This is the one check in the design that is not the subnet vouching for
    /// itself, so a deployment should run it once with the source it expects.
    public_key_matches_master : ?Bool;
    /// The key name actually in use, read from stable state rather than source.
    effective_key_name : Text;
    effective_context : Blob;
    epoch : Nat32;
    num_secrets : Nat64;
    /// Names that failed to decrypt. Should always be empty.
    undecryptable : [Text];
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
