/// Endpoint guards.
///
/// These live in a module rather than at the top of a mixin on purpose: every
/// bare `let`, `var` or `func` in a `mixin` block is implicitly *stable*, and a
/// function value is not a stable type — so a helper declared there compiles and
/// then traps on the deployed canister with `IC0503`. A module has no such
/// constraint, and the call sites read the same.

import Format "Format";
import Types "../Types";

import Int "mo:core/Int";
import Nat "mo:core/Nat";
import Principal "mo:core/Principal";
import Time "mo:core/Time";

module {
  /// `null` when the caller may proceed, an error when it may not.
  ///
  /// Shaped this way rather than as a `Bool` so a call site reads
  /// `switch (requireController(caller)) { case (?e) return #Err(e); ... }` and
  /// cannot silently ignore the result the way `if (isController(caller))` can.
  public func requireController(caller : Principal) : ?Types.SealedSecretsError =
    if (caller.isController()) { null } else { ?#Unauthorized };

  /// Validates a secret name and maps the failure onto the wire error.
  public func checkName(name : Text) : ?Types.SealedSecretsError =
    switch (Format.validateSecretName(name)) {
      case (#ok) null;
      case (#err(e)) ?#InvalidName(Format.errorText(e));
    };

  /// Wall-clock nanoseconds, as the record timestamps want them.
  public func now() : Nat64 = Int.abs(Time.now()).toNat64();
}
