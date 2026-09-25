/// Byte comparisons.

import Blob "mo:core/Blob";
import Nat8 "mo:core/Nat8";

module {
  /// Whether two byte strings are equal, in time that depends only on their
  /// lengths — the counterpart of `subtle::ConstantTimeEq` in the Rust canister.
  /// `==` on `Blob` makes no such promise.
  public func equalConstantTime(a : Blob, b : Blob) : Bool {
    if (a.size() != b.size()) { return false };
    var diff : Nat8 = 0;
    let ys = b.vals();
    for (x in a.vals()) {
      switch (ys.next()) {
        case (?y) { diff |= x ^ y };
        case null {};
      };
    };
    diff == 0;
  };
}
