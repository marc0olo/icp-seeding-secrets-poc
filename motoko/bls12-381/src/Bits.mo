/// Bit access on `Nat`, through shifts.
///
/// `n % 2` and `n / 2` are general bignum divisions — about 29,000
/// instructions each on a 381-bit value — while `Nat.bitshiftRight` is closer
/// to 3,000. Every exponentiation and scalar multiplication walks its exponent
/// bit by bit, so this is the difference between paying that once per bit or
/// once per 64.

import Array "mo:core/Array";
import List "mo:core/List";
import Nat "mo:core/Nat";
import Nat8 "mo:core/Nat8";
import Nat64 "mo:core/Nat64";

module {
  /// The bits of `n`, most significant first. Empty for zero, so the first
  /// element of a non-empty result is always `true`.
  public func msbFirst(n : Nat) : [Bool] {
    let limbs = List.empty<Nat64>();
    var rest = n;
    while (rest > 0) {
      limbs.add(Nat64.fromIntWrap(rest));
      rest := Nat.bitshiftRight(rest, 64);
    };
    if (limbs.isEmpty()) { return [] };

    let top = limbs.at(limbs.size() - 1 : Nat);
    let width = (limbs.size() - 1 : Nat) * 64 + (64 - Nat64.bitcountLeadingZero(top).toNat() : Nat);
    Array.tabulate(
      width,
      func i {
        let pos = width - 1 - i : Nat;
        (limbs.at(pos / 64) >> Nat.toNat64(pos % 64)) & 1 == 1;
      },
    );
  };

  /// Whether the lowest bit of `n` is set.
  public func isOdd(n : Nat) : Bool = Nat8.fromIntWrap(n) & 1 == 1;

  /// The byte of `n` at bit offset `shift`.
  public func byteAt(n : Nat, shift : Nat) : Nat8 =
    Nat8.fromIntWrap(Nat.bitshiftRight(n, shift.toNat32()));
}
