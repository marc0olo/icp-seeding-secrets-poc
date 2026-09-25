/// Tests for `Bits`, against the division-based definitions it replaces.

import { test } "mo:test";
import Bits "../src/Bits";
import Fp "../src/Fp";
import Nat "mo:core/Nat";
import Nat8 "mo:core/Nat8";

func fromBits(bits : [Bool]) : Nat {
  var acc : Nat = 0;
  for (bit in bits.vals()) { acc := acc * 2 + (if (bit) { 1 } else { 0 }) };
  acc;
};

let values : [Nat] = [0, 1, 2, 3, 2 ** 63, 2 ** 64 - 1, 2 ** 64, 2 ** 64 + 1, 0xd201_0000_0001_0000, Fp.P, Fp.P - 3, 2 ** 762 - 1];

test(
  "msbFirst round-trips and has no leading zero",
  func() {
    for (n in values.vals()) {
      let bits = Bits.msbFirst(n);
      assert fromBits(bits) == n;
      if (n == 0) { assert bits.size() == 0 } else { assert bits[0] };
    };
  },
);

test(
  "isOdd and byteAt agree with division",
  func() {
    for (n in values.vals()) {
      assert Bits.isOdd(n) == (n % 2 == 1);
      for (shift in Nat.range(0, 48)) {
        assert Bits.byteAt(n, shift * 8).toNat() == (n / 2 ** (shift * 8)) % 256;
      };
    };
  },
);
