import { test } "mo:test";
import Bytes "../src/lib/Bytes";

test(
  "equalConstantTime agrees with ==",
  func() {
    let cases : [(Blob, Blob)] = [
      ("", ""),
      ("\01", "\01"),
      ("\01", "\02"),
      ("abc", "abd"),
      ("abc", "ab"),
      ("ab", "abc"),
      ("\00\00\00", "\00\00\01"),
    ];
    for ((a, b) in cases.vals()) {
      assert Bytes.equalConstantTime(a, b) == (a == b);
    };
  },
);
