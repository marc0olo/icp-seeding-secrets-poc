/// The measurement the whole port was gambling on.
///
/// The README estimated a pairing at ~30,000 field multiplications, so roughly
/// 1.6 billion instructions against the 40 billion an update call gets. This
/// replaces that estimate with the number.

import Bench "mo:bench";
import G1 "../src/G1";
import G2 "../src/G2";
import Pairing "../src/Pairing";

module {
  public func init() : Bench.Bench {
    let bench = Bench.Bench();
    bench.name("BLS12-381 pairing");
    bench.description("Against the 40B-instruction update budget.");
    bench.rows(["millerLoop", "finalExponentiation", "pairing"]);
    bench.cols(["1"]);

    let g1 = G1.generator;
    let g2 = G2.generator;
    let ml = Pairing.millerLoop(g1, g2);

    bench.runner(
      func(row, _col) {
        switch (row) {
          case ("millerLoop") { ignore Pairing.millerLoop(g1, g2) };
          case ("finalExponentiation") { ignore Pairing.finalExponentiation(ml) };
          case ("pairing") { ignore Pairing.pairing(g1, g2) };
          case (_) {};
        };
      }
    );

    bench;
  };
}
