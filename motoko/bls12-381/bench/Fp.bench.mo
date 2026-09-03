/// Measures the field operations against the canister instruction budget.
///
/// This exists to answer one question before any more of the port is written:
/// **can a BLS12-381 pairing fit in a Motoko canister call?**
///
/// The budget is 40 billion instructions for an update message and 5 billion for
/// a query (`ic/rs/config/src/subnet_config.rs`, `MAX_INSTRUCTIONS_PER_MESSAGE`
/// and `MAX_INSTRUCTIONS_PER_QUERY_MESSAGE`). A pairing costs on the order of
/// 25,000–30,000 base-field multiplications — roughly 64 Miller-loop iterations
/// over `Fp12`, where one `Fp12` multiplication is itself tens of `Fp`
/// multiplications, plus a final exponentiation of similar magnitude.
///
/// So the number that matters is the per-multiplication cost measured here,
/// multiplied by ~30,000. If that lands under 40 billion, the representation is
/// viable and the rest of the port is ordinary work. If it does not, the limb
/// representation the Rust reference uses is the fallback, and these vectors are
/// what would make that port safe.

import Bench "mo:bench";
import Fp "../src/Fp";

module {
  public func init() : Bench.Bench {
    let bench = Bench.Bench();

    bench.name("BLS12-381 base field");
    bench.description(
      "Per-operation cost against the 40B-instruction update budget. A pairing " #
      "needs roughly 30,000 multiplications."
    );

    bench.rows(["mul", "square", "add", "inverse", "sqrt"]);
    bench.cols(["1", "100"]);

    // Two real field elements: the G1 generator's coordinates.
    let x : Fp.Fp = 3685416753713387016781088315183077757961620795782546409894578378688607592378376318836054947676345821548104185464507;
    let y : Fp.Fp = 1339506544944476473020471379941921221584933875938349620426543736416511423956333506472724655353366534992391756441569;

    bench.runner(
      func(row, col) {
        let n = if (col == "1") { 1 } else { 100 };
        var i = 0;
        while (i < n) {
          switch (row) {
            case ("mul") { ignore Fp.mul(x, y) };
            case ("square") { ignore Fp.square(x) };
            case ("add") { ignore Fp.add(x, y) };
            case ("inverse") { ignore Fp.inverse(x) };
            case ("sqrt") { ignore Fp.sqrt(Fp.square(y)) };
            case (_) {};
          };
          i += 1;
        };
      }
    );

    bench;
  };
}
