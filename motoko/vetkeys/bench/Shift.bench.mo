/// Is a userland Barrett reduction possible?
///
/// Barrett replaces a division by `P` with two multiplications and two shifts.
/// Motoko `Nat` has no shift operator, so a shift has to be written as division
/// by a power of two — and if that is just as expensive as any other division,
/// the whole approach is a dead end without runtime support.

import Bench "mo:bench";
import Fp "../src/Fp";

module {
  public func init() : Bench.Bench {
    let bench = Bench.Bench();
    bench.name("is a shift cheaper than a reduction?");
    bench.description("100 iterations each.");
    bench.rows(["mod_p", "div_by_power_of_two", "mul"]);
    bench.cols(["100"]);

    let x : Fp.Fp = 3685416753713387016781088315183077757961620795782546409894578378688607592378376318836054947676345821548104185464507;
    let y : Fp.Fp = 1339506544944476473020471379941921221584933875938349620426543736416511423956333506472724655353366534992391756441569;
    let big : Nat = x * y;
    let twoTo381 : Nat = 2 ** 381;

    bench.runner(
      func(row, _col) {
        var i = 0;
        while (i < 100) {
          switch (row) {
            case ("mod_p") { ignore big % Fp.P };
            case ("div_by_power_of_two") { ignore big / twoTo381 };
            case ("mul") { ignore x * y };
            case (_) {};
          };
          i += 1;
        };
      }
    );

    bench;
  };
}
