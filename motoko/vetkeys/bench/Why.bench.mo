/// Where the instructions actually go in the base field.
///
/// The Rust reference keeps elements in Montgomery form as `[u64; 6]`, so a
/// multiplication is a limb multiply plus a Montgomery reduction — no division.
/// This port stores a plain `Nat` and reduces with `%`, which is a division by a
/// 381-bit modulus.
///
/// This separates the two halves so the difference is measured rather than
/// assumed.

import Bench "mo:bench";
import Fp "../src/Fp";

module {
  public func init() : Bench.Bench {
    let bench = Bench.Bench();
    bench.name("where the cost is");
    bench.description("Multiply versus reduce, 100 iterations each.");
    bench.rows(["mul_then_reduce", "mul_only", "reduce_only", "add"]);
    bench.cols(["100"]);

    let x : Fp.Fp = 3685416753713387016781088315183077757961620795782546409894578378688607592378376318836054947676345821548104185464507;
    let y : Fp.Fp = 1339506544944476473020471379941921221584933875938349620426543736416511423956333506472724655353366534992391756441569;
    // A value the size of a product, so `reduce_only` divides a realistic input.
    let big : Nat = x * y;

    bench.runner(
      func(row, _col) {
        var i = 0;
        while (i < 100) {
          switch (row) {
            case ("mul_then_reduce") { ignore (x * y) % Fp.P };
            case ("mul_only") { ignore x * y };
            case ("reduce_only") { ignore big % Fp.P };
            case ("add") { ignore Fp.add(x, y) };
            case (_) {};
          };
          i += 1;
        };
      }
    );

    bench;
  };
}
