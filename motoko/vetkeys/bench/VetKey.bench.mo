/// What unwrapping and verifying a vetKD reply costs.
///
/// This is the half the earlier IBE benchmark did not measure, and it is the
/// larger one: `decryptAndVerify` runs two multipairings and a hash-to-curve,
/// where `Ibe.decrypt` runs a single pairing. A canister pays both — the reply
/// must be verified before the ciphertext it unlocks can be trusted — so the
/// sum, not either row alone, is what to compare against the 40B update budget.

import Bench "mo:bench";
import G1 "mo:sealed-secrets-bls/G1";
import G2 "mo:sealed-secrets-bls/G2";
import Scalar "mo:sealed-secrets-bls/Scalar";
import VetKey "../src/VetKey";
import HashToCurve "mo:sealed-secrets-bls/HashToCurve";
import Array "mo:core/Array";
import Nat8 "mo:core/Nat8";
import Char "mo:core/Char";
import Nat32 "mo:core/Nat32";
import Text "mo:core/Text";

module {
  func hexVal(c : Char) : Nat {
    let n = Nat32.toNat(Char.toNat32(c));
    if (n >= 48 and n <= 57) { n - 48 } else if (n >= 97 and n <= 102) {
      n - 87;
    } else { 16 };
  };

  func hexBytes(hex : Text) : [Nat8] {
    let chars = Array.fromIter<Char>(Text.toIter(hex));
    Array.tabulate<Nat8>(
      chars.size() / 2,
      func(i) = Nat8.fromNat(hexVal(chars[i * 2]) * 16 + hexVal(chars[i * 2 + 1])),
    );
  };

  public func init() : Bench.Bench {
    let bench = Bench.Bench();
    bench.name("vetKey unwrapping");
    bench.description("Verifying the subnet's reply, and the hash-to-curve inside it.");
    bench.rows(["hashToCurve", "decryptAndVerify"]);
    bench.cols(["1"]);

    let TSK_BE = "167b736e44a1c134bd46ca834220c75c186768612568ac264a01554c46633e76";
    let DPK = "972c4c6cc184b56121a1d27ef1ca3a2334d1a51be93573bd18e168f78f8fe15ce44fb029ffe8e9c3ee6bea2660f4f35e0774a35a80d6236c050fd8f831475b5e145116d3e83d26c533545f64b08464e4bcc755f990a381efa89804212d4eef5f";
    let EK = "b1a13757eaae15a3c8884fc1a3453f8a29b88984418e65f1bd21042ce1d6809b2f8a49f7326c1327f2a3921e8ff1d6c3adde2a801f1f88de98ccb40c62e366a279e7aec5875a0ce2f2a9f3e109d9cb193f0197eadb2c5f5568ee4d6a87e115910662e01e604087246be8b081fc6b8a06b4b0100ed1935d8c8d18d9f70d61718c5dba23a641487e72b3b25884eeede8feb3c71599bfbcebe60d29408795c85b4bdf19588c034d898e7fc513be8dbd04cac702a1672f5625f5833d063b05df7503";
    let IDENTITY = "6d657373616765";

    let tsk = switch (Scalar.fromBytes(hexBytes(TSK_BE))) {
      case (?s) s;
      case null { assert false; loop {} };
    };
    let dpk = switch (G2.fromCompressed(Array.toBlob(hexBytes(DPK)))) {
      case (?p) p;
      case null { assert false; loop {} };
    };
    let ek = switch (VetKey.deserialize(hexBytes(EK))) {
      case (?k) k;
      case null { assert false; loop {} };
    };
    let identity = hexBytes(IDENTITY);

    bench.runner(
      func(row, _col) {
        switch (row) {
          case ("hashToCurve") ignore VetKey.augmentedHashToG1(dpk, identity);
          case (_) ignore VetKey.decryptAndVerify(ek, tsk, dpk, identity);
        };
      }
    );
    bench;
  };
}
