/// What an IBE decryption actually costs, against the 40B update budget.

import Bench "mo:bench";
import G1 "../src/G1";
import Ibe "../src/Ibe";
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
    bench.name("IBE decryption");
    bench.description("The operation a canister performs to read a sealed secret.");
    bench.rows(["decrypt"]);
    bench.cols(["1"]);

    let VETKEY = "887e66122b2ab97ad8ade759ec0d80a395b889f990fb3623d3a9d27c5a825a7b5f5693664b2e15137015640041341558";
    let CIPHERTEXT = "4943204942450001acb3eb5f0f0f8e8026deca9ee0d9616df6cb80afcff012cd67427b6ce233e2829233d93b0ffbbcc23ef7f80e3928c43c0a6be487f9bfc88b4722c19e83e0abc441ca9799d84c50103d43d8f893624bd593b708cdd54e8be53825d738f8592b306a7913b4bf582dfef541fba06bc05df63134ee224ea732b1fb715073e9a44e6b0bbe03639e88526c7352dac8a09c95";

    let key = switch (G1.fromCompressed(Array.toBlob(hexBytes(VETKEY)))) {
      case (?p) p;
      case null G1.affineIdentity;
    };
    let ct = switch (Ibe.deserialize(hexBytes(CIPHERTEXT))) {
      case (?c) c;
      case null { assert false; loop {} };
    };

    bench.runner(func(_row, _col) { ignore Ibe.decrypt(ct, key) });
    bench;
  };
}
