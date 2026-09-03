/**
 * Golden vectors, byte-for-byte identical to `crates/core/tests/golden.rs`.
 *
 * This file is the reason the Rust and TypeScript implementations cannot drift:
 * a change to either encoding breaks one of the two suites. Any future Motoko
 * port should assert these same values.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { Principal } from "@icp-sdk/core/principal";

import {
  IBE_OVERHEAD,
  MAX_APP_SEPARATOR_LEN,
  MAX_NAME_LEN,
  SUITE,
  derivePublicKey,
  sealedSecretsContext,
  sealedSecretsIdentity,
  toHex,
  validateSecretName,
} from "./format.js";

const TEST_CANISTER = Principal.fromText("bkyz2-fmaaa-aaaaa-qaaaq-cai");

test("suite label is pinned", () => {
  assert.equal(toHex(SUITE), "6963702d7365616c65642d736563726574732d7631");
  assert.equal(SUITE.length, 21);
});

test("context golden vectors", () => {
  assert.equal(
    toHex(sealedSecretsContext("")),
    "01156963702d7365616c65642d736563726574732d763100",
  );
  assert.equal(
    toHex(sealedSecretsContext("demo")),
    "01156963702d7365616c65642d736563726574732d76310464656d6f",
  );
});

test("identity golden vectors", () => {
  assert.equal(
    toHex(sealedSecretsIdentity(0)),
    "01156963702d7365616c65642d736563726574732d763100000000",
  );
  assert.equal(
    toHex(sealedSecretsIdentity(1)),
    "01156963702d7365616c65642d736563726574732d763100000001",
  );
  assert.equal(
    toHex(sealedSecretsIdentity(0xffffffff)),
    "01156963702d7365616c65642d736563726574732d7631ffffffff",
  );
});

test("context encoding is unambiguous", () => {
  const a = sealedSecretsContext("x");
  const b = sealedSecretsContext("");
  assert.notDeepEqual(a, b);
  assert.equal(a.length, b.length + 1);
});

test("app separator length is bounded", () => {
  assert.doesNotThrow(() => sealedSecretsContext("a".repeat(MAX_APP_SEPARATOR_LEN)));
  assert.throws(() => sealedSecretsContext("a".repeat(MAX_APP_SEPARATOR_LEN + 1)));
});

test("epoch must be a uint32", () => {
  assert.throws(() => sealedSecretsIdentity(-1));
  assert.throws(() => sealedSecretsIdentity(0x1_0000_0000));
  assert.throws(() => sealedSecretsIdentity(1.5));
});

test("secret name validation", () => {
  for (const good of ["A", "DUMMY_API_KEY", "billing.live-key_2", "0", "n".repeat(MAX_NAME_LEN)]) {
    assert.doesNotThrow(() => validateSecretName(good), `rejected ${good}`);
  }
  for (const bad of ["", "n".repeat(MAX_NAME_LEN + 1), "a/b", "a b", "kéy"]) {
    assert.throws(() => validateSecretName(bad), `accepted ${JSON.stringify(bad)}`);
  }
});

test("public key derivation is deterministic and 96 bytes", () => {
  const ctx = sealedSecretsContext("");
  const a = derivePublicKey("mainnet", "key_1", TEST_CANISTER, ctx);
  const b = derivePublicKey("mainnet", "key_1", TEST_CANISTER, ctx);
  assert.deepEqual(a.publicKeyBytes(), b.publicKeyBytes());
  assert.equal(a.publicKeyBytes().length, 96);
});

/**
 * The trap: mainnet and PocketIC both have a key named `key_1`, backed by
 * different master keys. Choosing the table by key name would silently produce
 * ciphertext nobody can decrypt.
 */
test("the same key name differs across master key sources", () => {
  const ctx = sealedSecretsContext("");
  const mainnet = derivePublicKey("mainnet", "key_1", TEST_CANISTER, ctx);
  const pocketic = derivePublicKey("pocketic", "key_1", TEST_CANISTER, ctx);
  assert.notDeepEqual(mainnet.publicKeyBytes(), pocketic.publicKeyBytes());
});

test("derivation is bound to the canister and to the context", () => {
  const other = Principal.fromText("bd3sg-teaaa-aaaaa-qaaba-cai");
  const ctx = sealedSecretsContext("");
  const base = derivePublicKey("mainnet", "key_1", TEST_CANISTER, ctx);

  assert.notDeepEqual(
    base.publicKeyBytes(),
    derivePublicKey("mainnet", "key_1", other, ctx).publicKeyBytes(),
  );
  assert.notDeepEqual(
    base.publicKeyBytes(),
    derivePublicKey("mainnet", "key_1", TEST_CANISTER, sealedSecretsContext("x")).publicKeyBytes(),
  );
});

test("unknown key names are rejected rather than guessed", () => {
  const ctx = sealedSecretsContext("");
  assert.throws(() => derivePublicKey("mainnet", "no_such_key", TEST_CANISTER, ctx));
  assert.throws(() => derivePublicKey("mainnet", "dfx_test_key", TEST_CANISTER, ctx));
});

test("IBE overhead constant matches the Rust side", () => {
  assert.equal(IBE_OVERHEAD, 136);
});
