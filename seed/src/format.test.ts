/**
 * Golden vectors, byte-for-byte identical to `rust/core/tests/golden.rs` and
 * `motoko/canister/test/Format.test.mo`.
 *
 * This file is why the three implementations cannot drift: a change to either
 * constant breaks all three suites.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { Principal } from "@icp-sdk/core/principal";

import {
  CONTEXT,
  IBE_OVERHEAD,
  KEY_LABEL,
  MAX_NAME_LEN,
  derivePublicKey,
  toHex,
  validateSecretName,
} from "./format.js";

const TEST_CANISTER = Principal.fromText("bkyz2-fmaaa-aaaaa-qaaaq-cai");

test("context and key label golden vectors", () => {
  assert.equal(toHex(CONTEXT), "6963702d7365616c65642d736563726574732d7631");
  assert.equal(toHex(KEY_LABEL), "6963702d7365616c65642d736563726574732d76312e6b657973");
});

/**
 * They select different things — the context selects the keypair, the label
 * selects a key within it — so they must never be the same bytes.
 */
test("the context and the key label differ", () => {
  assert.notDeepEqual(CONTEXT, KEY_LABEL);
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
  const a = derivePublicKey("mainnet", "key_1", TEST_CANISTER);
  const b = derivePublicKey("mainnet", "key_1", TEST_CANISTER);
  assert.deepEqual(a.publicKeyBytes(), b.publicKeyBytes());
  assert.equal(a.publicKeyBytes().length, 96);
});

/**
 * The trap: mainnet and PocketIC both have a key named `key_1`, backed by
 * different master keys. Choosing the table by key name would silently produce
 * ciphertext nobody can decrypt.
 */
test("the same key name differs across master key sources", () => {
  const mainnet = derivePublicKey("mainnet", "key_1", TEST_CANISTER);
  const pocketic = derivePublicKey("pocketic", "key_1", TEST_CANISTER);
  assert.notDeepEqual(mainnet.publicKeyBytes(), pocketic.publicKeyBytes());
});

test("derivation is bound to the canister", () => {
  const other = Principal.fromText("bd3sg-teaaa-aaaaa-qaaba-cai");
  assert.notDeepEqual(
    derivePublicKey("mainnet", "key_1", TEST_CANISTER).publicKeyBytes(),
    derivePublicKey("mainnet", "key_1", other).publicKeyBytes(),
  );
});

test("unknown key names are rejected rather than guessed", () => {
  assert.throws(() => derivePublicKey("mainnet", "no_such_key", TEST_CANISTER));
  assert.throws(() => derivePublicKey("mainnet", "dfx_test_key", TEST_CANISTER));
});

test("IBE overhead constant matches the Rust side", () => {
  assert.equal(IBE_OVERHEAD, 136);
});
