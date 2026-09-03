/**
 * Wire format, mirroring `crates/core/src/lib.rs`.
 *
 * The two implementations are kept in step by the golden vectors in
 * `format.test.ts`, which are byte-for-byte the same values asserted by the Rust
 * tests in `crates/core/tests/golden.rs`. If you change an encoding, both sets
 * must be updated together — and every previously sealed ciphertext becomes
 * undecryptable, so don't.
 */

import { MasterPublicKey, MasterPublicKeyId, PocketIcMasterPublicKeyId } from "@icp-sdk/vetkeys";
import type { DerivedPublicKey } from "@icp-sdk/vetkeys";
import type { Principal } from "@icp-sdk/core/principal";

/** Ciphersuite label. Changing it is a hard protocol break. */
export const SUITE = new TextEncoder().encode("icp-sealed-secrets-v1");

export const CONTEXT_FORMAT_VERSION = 0x01;
export const IDENTITY_FORMAT_VERSION = 0x01;

/** Fixed IBE overhead: 8-byte header + 32-byte seed + 96-byte G2 element. */
export const IBE_OVERHEAD = 136;

export const MAX_NAME_LEN = 64;
export const MAX_APP_SEPARATOR_LEN = 255;

/**
 * Which table of hardcoded master public keys to derive from.
 *
 * Deliberately explicit rather than inferred from the key name: mainnet and
 * PocketIC both have a `key_1`, and their master public keys differ. Guessing
 * wrong produces a ciphertext nobody can ever decrypt, with no error at seal time.
 */
export type MasterKeySource = "mainnet" | "pocketic";

/**
 * context := 0x01 || u8(len(SUITE)) || SUITE || u8(len(app_separator)) || app_separator
 *
 * Both variable-length fields are length-prefixed so no two distinct
 * (suite, separator) pairs can encode identically.
 */
export function sealedSecretsContext(appSeparator: string): Uint8Array {
  const sep = new TextEncoder().encode(appSeparator);
  if (sep.length > MAX_APP_SEPARATOR_LEN) {
    throw new Error(
      `application domain separator is ${sep.length} bytes, maximum is ${MAX_APP_SEPARATOR_LEN}`,
    );
  }
  const out = new Uint8Array(3 + SUITE.length + sep.length);
  let i = 0;
  out[i++] = CONTEXT_FORMAT_VERSION;
  out[i++] = SUITE.length;
  out.set(SUITE, i);
  i += SUITE.length;
  out[i++] = sep.length;
  out.set(sep, i);
  return out;
}

/**
 * identity := 0x01 || u8(len(SUITE)) || SUITE || be_u32(epoch)
 *
 * Note the absence of the secret's name: one identity serves every secret in a
 * canister, so a single `vetkd_derive_key` unlocks all of them.
 */
export function sealedSecretsIdentity(epoch: number): Uint8Array {
  if (!Number.isInteger(epoch) || epoch < 0 || epoch > 0xffffffff) {
    throw new Error(`epoch must be a uint32, got ${epoch}`);
  }
  const out = new Uint8Array(2 + SUITE.length + 4);
  let i = 0;
  out[i++] = IDENTITY_FORMAT_VERSION;
  out[i++] = SUITE.length;
  out.set(SUITE, i);
  i += SUITE.length;
  new DataView(out.buffer).setUint32(i, epoch, false);
  return out;
}

/** Accepts `[A-Za-z0-9_.-]{1,64}`. */
export function validateSecretName(name: string): void {
  if (name.length === 0) throw new Error("secret name must not be empty");
  if (name.length > MAX_NAME_LEN) {
    throw new Error(`secret name is ${name.length} bytes, maximum is ${MAX_NAME_LEN}`);
  }
  const bad = /[^A-Za-z0-9_.-]/.exec(name);
  if (bad) {
    throw new Error(
      `secret name contains ${JSON.stringify(bad[0])}; only A-Z a-z 0-9 _ . - are allowed`,
    );
  }
}

/**
 * Derives the canister's sealed-secrets public key offline.
 *
 * No network call. This is the value actually encrypted to; anything the canister
 * reports is only ever a cross-check against this.
 */
export function derivePublicKey(
  source: MasterKeySource,
  keyName: string,
  canisterId: Principal,
  context: Uint8Array,
): DerivedPublicKey {
  const master =
    source === "mainnet"
      ? MasterPublicKey.productionKey(masterKeyId(keyName))
      : MasterPublicKey.pocketicKey(pocketIcKeyId(keyName));

  return master.deriveCanisterKey(canisterId.toUint8Array()).deriveSubKey(context);
}

function masterKeyId(keyName: string): MasterPublicKeyId {
  switch (keyName) {
    case "key_1":
      return MasterPublicKeyId.KEY_1;
    case "test_key_1":
      return MasterPublicKeyId.TEST_KEY_1;
    default:
      throw new Error(`no mainnet master public key is compiled in for key "${keyName}"`);
  }
}

function pocketIcKeyId(keyName: string): PocketIcMasterPublicKeyId {
  switch (keyName) {
    case "key_1":
      return PocketIcMasterPublicKeyId.KEY_1;
    case "test_key_1":
      return PocketIcMasterPublicKeyId.TEST_KEY_1;
    case "dfx_test_key":
      return PocketIcMasterPublicKeyId.DFX_TEST_KEY;
    default:
      throw new Error(`no PocketIC master public key is compiled in for key "${keyName}"`);
  }
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}
