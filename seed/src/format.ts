/**
 * Wire format, mirroring `rust/core/src/lib.rs`.
 *
 * The two implementations are kept in step by the golden vectors in
 * `format.test.ts`, which are byte-for-byte the same values asserted by the Rust
 * tests in `rust/core/tests/golden.rs`. If you change an encoding, both sets
 * must be updated together — and every previously sealed ciphertext becomes
 * undecryptable, so don't.
 */

import { MasterPublicKey, MasterPublicKeyId, PocketIcMasterPublicKeyId } from "@icp-sdk/vetkeys";
import type { DerivedPublicKey } from "@icp-sdk/vetkeys";
import type { Principal } from "@icp-sdk/core/principal";

/**
 * Ciphersuite label, and the version of this protocol. Changing it is a hard
 * break: every previously sealed ciphertext becomes undecryptable.
 */
export const SUITE_TEXT = "icp-sealed-secrets-v1";

/**
 * The vetKD `context`: which keypair the canister derives under.
 *
 * A constant of the standard, not configuration. The derivation is master key ->
 * canister id -> context, so the canister id already separates canisters and the
 * suite already separates sealed secrets from any other use of vetKD in the same
 * canister.
 */
export const CONTEXT = new TextEncoder().encode(SUITE_TEXT);

/**
 * The `input` to `vetkd_derive_key`: which key to derive under that keypair.
 *
 * In vetKD terms the IBE identity. Called a *label* because on ICP "identity"
 * means a caller's principal, and this is neither that nor a key.
 *
 * Distinct from `CONTEXT` so the two cannot be confused at a call site, and
 * deliberately independent of the secret's name: one label serves every secret,
 * so a single `vetkd_derive_key` unlocks all of them.
 */
export const KEY_LABEL = new TextEncoder().encode("icp-sealed-secrets-v1.keys");

/** Fixed IBE overhead: 8-byte header + 32-byte seed + 96-byte G2 element. */
export const IBE_OVERHEAD = 136;

export const MAX_NAME_LEN = 64;

/**
 * Which table of hardcoded master public keys to derive from.
 *
 * Deliberately explicit rather than inferred from the key name: mainnet and
 * PocketIC both have a `key_1`, and their master public keys differ. Guessing
 * wrong produces a ciphertext the canister cannot decrypt — which `set` catches,
 * because it decrypts before storing.
 */
export type MasterKeySource = "mainnet" | "pocketic";

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
 * No network call, and nothing to trust: a master public key shipped in the
 * vetKeys library, plus the canister id, plus the context.
 */
export function derivePublicKey(
  source: MasterKeySource,
  keyName: string,
  canisterId: Principal,
): DerivedPublicKey {
  const master =
    source === "mainnet"
      ? MasterPublicKey.productionKey(masterKeyId(keyName))
      : MasterPublicKey.pocketicKey(pocketIcKeyId(keyName));

  return master.deriveCanisterKey(canisterId.toUint8Array()).deriveSubKey(CONTEXT);
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
