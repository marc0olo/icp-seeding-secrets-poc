/**
 * Encrypts a secret for a canister and writes the Candid argument that sends it.
 *
 *   1. Derive the canister's public key OFFLINE — a master public key shipped in
 *      the vetKeys library, plus the canister id, plus the context. Pure
 *      arithmetic: no network call, nothing to trust.
 *   2. Encrypt the secret to it.
 *
 * Then it stops, because sending is a separate concern with a separate
 * requirement. Nothing here needs your identity: no key of yours goes into a
 * ciphertext, so anyone can produce one for this canister and only the canister
 * can open it. The call that follows is what needs a signature, from a
 * controller. `scripts/seal` runs both steps.
 *
 * Run it twice and you get different bytes — IBE is randomised — but both open
 * to the same secret.
 *
 * The value comes from the environment, never argv: argv is visible to anyone
 * who can run `ps`, lands in shell history, and is echoed into CI logs.
 */

import { Principal } from "@icp-sdk/core/principal";
import {
  IbeCiphertext,
  IbeIdentity,
  IbeSeed,
  MasterPublicKey,
  MasterPublicKeyId,
  PocketIcMasterPublicKeyId,
} from "@icp-sdk/vetkeys";
import { writeFileSync } from "node:fs";

/**
 * The two constants that must match the canister byte for byte.
 *
 * `CONTEXT` selects the **keypair**. The derivation is master key -> canister id
 * -> context, so a different context is a different keypair entirely. One per
 * purpose: a canister using vetKD for two unrelated things gives each its own.
 *
 * `SECRET_NAME` names which secret this is — a label, not a key and not the
 * value. In vetKD terms it is the IBE identity the secret is sealed to, and the
 * `input` the canister passes to `vetkd_derive_key`. One label here, because
 * there is one secret.
 *
 * Get either wrong and encryption still succeeds. You find out when the canister
 * cannot decrypt, which is why `set_dummy_secret` decrypts immediately rather
 * than storing the blob and hoping.
 *
 * See rust/canister/src/lib.rs.
 */
const CONTEXT = new TextEncoder().encode("dummy-secret-poc");
const SECRET_NAME = new TextEncoder().encode("dummy-secret");

const USAGE = `
Encrypt a secret for a canister, and print the call argument.

  DUMMY_SECRET=<value> npm run seal -- --canister <id> [options]

  --canister <id>   Target canister id.
  --out <path>      Write the Candid argument here instead of stdout.
  --key-name <n>    vetKD key. Default key_1
  --source <which>  mainnet | pocketic. Default pocketic.
                    NOT inferable from the key name: both networks have a
                    key_1, backed by different master keys.

Then send it as a controller of the canister. scripts/seal does both steps:

  DUMMY_SECRET=<value> ./scripts/seal dummy-secret-rust

Or by hand:

  icp canister call <canister> set_dummy_secret --args-file <path> -e local
`.trim();

function arg(flag: string, fallback?: string): string {
  const i = process.argv.indexOf(flag);
  const value = i === -1 ? fallback : process.argv[i + 1];
  if (value === undefined) {
    console.error(`error: ${flag} is required\n\n${USAGE}`);
    process.exit(1);
  }
  return value;
}

/**
 * Step 1: the canister's public key, computed here, offline.
 *
 * `--source` cannot be inferred from the key name. Mainnet and a local network
 * each have a key called `key_1` backed by a *different* master key —
 * necessarily, since a local network cannot hold mainnet's master secret. Guess
 * wrong and you get a ciphertext nobody can ever open, with no error until the
 * canister tries.
 */
function derivePublicKey(source: string, keyName: string, canisterId: Principal) {
  const master =
    source === "mainnet"
      ? MasterPublicKey.productionKey(
          keyName === "test_key_1" ? MasterPublicKeyId.TEST_KEY_1 : MasterPublicKeyId.KEY_1,
        )
      : MasterPublicKey.pocketicKey(
          keyName === "test_key_1"
            ? PocketIcMasterPublicKeyId.TEST_KEY_1
            : PocketIcMasterPublicKeyId.KEY_1,
        );

  return master.deriveCanisterKey(canisterId.toUint8Array()).deriveSubKey(CONTEXT);
}

/** Candid text for a blob: every byte escaped, so quoting can never surprise. */
function candidBlob(bytes: Uint8Array): string {
  const escaped = Array.from(bytes, (b) => `\\${b.toString(16).padStart(2, "0")}`).join("");
  return `(blob "${escaped}")`;
}

function main() {
  if (process.argv.includes("--help")) {
    console.log(USAGE);
    return;
  }

  const canisterId = Principal.fromText(arg("--canister"));
  const keyName = arg("--key-name", "key_1");
  const source = arg("--source", "pocketic");
  const out = arg("--out", "");

  const secret = process.env.DUMMY_SECRET;
  if (!secret) {
    console.error(
      "error: DUMMY_SECRET is unset.\n" +
        "       Set it in your shell, e.g.  export DUMMY_SECRET=super-secret-value\n" +
        "       (read from the environment on purpose — a --value flag would\n" +
        "        land in shell history and CI logs)",
    );
    process.exit(1);
  }

  // 1. offline — no network call, no identity
  const publicKey = derivePublicKey(source, keyName, canisterId);

  // 2. encrypt
  const ciphertext = IbeCiphertext.encrypt(
    publicKey,
    IbeIdentity.fromBytes(SECRET_NAME),
    new TextEncoder().encode(secret),
    IbeSeed.random(),
  ).serialize();

  const candid = candidBlob(ciphertext);
  if (out) {
    writeFileSync(out, candid);
    console.error(
      `derived ${source}:${keyName} key for ${canisterId.toText()} offline, ` +
        `encrypted ${secret.length} bytes -> ${ciphertext.length}, wrote ${out}`,
    );
  } else {
    console.log(candid);
  }
}

main();
