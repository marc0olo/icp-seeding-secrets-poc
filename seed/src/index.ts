/**
 * Seals a secret with vetKD IBE and writes the Candid argument that sends it.
 *
 * Two steps, and it stops after the first:
 *
 *   1. Derive the canister's public key OFFLINE — a master public key shipped in
 *      the vetKeys library, plus the canister id, plus a context that is a
 *      constant of this standard. Pure arithmetic: no network call, nothing to
 *      trust, and it works before the canister has executed an instruction.
 *   2. Encrypt the secret to it, under the name it will be stored as.
 *
 * Sending is a separate concern with a separate requirement. Nothing here needs
 * an identity of yours: no key of yours goes into the ciphertext, so anyone can
 * produce one for this canister and only the canister can open it. The call that
 * follows is what needs a signature, from a controller — and that is
 * `icp canister call`'s job, using the identity you already have configured.
 *
 * Run it twice and you get different bytes — IBE is randomised — but both open
 * to the same secret.
 *
 * **Nothing is verified here, deliberately.** Get `--source` or `--key-name`
 * wrong and this still produces a well-formed ciphertext. That is caught one
 * step later, and caught properly: `icp_sealed_secret_set` decrypts before
 * storing, so a wrong key fails at deploy time in front of the operator rather
 * than at first production use.
 *
 * The value comes from the environment, never argv: argv is visible to anyone
 * who can run `ps`, lands in shell history, and is echoed into CI logs.
 */

import { Principal } from "@icp-sdk/core/principal";
import { IbeCiphertext, IbeIdentity, IbeSeed } from "@icp-sdk/vetkeys";
import { writeFileSync } from "node:fs";

import {
  KEY_LABEL,
  derivePublicKey,
  toHex,
  validateSecretName,
  type MasterKeySource,
} from "./format.js";

const USAGE = `
Seal a secret for a sealed-secrets canister, and write the call argument.

  <NAME>=<value> npm run seal -- --canister <id> --name <NAME> [options]

Required
  --canister <id>   Target canister id.
  --name <NAME>     Secret name, [A-Za-z0-9_.-]{1,64}. A map key in the
                    canister — it is NOT part of any key derivation and never
                    reaches vetKD.

Value source
  --from-env <VAR>  Environment variable holding the value.
                    Defaults to the value of --name.
                    There is deliberately no --value flag: argv is
                    world-readable via ps and is echoed into CI logs.

Derivation
  --key-name <n>    vetKD key. Default key_1. Must match the canister's.
  --source <which>  mainnet | pocketic. Default pocketic.
                    NOT inferable from the key name: both networks have a
                    key_1, backed by different master keys.

Output
  --out <path>      Write the Candid argument here instead of stdout.

Then send it as a controller of the canister. scripts/seal.sh does both steps:

  <NAME>=<value> ./scripts/seal.sh sealed-secrets-rust <NAME>

Or by hand:

  icp canister call <id> icp_sealed_secret_set --args-file <path> -e local

The same argument also drives icp_sealed_secret_matches, which asks "do you
already hold this value?" without either side disclosing it. Both take
(text, blob), so there is no separate flag here — send the same file to the
other method:

  icp canister call <id> icp_sealed_secret_matches --args-file <path> -e local

To see what a canister holds, call it directly — no client needed:

  icp canister call <id> icp_sealed_secret_list '()' -e local
`.trim();

function fail(message: string): never {
  console.error(`error: ${message}`);
  process.exit(1);
}

function arg(flag: string, fallback?: string): string {
  const i = process.argv.indexOf(flag);
  const value = i === -1 ? fallback : process.argv[i + 1];
  if (value === undefined) fail(`${flag} is required\n\n${USAGE}`);
  return value;
}

/** Candid text for (name, blob): every byte escaped, so quoting cannot surprise. */
function candidArgs(name: string, bytes: Uint8Array): string {
  const escaped = Array.from(bytes, (b) => `\\${b.toString(16).padStart(2, "0")}`).join("");
  return `("${name}", blob "${escaped}")`;
}

function main() {
  if (process.argv.includes("--help") || process.argv.includes("-h")) {
    console.log(USAGE);
    return;
  }

  const canisterId = Principal.fromText(arg("--canister"));
  const name = arg("--name");
  const envVar = arg("--from-env", name);
  const keyName = arg("--key-name", "key_1");
  const source = arg("--source", "pocketic") as MasterKeySource;
  const out = arg("--out", "");

  if (source !== "mainnet" && source !== "pocketic") {
    fail(`--source must be "mainnet" or "pocketic", got ${JSON.stringify(source)}`);
  }
  validateSecretName(name);

  const value = process.env[envVar];
  if (value === undefined || value === "") {
    fail(
      `environment variable ${envVar} is unset or empty.\n` +
        `       Set it in your shell, e.g.  export ${envVar}=...\n` +
        `       (read from the environment on purpose — a --value flag would land in shell history and CI logs)`,
    );
  }

  // 1. offline — no network call, no identity
  const publicKey = derivePublicKey(source, keyName, canisterId);

  // 2. encrypt
  const plaintext = new TextEncoder().encode(value);
  const ciphertext = IbeCiphertext.encrypt(
    publicKey,
    IbeIdentity.fromBytes(KEY_LABEL),
    plaintext,
    IbeSeed.random(),
  ).serialize();

  const candid = candidArgs(name, ciphertext);

  // Progress goes to stderr so that stdout is only ever the Candid argument,
  // which is what makes `npm run seal ... > args` work without `--out`.
  console.error(
    `derived ${source}:${keyName} key ${toHex(publicKey.publicKeyBytes()).slice(0, 32)}… ` +
      `for ${canisterId.toText()} offline\n` +
      `encrypted "${name}" (${plaintext.length} bytes → ${ciphertext.length} bytes)`,
  );

  if (out) {
    writeFileSync(out, candid);
    // Deliberately no "now run icp canister call …" hint: scripts/seal.sh does
    // that step itself, where the hint would read as an instruction to repeat it.
    // USAGE above has the command for anyone running this on its own.
    console.error(`wrote ${out}`);
  } else {
    console.log(candid);
  }
}

main();
