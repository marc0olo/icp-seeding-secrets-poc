/**
 * Seals a secret with vetKD IBE and writes the Candid argument that sends it.
 *
 * The flow, and why each step is in that order:
 *
 *   1. Ask the canister what it uses — key name, context, identity, epoch, and
 *      the public key it believes it has.
 *   2. Preflight the subnet: are its nodes SEV-SNP? That is what protects the
 *      plaintext once the canister decrypts it.
 *   3. Derive the public key OFFLINE from a master key constant we ship, and
 *      abort unless it equals what the canister reported. The reported value is
 *      never used for encryption — only as a cross-check. Trusting it would let
 *      anyone able to tamper with that reply substitute a key they control.
 *   4. Encrypt to the key WE derived, and write the call argument.
 *
 * Then it stops, because **sending is a separate concern with a separate
 * requirement**. Nothing up to here needs an identity of yours: no key of yours
 * goes into the ciphertext, so anyone can produce one for this canister and only
 * the canister can open it. The call that follows is what needs a signature,
 * from a controller — and that is `icp canister call`'s job, using the identity
 * you already have configured. So this script never asks you to export a private
 * key. `scripts/seal.sh` runs both steps.
 *
 * With `--verify`, step 4 writes the argument for `icp_sealed_secret_matches`
 * instead of `icp_sealed_secret_set`, which answers whether the canister already
 * holds this value without either side disclosing it.
 *
 * The value is read from an environment variable and never from argv: argv is
 * world-readable via `ps`, lands in shell history, and is echoed into CI logs.
 */

import { HttpAgent, Actor, AnonymousIdentity } from "@icp-sdk/core/agent";
import { Principal } from "@icp-sdk/core/principal";
import { IbeCiphertext, IbeIdentity, IbeSeed, DerivedPublicKey } from "@icp-sdk/vetkeys";
import { writeFileSync } from "node:fs";

import { idlFactory, type _SERVICE } from "./declarations/sealed_secrets_canister.did.js";
import { evaluatePreflight, inspectSubnet } from "./preflight.js";
import {
  bytesEqual,
  derivePublicKey,
  sealedSecretsContext,
  sealedSecretsKeyLabel,
  toHex,
  validateSecretName,
  type MasterKeySource,
} from "./format.js";

interface Options {
  canisterId: string;
  name: string;
  envVar: string;
  host: string;
  out: string;
  source: MasterKeySource;
  verify: boolean;
  allowUnverifiedSev: boolean;
}

const USAGE = `
Seal a secret for a sealed-secrets canister, and write the call argument.

  <NAME>=<value> seal --canister <id> --name <NAME> [options]

Required
  --canister <id>        Target canister id.
  --name <NAME>          Secret name, [A-Za-z0-9_.-]{1,64}.

Value source
  --from-env <VAR>       Environment variable holding the value.
                         Defaults to the value of --name.
                         There is deliberately no --value flag: argv is
                         world-readable via ps and is echoed into CI logs.

Connection
  --host <url>           Replica URL. Default http://127.0.0.1:8000
                         Read-only: this script calls icp_sealed_secret_info,
                         which is not controller-gated, so it connects
                         anonymously and never needs an identity of yours.

Output
  --out <path>           Write the Candid argument here instead of stdout.

Derivation
  --source <which>       mainnet | pocketic. Default pocketic.
                         NOT inferable from the key name: mainnet and PocketIC
                         each have a key_1 with a different master key.

Escape hatches
  --allow-unverified-sev Proceed although the subnet is not confirmed SEV-SNP.
                         Required locally, where PocketIC reports sev_enabled
                         for no subnet. On mainnet this means node operators can
                         read the plaintext once the canister decrypts it.
  --local                Alias for --allow-unverified-sev, for local runs.
  --verify               Produce the argument for icp_sealed_secret_matches
                         instead of icp_sealed_secret_set — "do you already hold
                         this value?", answered without either side disclosing it.

Then send it as a controller of the canister. scripts/seal.sh does both steps:

  <NAME>=<value> ./scripts/seal.sh sealed-secrets-rust <NAME>

Or by hand:

  icp canister call <id> icp_sealed_secret_set --args-file <path> -e local

To read what a canister holds, call it directly — no client needed:

  icp canister call <id> icp_sealed_secret_list '()' -e local
`.trim();

function parseArgs(argv: string[]): Options {
  const get = (flag: string): string | undefined => {
    const i = argv.indexOf(flag);
    return i === -1 ? undefined : argv[i + 1];
  };
  const has = (flag: string) => argv.includes(flag);

  if (has("--help") || has("-h") || argv.length === 0) {
    console.log(USAGE);
    process.exit(0);
  }

  const canisterId = get("--canister");
  if (!canisterId) fail("--canister is required");

  const name = get("--name");
  if (!name) fail("--name is required");

  const source = (get("--source") ?? "pocketic") as MasterKeySource;
  if (source !== "mainnet" && source !== "pocketic") {
    fail(`--source must be "mainnet" or "pocketic", got ${JSON.stringify(source)}`);
  }

  return {
    canisterId: canisterId!,
    name: name!,
    envVar: get("--from-env") ?? name!,
    host: get("--host") ?? "http://127.0.0.1:8000",
    out: get("--out") ?? "",
    source,
    verify: has("--verify"),
    allowUnverifiedSev: has("--allow-unverified-sev") || has("--local"),
  };
}

function fail(message: string): never {
  console.error(`error: ${message}`);
  process.exit(1);
}

/** Candid `variant { Ok; Err }` decodes to `{ Ok: T } | { Err: E }`. */
function unwrap<T>(result: { Ok: T } | { Err: unknown }, what: string): T {
  if ("Ok" in result) return result.Ok;
  fail(`${what} failed: ${JSON.stringify(result.Err, bigintReplacer)}`);
}

function bigintReplacer(_key: string, value: unknown) {
  return typeof value === "bigint" ? value.toString() : value;
}

/** Candid text for (name, blob): every byte escaped, so quoting cannot surprise. */
function candidArgs(name: string, bytes: Uint8Array): string {
  const escaped = Array.from(bytes, (b) => `\\${b.toString(16).padStart(2, "0")}`).join("");
  return `("${name}", blob "${escaped}")`;
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  const canisterId = Principal.fromText(opts.canisterId);

  // Anonymous on purpose. Everything this script reads is ungated, and nothing
  // it writes is sent from here — see the module comment.
  const agent = await HttpAgent.create({ host: opts.host, identity: new AnonymousIdentity() });
  if (!opts.host.includes("icp-api.io") && !opts.host.includes("ic0.app")) {
    // Local and test networks have their own root key.
    await agent.fetchRootKey();
  }

  const actor = Actor.createActor<_SERVICE>(idlFactory, { agent, canisterId });

  validateSecretName(opts.name);

  const value = process.env[opts.envVar];
  if (value === undefined || value === "") {
    fail(
      `environment variable ${opts.envVar} is unset or empty.\n` +
        `       Set it in your shell, e.g.  export ${opts.envVar}=...\n` +
        `       (read from the environment on purpose — a --value flag would land in shell history and CI logs)`,
    );
  }

  // ---------------------------------------------- 1. what does the canister use?
  const info = unwrap(await actor.icp_sealed_secret_info(), "icp_sealed_secret_info");
  // The application domain separator is always empty in this PoC; it stays in
  // the wire format only so it can be adopted later without a format break.
  const context = sealedSecretsContext("");
  const epoch = Number(info.epoch);

  // ------------------------------------------------------------- 2. preflight
  const check = await inspectSubnet(agent, canisterId);
  const preflight = evaluatePreflight(check, {
    allowUnverifiedSev: opts.allowUnverifiedSev,
  });
  console.error("preflight");
  for (const line of preflight.lines) console.error(`  ${line}`);
  if (!preflight.ok) {
    fail(
      "subnet preflight failed; refusing to seal.\n" +
        "       For a local network, pass --local (or --allow-unverified-sev).",
    );
  }

  // --------------------------------------------- 3. derive offline, then check
  const derived = derivePublicKey(opts.source, info.key_name, canisterId, context);
  const derivedBytes = derived.publicKeyBytes();
  const reported = Uint8Array.from(info.public_key);

  console.error("\nkey derivation");
  console.error(`  source    ${opts.source}:${info.key_name}`);
  console.error(`  context   ${toHex(context)}`);
  console.error(`  identity  ${toHex(sealedSecretsKeyLabel(epoch))}  (epoch ${epoch})`);
  console.error(`  derived   ${toHex(derivedBytes).slice(0, 32)}…`);

  if (!bytesEqual(context, Uint8Array.from(info.context))) {
    fail(
      "the canister derives under a different context than we computed.\n" +
        `       ours:    ${toHex(context)}\n` +
        `       theirs:  ${toHex(Uint8Array.from(info.context))}\n` +
        "       The canister and this client disagree on the wire format.",
    );
  }

  if (!bytesEqual(derivedBytes, reported)) {
    fail(
      "the canister reported a different public key than we derived. REFUSING TO ENCRYPT.\n" +
        `       ours:    ${toHex(derivedBytes)}\n` +
        `       theirs:  ${toHex(reported)}\n` +
        "       Either --source is wrong for this network, or the response was tampered with.",
    );
  }
  console.error("  verified  canister agrees with our offline derivation");

  // ------------------------------------------------------------- 4. encrypt
  const plaintext = new TextEncoder().encode(value);
  const ciphertext = IbeCiphertext.encrypt(
    // Encrypt to the key WE derived, never to the one the canister reported.
    DerivedPublicKey.deserialize(derivedBytes),
    IbeIdentity.fromBytes(sealedSecretsKeyLabel(epoch)),
    plaintext,
    IbeSeed.random(),
  ).serialize();

  if (BigInt(ciphertext.length) > info.max_ciphertext_len) {
    fail(
      `ciphertext is ${ciphertext.length} bytes, canister accepts at most ${info.max_ciphertext_len}`,
    );
  }

  const method = opts.verify ? "icp_sealed_secret_matches" : "icp_sealed_secret_set";
  const candid = candidArgs(opts.name, ciphertext);

  if (opts.out) {
    writeFileSync(opts.out, candid);
    console.error(
      `\nencrypted "${opts.name}" (${plaintext.length} bytes → ${ciphertext.length} bytes), wrote ${opts.out}\n` +
        `send it as a controller:\n` +
        `  icp canister call ${canisterId.toText()} ${method} --args-file ${opts.out}`,
    );
  } else {
    console.error(`\nencrypted "${opts.name}" (${plaintext.length} bytes → ${ciphertext.length} bytes)`);
    console.log(candid);
  }
}

main().catch((e) => {
  console.error(`error: ${e instanceof Error ? e.message : String(e)}`);
  process.exit(1);
});
