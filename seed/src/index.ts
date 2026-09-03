/**
 * Seals a secret with vetKD IBE and submits it to a canister.
 *
 * The flow, and why each step is there:
 *
 *   1. Preflight the subnet — is it SEV-SNP, and does it hold the vetKD key?
 *   2. Derive the canister's public key OFFLINE, from a master key constant.
 *   3. Ask the canister what key it thinks it has, and abort on mismatch. The
 *      reported value is never used for encryption; it is only ever a cross-check.
 *      Trusting it would let anyone able to tamper with that response substitute
 *      a key they control and harvest the secret.
 *   4. Encrypt, and submit. The canister trial-decrypts before storing, so a
 *      wrong context or epoch fails here rather than in production.
 *
 * The value is read from an environment variable and never from argv: argv is
 * world-readable via `ps`, lands in shell history, and is echoed into CI logs.
 */

import { HttpAgent, Actor } from "@icp-sdk/core/agent";
import { Principal } from "@icp-sdk/core/principal";
import { IbeCiphertext, IbeIdentity, IbeSeed, DerivedPublicKey } from "@icp-sdk/vetkeys";

import { canisterIdl } from "./idl.js";
import { identityFromPemFile } from "./identity.js";
import { evaluatePreflight, inspectSubnet } from "./preflight.js";
import {
  bytesEqual,
  derivePublicKey,
  sealedSecretsContext,
  sealedSecretsIdentity,
  toHex,
  validateSecretName,
  type MasterKeySource,
} from "./format.js";

/** Decoded shape of `icp_sealed_secret_info`. */
interface Info {
  standard_version: number;
  context: number[];
  identity: number[];
  epoch: number;
  key_name: string;
  public_key: number[];
  max_ciphertext_len: bigint;
  max_secrets: bigint;
}

/** Decoded shape of one `icp_sealed_secret_list` entry. */
interface Entry {
  name: string;
  epoch: number;
  revision: bigint;
  ciphertext_len: bigint;
  ciphertext_sha256: number[];
  created_at_ns: bigint;
  updated_at_ns: bigint;
}

interface Options {
  canisterId: string;
  name: string;
  envVar: string;
  host: string;
  pem: string;
  source: MasterKeySource;
  appSeparator: string;
  allowUnprotectedSubnet: boolean;
  list: boolean;
}

const USAGE = `
Seal a secret and submit it to a sealed-secrets canister.

  seal --canister <id> --name <NAME> [--from-env <VAR>] [options]
  seal --canister <id> --list

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
  --pem <path>           Controller identity PEM.
                         Default $SEAL_IDENTITY_PEM.
                         Produce one with: icp identity export <name> > id.pem

Derivation
  --source <which>       mainnet | pocketic. Default pocketic.
                         NOT inferable from the key name: mainnet and PocketIC
                         each have a key_1 with a different master key.
  --app-separator <s>    Must match the canister's. Default empty.

Escape hatches
  --allow-unprotected-subnet
                         Proceed even though the subnet is not confirmed
                         SEV-SNP. For local development only: on such a subnet
                         node operators can read the plaintext once the canister
                         decrypts it.
  --list                 List the secrets the canister already holds.
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

  const list = has("--list");
  const name = get("--name") ?? "";
  if (!list && !name) fail("--name is required (or use --list)");

  const source = (get("--source") ?? "pocketic") as MasterKeySource;
  if (source !== "mainnet" && source !== "pocketic") {
    fail(`--source must be "mainnet" or "pocketic", got ${JSON.stringify(source)}`);
  }

  return {
    canisterId: canisterId!,
    name,
    envVar: get("--from-env") ?? name,
    host: get("--host") ?? "http://127.0.0.1:8000",
    pem: get("--pem") ?? process.env.SEAL_IDENTITY_PEM ?? "",
    source,
    appSeparator: get("--app-separator") ?? "",
    allowUnprotectedSubnet: has("--allow-unprotected-subnet"),
    list,
  };
}

function fail(message: string): never {
  console.error(`error: ${message}`);
  process.exit(1);
}

function unwrap<T>(result: { Ok: T } | { Err: unknown }, what: string): T {
  if ("Ok" in result) return result.Ok;
  fail(`${what} failed: ${JSON.stringify(result.Err, bigintReplacer)}`);
}

function bigintReplacer(_key: string, value: unknown) {
  return typeof value === "bigint" ? value.toString() : value;
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));

  if (!opts.pem) {
    fail("no identity: pass --pem <path> or set SEAL_IDENTITY_PEM");
  }

  const canisterId = Principal.fromText(opts.canisterId);
  const identity = identityFromPemFile(opts.pem);

  const agent = await HttpAgent.create({ host: opts.host, identity });
  if (!opts.host.includes("icp-api.io") && !opts.host.includes("ic0.app")) {
    // Local and test networks have their own root key.
    await agent.fetchRootKey();
  }

  const actor: any = Actor.createActor(canisterIdl, { agent, canisterId });

  // ---------------------------------------------------------------- list mode
  if (opts.list) {
    const entries = unwrap<Entry[]>(await actor.icp_sealed_secret_list(), "list");
    if (entries.length === 0) {
      console.log("no secrets stored");
      return;
    }
    for (const e of entries) {
      console.log(
        `${e.name}\n` +
          `  revision ${e.revision}  epoch ${e.epoch}  ciphertext ${e.ciphertext_len} bytes\n` +
          `  sha256 ${toHex(Uint8Array.from(e.ciphertext_sha256))}`,
      );
    }
    return;
  }

  validateSecretName(opts.name);

  const value = process.env[opts.envVar];
  if (value === undefined || value === "") {
    fail(
      `environment variable ${opts.envVar} is unset or empty.\n` +
        `       Set it in your shell, e.g.  export ${opts.envVar}=...\n` +
        `       (read from the environment on purpose — a --value flag would land in shell history and CI logs)`,
    );
  }

  // ------------------------------------------------------------- 1. preflight
  const check = await inspectSubnet(agent, canisterId);
  const preflight = evaluatePreflight(check, "", opts.allowUnprotectedSubnet);
  // The key name is only known after we read info, so re-evaluate below; this
  // first pass is just to surface the subnet id early.

  // ------------------------------------------------------------------ 2. info
  const info = unwrap<Info>(await actor.icp_sealed_secret_info(), "icp_sealed_secret_info");
  const context = sealedSecretsContext(opts.appSeparator);
  const epoch = Number(info.epoch);

  const finalPreflight = evaluatePreflight(check, info.key_name, opts.allowUnprotectedSubnet);
  console.log("preflight");
  for (const line of finalPreflight.lines) console.log(`  ${line}`);
  if (!finalPreflight.ok) {
    fail(
      "subnet preflight failed; refusing to seal.\n" +
        "       Pass --allow-unprotected-subnet to override (local development only).",
    );
  }
  void preflight;

  // --------------------------------------------- 3. derive offline, then check
  const derived = derivePublicKey(opts.source, info.key_name, canisterId, context);
  const derivedBytes = derived.publicKeyBytes();
  const reported = Uint8Array.from(info.public_key);

  console.log("\nkey derivation");
  console.log(`  source    ${opts.source}:${info.key_name}`);
  console.log(`  context   ${toHex(context)}`);
  console.log(`  identity  ${toHex(sealedSecretsIdentity(epoch))}  (epoch ${epoch})`);
  console.log(`  derived   ${toHex(derivedBytes).slice(0, 32)}…`);

  if (!bytesEqual(context, Uint8Array.from(info.context))) {
    fail(
      "the canister derives under a different context than we computed.\n" +
        `       ours:    ${toHex(context)}\n` +
        `       theirs:  ${toHex(Uint8Array.from(info.context))}\n` +
        "       Check --app-separator.",
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
  console.log("  verified  canister agrees with our offline derivation");

  // ------------------------------------------------------- 4. encrypt and send
  const plaintext = new TextEncoder().encode(value);
  const ciphertext = IbeCiphertext.encrypt(
    // Encrypt to the key WE derived, never to the one the canister reported.
    DerivedPublicKey.deserialize(derivedBytes),
    IbeIdentity.fromBytes(sealedSecretsIdentity(epoch)),
    plaintext,
    IbeSeed.random(),
  ).serialize();

  if (BigInt(ciphertext.length) > info.max_ciphertext_len) {
    fail(
      `ciphertext is ${ciphertext.length} bytes, canister accepts at most ${info.max_ciphertext_len}`,
    );
  }

  console.log(`\nsealing "${opts.name}" (${plaintext.length} bytes → ${ciphertext.length} bytes)`);
  const revision = unwrap<bigint>(
    await actor.icp_sealed_secret_set(opts.name, ciphertext),
    "icp_sealed_secret_set",
  );

  console.log(`✓ sealed "${opts.name}" at revision ${revision}`);
  console.log("  the canister trial-decrypted it before storing, so it is readable");
}

main().catch((e) => {
  console.error(`error: ${e instanceof Error ? e.message : String(e)}`);
  process.exit(1);
});
