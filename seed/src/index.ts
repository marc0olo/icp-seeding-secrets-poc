/**
 * Seals a secret for a canister and sends it.
 *
 * Three steps, and the first is the one that matters:
 *
 *   1. Derive the canister's public key OFFLINE. Start from a master public key
 *      shipped in this library, mix in the canister id, mix in the context.
 *      Pure arithmetic — no network call, nothing to trust.
 *   2. Encrypt the secret to that key.
 *   3. Send the ciphertext in an ordinary update call.
 *
 * Step 1 is why this is worth doing. The ciphertext can only be opened by a key
 * that the target canister, on its own subnet, can ask the subnet to
 * reconstruct. Nobody else can — not the boundary node that relays the call,
 * not whoever is reading the CI log.
 *
 * The value is read from the environment, never from argv: argv is visible to
 * anyone who can run `ps`, lands in shell history, and is echoed into CI logs.
 */

import { HttpAgent, Actor } from "@icp-sdk/core/agent";
import { Principal } from "@icp-sdk/core/principal";
import {
  IbeCiphertext,
  IbeIdentity,
  IbeSeed,
  MasterPublicKey,
  MasterPublicKeyId,
  PocketIcMasterPublicKeyId,
} from "@icp-sdk/vetkeys";

import { IDL } from "@icp-sdk/core/candid";

import { identityFromPemFile } from "./identity.js";

/**
 * The canister interface, written out rather than generated.
 *
 * Two methods is small enough to read, and writing it here lets one script
 * drive both canisters: the Rust one exports `set_dummy_secret`, the Motoko one
 * `setDummySecret`, because each follows its language's convention. A generated
 * binding would be tied to one of them.
 *
 * `local-test.sh` calls both on every run, so a drift between this and either
 * canister fails immediately rather than silently.
 */
const Result = IDL.Variant({ Ok: IDL.Null, Err: IDL.Text });
const idlFactory = () =>
  IDL.Service({
    set_dummy_secret: IDL.Func([IDL.Vec(IDL.Nat8)], [Result], []),
    setDummySecret: IDL.Func([IDL.Vec(IDL.Nat8)], [Result], []),
  });

interface Service {
  set_dummy_secret: (ct: Uint8Array) => Promise<{ Ok: null } | { Err: string }>;
  setDummySecret: (ct: Uint8Array) => Promise<{ Ok: null } | { Err: string }>;
}

/** Must match the canister byte for byte — see rust/canister/src/lib.rs. */
const CONTEXT = new TextEncoder().encode("dummy-secret-poc");
const IDENTITY = new TextEncoder().encode("dummy-secret");

const USAGE = `
Seal a secret and send it to the canister.

  DUMMY_SECRET=<value> npm run seal -- --canister <id> [options]

  --canister <id>   Target canister id.
  --host <url>      Replica URL. Default http://127.0.0.1:8010
  --pem <path>      Controller identity PEM. Default $SEAL_IDENTITY_PEM
                    Produce one with: icp identity export <name> > id.pem
  --motoko          Call setDummySecret instead of set_dummy_secret.
                    The two canisters follow their own language's naming.
  --key-name <n>    vetKD key. Default key_1
  --source <which>  mainnet | pocketic. Default pocketic.
                    NOT inferable from the key name: both networks have a
                    key_1, backed by different master keys.
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
 * `--source` cannot be inferred from the key name. Mainnet and PocketIC each
 * have a key called `key_1` backed by a *different* master key — necessarily, a
 * local network cannot hold mainnet's master secret. Guess wrong and you get a
 * ciphertext nobody can ever open, with no error until the canister tries.
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

async function main() {
  if (process.argv.includes("--help")) {
    console.log(USAGE);
    return;
  }

  const canisterId = Principal.fromText(arg("--canister"));
  const host = arg("--host", "http://127.0.0.1:8010");
  const keyName = arg("--key-name", "key_1");
  const source = arg("--source", "pocketic");
  const pem = arg("--pem", process.env.SEAL_IDENTITY_PEM ?? "");

  const secret = process.env.DUMMY_SECRET;
  if (!secret) {
    console.error(
      "error: DUMMY_SECRET is unset.\n" +
        "       Set it in your shell, e.g.  export DUMMY_SECRET=hunter2\n" +
        "       (read from the environment on purpose — a --value flag would\n" +
        "        land in shell history and CI logs)",
    );
    process.exit(1);
  }

  const agent = await HttpAgent.create({ host, identity: identityFromPemFile(pem) });
  // A local replica has its own root key, which the agent has to be told.
  if (!host.includes("icp-api.io") && !host.includes("ic0.app")) {
    await agent.fetchRootKey();
  }

  // 1. offline
  const publicKey = derivePublicKey(source, keyName, canisterId);
  console.log(`derived ${source}:${keyName} key for ${canisterId.toText()} — no network call`);

  // 2. encrypt
  const ciphertext = IbeCiphertext.encrypt(
    publicKey,
    IbeIdentity.fromBytes(IDENTITY),
    new TextEncoder().encode(secret),
    IbeSeed.random(),
  ).serialize();
  console.log(`encrypted ${secret.length} bytes -> ${ciphertext.length} bytes`);

  // 3. send
  const actor = Actor.createActor<Service>(idlFactory, { agent, canisterId });
  const result = process.argv.includes("--motoko")
    ? await actor.setDummySecret(ciphertext)
    : await actor.set_dummy_secret(ciphertext);
  if ("Err" in result) {
    console.error(`the canister could not decrypt it: ${result.Err}`);
    process.exit(1);
  }
  console.log("sealed — the canister decrypted it and kept the plaintext");
}

main().catch((e) => {
  console.error(`error: ${e instanceof Error ? e.message : String(e)}`);
  process.exit(1);
});
