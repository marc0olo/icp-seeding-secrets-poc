/**
 * End-to-end verification against a deployed canister.
 *
 * Everything here needs a live replica, so it is a script rather than a unit
 * test. The negative cases are the interesting ones: they check that the
 * canister refuses ciphertext it cannot decrypt, which is the property that
 * turns a misconfiguration into a deploy-time error instead of a production
 * outage months later.
 *
 *   npx tsx src/e2e.ts --print-principal            # who to authorise
 *   npx tsx src/e2e.ts --canister <id> --host <url> --source pocketic
 *
 * # Why this needs an identity of its own
 *
 * This is an **in-process** client: most assertions build a ciphertext here and
 * immediately call the canister, branching on the typed result. Update calls
 * have to be signed, so the process needs a signing key. Three ways to get one,
 * and only the third is acceptable:
 *
 *   1. Run as anonymous. Rejected — the suite asserts that anonymous callers are
 *      turned away, so making that principal a controller would pass the gate
 *      test vacuously.
 *   2. Export the icp-cli identity. Rejected — nothing else in this repo asks
 *      you to put a private key on disk, and a test harness is a poor reason to
 *      start.
 *   3. Generate one. An Ed25519 identity from the fixed seed below, which never
 *      leaves this process and is not a secret: it is published right here, and
 *      only ever authorised on a throwaway local canister.
 *
 *   icp canister settings update <canister> --add-controller <principal> -e local
 *
 * `scripts/local-test.sh` wires up both steps.
 *
 * Note this is a property of being in-process, not of the assertions themselves.
 * `icp canister call --identity anonymous` works, so a shell harness could test
 * the gate with no key at all — which is what the minimal PoC on `main` does,
 * driving everything through icp-cli. The trade is that shell assertions parse
 * Candid text where these branch on discriminated unions, and one client here
 * drives both canisters unchanged, which is the interoperability claim this
 * repo makes.
 */

import { HttpAgent, Actor, AnonymousIdentity } from "@icp-sdk/core/agent";
import { Ed25519KeyIdentity } from "@icp-sdk/core/identity";
import { Principal } from "@icp-sdk/core/principal";
import { IbeCiphertext, IbeIdentity, IbeSeed, DerivedPublicKey } from "@icp-sdk/vetkeys";

import { idlFactory, type _SERVICE } from "./declarations/sealed_secrets_canister.did.js";
import {
  KEY_LABEL,
  derivePublicKey,
  type MasterKeySource,
} from "./format.js";

let passed = 0;
let failed = 0;

function check(name: string, ok: boolean, detail = "") {
  if (ok) {
    passed++;
    console.log(`  ok    ${name}`);
  } else {
    failed++;
    console.log(`  FAIL  ${name}${detail ? `\n        ${detail}` : ""}`);
  }
}

/** JSON.stringify refuses BigInt, and Candid nat64 decodes to one. */
function show(value: unknown): string {
  return JSON.stringify(value, (_k, v) => (typeof v === "bigint" ? v.toString() : v));
}

function errName(res: any): string {
  return "Err" in res ? Object.keys(res.Err)[0]! : "<Ok>";
}

function arg(flag: string, fallback?: string): string {
  const i = process.argv.indexOf(flag);
  const v = i === -1 ? fallback : process.argv[i + 1];
  if (v === undefined) throw new Error(`${flag} is required`);
  return v;
}

/**
 * The harness's own caller. Deterministic, so the principal can be authorised
 * before the suite runs — see the module comment for why a fixed seed in a
 * committed file is the right call here and not a leak.
 */
const TEST_IDENTITY_SEED = new Uint8Array(32).fill(7);

function testIdentity(): Ed25519KeyIdentity {
  return Ed25519KeyIdentity.generate(TEST_IDENTITY_SEED);
}

async function main() {
  if (process.argv.includes("--print-principal")) {
    console.log(testIdentity().getPrincipal().toText());
    return;
  }

  const canisterId = Principal.fromText(arg("--canister"));
  const host = arg("--host", "http://127.0.0.1:8010");
  const source = arg("--source", "pocketic") as MasterKeySource;
  const keyName = arg("--key-name", "key_1");
  const agent = await HttpAgent.create({ host, identity: testIdentity() });
  await agent.fetchRootKey();
  const actor = Actor.createActor<_SERVICE>(idlFactory, { agent, canisterId });

  // An anonymous caller, to prove the controller gate actually gates.
  const anonAgent = await HttpAgent.create({ host, identity: new AnonymousIdentity() });
  await anonAgent.fetchRootKey();
  const anon = Actor.createActor<_SERVICE>(idlFactory, { agent: anonAgent, canisterId });

  console.log("e2e verification\n");

  // The canister publishes nothing to check against — that is the design. The
  // client derives from constants and the canister decrypts or rejects, so
  // "did we agree" is answered by `set` succeeding, which is assertion 1.
  const dpk = derivePublicKey(source, keyName, canisterId);

  const seal = (value: string, label: Uint8Array = KEY_LABEL) =>
    IbeCiphertext.encrypt(
      DerivedPublicKey.deserialize(dpk.publicKeyBytes()),
      IbeIdentity.fromBytes(label),
      new TextEncoder().encode(value),
      IbeSeed.random(),
    ).serialize();

  // 1 ─ happy path. This one assertion covers the whole derivation agreement:
  //     set() decrypts before storing, so it can only succeed if the client and
  //     the canister derived the same key.
  const value = `e2e-${Date.now()}-value`;
  const setRes = await actor.icp_sealed_secret_set("e2e_probe", seal(value));
  check(
    "sealing a well-formed ciphertext succeeds",
    "Ok" in setRes,
    "Err" in setRes ? show(setRes.Err) : "",
  );
  check("the first revision is 0", "Ok" in setRes && setRes.Ok === 0n, show(setRes));

  // `matches` is a stronger check than a digest would be: it confirms the stored
  // value equals the one we hold AND that a different value is rejected, and it
  // needs no endpoint that discloses anything.
  const same = await actor.icp_sealed_secret_matches("e2e_probe", seal(value));
  check("matches() is true for the value we sealed", "Ok" in same && same.Ok === true, show(same));

  const different = await actor.icp_sealed_secret_matches(
    "e2e_probe",
    seal(`${value}-different`),
  );
  check(
    "matches() is false for a different value",
    "Ok" in different && different.Ok === false,
    show(different),
  );

  // 2 ─ ciphertext sealed to the WRONG label must be refused at seal time.
  //     This is the regression guard for making `set` async and decrypting
  //     before storing: without it, this blob would be stored happily and fail
  //     in production. It stands in for every derivation mismatch — a wrong key
  //     name, a wrong master key table, a wrong canister id — since all of them
  //     produce a ciphertext this canister's key cannot open.
  const wrongLabel = await actor.icp_sealed_secret_set(
    "e2e_wrong_label",
    seal(value, new TextEncoder().encode("not-the-key-label")),
  );
  check(
    "ciphertext for the wrong key label is rejected",
    errName(wrongLabel) === "InvalidCiphertext",
    `got ${errName(wrongLabel)}`,
  );

  // 3 ─ a blob that is not an IBE ciphertext at all
  const garbage = await actor.icp_sealed_secret_set(
    "e2e_garbage",
    new Uint8Array(200).fill(7),
  );
  check(
    "malformed ciphertext is rejected",
    errName(garbage) === "InvalidCiphertext",
    `got ${errName(garbage)}`,
  );

  // 4 ─ invalid name
  const badName = await actor.icp_sealed_secret_set("not/a/valid/name", seal(value));
  check("invalid name is rejected", errName(badName) === "InvalidName", `got ${errName(badName)}`);

  // 5 ─ the controller gate
  const anonSet = await anon.icp_sealed_secret_set("e2e_anon", seal(value));
  check(
    "anonymous caller cannot set a secret",
    errName(anonSet) === "Unauthorized",
    `got ${errName(anonSet)}`,
  );
  check("anonymous caller cannot list secrets", errName(await anon.icp_sealed_secret_list()) === "Unauthorized");
  check(
    "anonymous caller cannot use matches as an oracle",
    errName(await anon.icp_sealed_secret_matches("e2e_probe", seal(value))) === "Unauthorized",
  );

  // 6 ─ rejected writes left no trace
  const list = await actor.icp_sealed_secret_list();
  const names: string[] = "Ok" in list ? list.Ok.map((e) => e.name) : [];
  check(
    "rejected ciphertexts were not stored",
    !names.some((n) => n.startsWith("e2e_wrong") || n.startsWith("e2e_garbage")),
    `stored: [${names.join(", ")}]`,
  );

  // 7 ─ overwrite bumps the revision and the new value wins
  const newValue = `${value}-v2`;
  const again = await actor.icp_sealed_secret_set("e2e_probe", seal(newValue));
  check("overwriting bumps the revision", "Ok" in again && again.Ok === 1n, show(again));
  const freshMatches = await actor.icp_sealed_secret_matches("e2e_probe", seal(newValue));
  const staleMatches = await actor.icp_sealed_secret_matches("e2e_probe", seal(value));
  check(
    "an overwrite replaces the stored value rather than shadowing it",
    "Ok" in freshMatches &&
      freshMatches.Ok === true &&
      "Ok" in staleMatches &&
      staleMatches.Ok === false,
  );

  // 8 ─ cleanup
  await actor.icp_sealed_secret_unset("e2e_probe");
  check(
    "unset removes the secret",
    errName(await actor.icp_sealed_secret_matches("e2e_probe", seal(value))) === "NotFound",
  );

  console.log(`\n${passed} passed, ${failed} failed`);
  process.exit(failed === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
