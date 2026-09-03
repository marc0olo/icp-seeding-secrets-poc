/**
 * End-to-end verification against a deployed canister.
 *
 * Everything here needs a live replica, so it is a script rather than a unit
 * test. The negative cases are the interesting ones: they check that the
 * canister refuses ciphertext it cannot decrypt, which is the property that
 * turns a misconfiguration into a deploy-time error instead of a production
 * outage months later.
 *
 *   npx tsx src/e2e.ts --canister <id> --host <url> --source pocketic
 */

import { createHash } from "node:crypto";
import { HttpAgent, Actor, AnonymousIdentity } from "@icp-sdk/core/agent";
import { Principal } from "@icp-sdk/core/principal";
import { IbeCiphertext, IbeIdentity, IbeSeed, DerivedPublicKey } from "@icp-sdk/vetkeys";

import { idlFactory, type _SERVICE } from "./declarations/sealed_secrets_canister.did.js";
import { identityFromPemFile } from "./identity.js";
import {
  bytesEqual,
  derivePublicKey,
  sealedSecretsContext,
  sealedSecretsIdentity,
  toHex,
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

async function main() {
  const canisterId = Principal.fromText(arg("--canister"));
  const host = arg("--host", "http://127.0.0.1:8010");
  const source = arg("--source", "pocketic") as MasterKeySource;
  const pem = arg("--pem", process.env.SEAL_IDENTITY_PEM);

  const agent = await HttpAgent.create({ host, identity: identityFromPemFile(pem) });
  await agent.fetchRootKey();
  const actor = Actor.createActor<_SERVICE>(idlFactory, { agent, canisterId });

  // An anonymous caller, to prove the controller gate actually gates.
  const anonAgent = await HttpAgent.create({ host, identity: new AnonymousIdentity() });
  await anonAgent.fetchRootKey();
  const anon = Actor.createActor<_SERVICE>(idlFactory, { agent: anonAgent, canisterId });

  console.log("e2e verification\n");

  // 1 ─ offline derivation agrees with the canister
  const infoRes = await actor.icp_sealed_secret_info();
  if (!("Ok" in infoRes)) throw new Error(`info failed: ${show(infoRes.Err)}`);
  const info = infoRes.Ok;
  const context = sealedSecretsContext("");
  const dpk = derivePublicKey(source, info.key_name, canisterId, context);

  check(
    "offline derivation matches the canister's reported public key",
    bytesEqual(dpk.publicKeyBytes(), Uint8Array.from(info.public_key)),
    `ours ${toHex(dpk.publicKeyBytes()).slice(0, 24)}… theirs ${toHex(Uint8Array.from(info.public_key)).slice(0, 24)}…`,
  );
  check(
    "canister context matches the golden encoding",
    bytesEqual(context, Uint8Array.from(info.context)),
  );
  check(
    "canister identity matches the golden encoding",
    bytesEqual(sealedSecretsIdentity(info.epoch), Uint8Array.from(info.identity)),
  );

  const seal = (value: string, identityBytes: Uint8Array) =>
    IbeCiphertext.encrypt(
      DerivedPublicKey.deserialize(dpk.publicKeyBytes()),
      IbeIdentity.fromBytes(identityBytes),
      new TextEncoder().encode(value),
      IbeSeed.random(),
    ).serialize();

  // 2 ─ happy path: the canister recovers the exact plaintext
  const value = `e2e-${Date.now()}-value`;
  const setRes = await actor.icp_sealed_secret_set(
    "e2e_probe",
    seal(value, sealedSecretsIdentity(info.epoch)),
  );
  check(
    "sealing a well-formed ciphertext succeeds",
    "Ok" in setRes,
    "Err" in setRes ? show(setRes.Err) : "",
  );

  const digest = await actor.secret_sha256("e2e_probe").catch(() => null);
  if (digest === null) {
    console.log("  skip  canister recovered the exact plaintext (build lacks --features test-hooks)");
  } else {
    const expected = createHash("sha256").update(value).digest("hex");
    check(
      "canister recovered the exact plaintext",
      "Ok" in digest && toHex(Uint8Array.from(digest.Ok)) === expected,
    );
  }

  // 3 ─ ciphertext sealed to the WRONG identity must be refused at seal time.
  //     This is the regression guard for making `set` async and trial-decrypting:
  //     without it, this blob would be stored happily and fail in production.
  const wrongEpoch = await actor.icp_sealed_secret_set(
    "e2e_wrong_epoch",
    seal(value, sealedSecretsIdentity(info.epoch + 1)),
  );
  check(
    "ciphertext for the wrong epoch is rejected",
    errName(wrongEpoch) === "InvalidCiphertext",
    `got ${errName(wrongEpoch)}`,
  );

  // 4 ─ a blob that is not an IBE ciphertext at all
  const garbage = await actor.icp_sealed_secret_set(
    "e2e_garbage",
    new Uint8Array(200).fill(7),
  );
  check(
    "malformed ciphertext is rejected",
    errName(garbage) === "InvalidCiphertext",
    `got ${errName(garbage)}`,
  );

  // 5 ─ oversized
  const huge = await actor.icp_sealed_secret_set(
    "e2e_huge",
    new Uint8Array(Number(info.max_ciphertext_len) + 1),
  );
  check("oversized ciphertext is rejected", errName(huge) === "TooLarge", `got ${errName(huge)}`);

  // 6 ─ invalid name
  const badName = await actor.icp_sealed_secret_set(
    "not/a/valid/name",
    seal(value, sealedSecretsIdentity(info.epoch)),
  );
  check("invalid name is rejected", errName(badName) === "InvalidName", `got ${errName(badName)}`);

  // 7 ─ the controller gate
  const anonSet = await anon.icp_sealed_secret_set(
    "e2e_anon",
    seal(value, sealedSecretsIdentity(info.epoch)),
  );
  check(
    "anonymous caller cannot set a secret",
    errName(anonSet) === "Unauthorized",
    `got ${errName(anonSet)}`,
  );
  check("anonymous caller cannot list secrets", errName(await anon.icp_sealed_secret_list()) === "Unauthorized");
  check("anonymous caller cannot read a digest", errName(await anon.secret_sha256("e2e_probe")) === "Unauthorized");

  // 8 ─ rejected writes left no trace
  const list = await actor.icp_sealed_secret_list();
  const names: string[] = "Ok" in list ? list.Ok.map((e) => e.name) : [];
  check(
    "rejected ciphertexts were not stored",
    !names.some((n) => n.startsWith("e2e_wrong") || n.startsWith("e2e_garbage") || n === "e2e_huge"),
    `stored: [${names.join(", ")}]`,
  );

  // 9 ─ overwrite bumps the revision and the new value wins
  const newValue = `${value}-v2`;
  const again = await actor.icp_sealed_secret_set(
    "e2e_probe",
    seal(newValue, sealedSecretsIdentity(info.epoch)),
  );
  check("overwriting bumps the revision", "Ok" in again && again.Ok > 0n, show(again));
  const digest2 = await actor.secret_sha256("e2e_probe");
  check(
    "the cache did not serve the stale value after overwrite",
    "Ok" in digest2 &&
      toHex(Uint8Array.from(digest2.Ok)) === createHash("sha256").update(newValue).digest("hex"),
  );

  // 10 ─ cleanup
  await actor.icp_sealed_secret_unset("e2e_probe");
  check(
    "unset removes the secret",
    errName(await actor.secret_sha256("e2e_probe")) === "NotFound",
  );

  console.log(`\n${passed} passed, ${failed} failed`);
  process.exit(failed === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
