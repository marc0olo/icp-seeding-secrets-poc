/**
 * Loads a PEM identity, so the script can call as a controller.
 *
 * Produce one with `icp identity export <name> > id.pem`.
 *
 * icp-cli writes PKCS#8 (`-----BEGIN PRIVATE KEY-----`) and defaults to
 * secp256k1. `Secp256k1KeyIdentity.fromPem` only accepts SEC1
 * (`-----BEGIN EC PRIVATE KEY-----`), so the PKCS#8 wrapper is unwrapped here.
 * Ed25519 PKCS#8 is also accepted, since other tooling emits it.
 */

import { readFileSync } from "node:fs";
import { Ed25519KeyIdentity } from "@icp-sdk/core/identity";
import { Secp256k1KeyIdentity } from "@icp-sdk/core/identity/secp256k1";
import type { Identity } from "@icp-sdk/core/agent";

/** DER prefix of a v1 PKCS#8 Ed25519 private key, followed by the 32-byte seed. */
const ED25519_PKCS8_PREFIX = "302e020100300506032b657004220420";

/** OID 1.3.132.0.10 — secp256k1. */
const SECP256K1_OID = "06052b8104000a";

/**
 * SEC1 `ECPrivateKey` preamble: SEQUENCE, INTEGER 1, then a 32-byte OCTET STRING.
 * The private scalar follows immediately.
 */
const SEC1_KEY_PREAMBLE = "020101" + "0420";

export function identityFromPemFile(path: string): Identity {
  return identityFromPem(readFileSync(path, "utf8"));
}

export function identityFromPem(pem: string): Identity {
  if (pem.includes("ENCRYPTED")) {
    throw new Error(
      "the PEM is password-encrypted; re-export it without --encrypt, or decrypt it first",
    );
  }

  // SEC1 secp256k1 — the library handles this shape directly.
  if (pem.includes("BEGIN EC PRIVATE KEY")) {
    return Secp256k1KeyIdentity.fromPem(pem);
  }

  const der = derFromPem(pem);
  const hex = Buffer.from(der).toString("hex");

  if (hex.startsWith(ED25519_PKCS8_PREFIX)) {
    const seed = der.subarray(ED25519_PKCS8_PREFIX.length / 2);
    if (seed.length !== 32) {
      throw new Error(`expected a 32-byte Ed25519 seed, found ${seed.length} bytes`);
    }
    return Ed25519KeyIdentity.fromSecretKey(seed);
  }

  if (hex.includes(SECP256K1_OID)) {
    return Secp256k1KeyIdentity.fromSecretKey(extractSec1Scalar(hex));
  }

  throw new Error(
    "unrecognised key: expected PKCS#8 or SEC1 holding an Ed25519 or secp256k1 private key",
  );
}

/** Pulls the 32-byte private scalar out of an embedded SEC1 `ECPrivateKey`. */
function extractSec1Scalar(hex: string): Uint8Array {
  const at = hex.indexOf(SEC1_KEY_PREAMBLE);
  if (at === -1) {
    throw new Error("could not locate the SEC1 private key inside the PKCS#8 wrapper");
  }
  const start = at + SEC1_KEY_PREAMBLE.length;
  const scalar = hex.slice(start, start + 64);
  if (scalar.length !== 64) {
    throw new Error("the SEC1 private key is truncated");
  }
  return new Uint8Array(Buffer.from(scalar, "hex"));
}

function derFromPem(pem: string): Uint8Array {
  const body = pem
    .replace(/-----BEGIN [^-]+-----/g, "")
    .replace(/-----END [^-]+-----/g, "")
    .replace(/\s+/g, "");
  if (body.length === 0) throw new Error("PEM file contains no key material");
  return new Uint8Array(Buffer.from(body, "base64"));
}
