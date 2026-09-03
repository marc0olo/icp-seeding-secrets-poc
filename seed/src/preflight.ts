/**
 * Subnet preflight.
 *
 * Two properties must hold before it is worth sealing anything, and neither
 * implies the other:
 *
 *   1. The subnet holds the vetKD key. Without it, `vetkd_derive_key` is
 *      rejected and the canister can never read the secret back.
 *   2. The subnet's nodes are SEV-SNP. Without that, the plaintext is readable
 *      by node operators out of a checkpoint once the canister decrypts it —
 *      which defeats the entire purpose of sealing it in the first place.
 *
 * Both come from a single `get_subnet` query on the NNS registry.
 */

import { Actor, type HttpAgent } from "@icp-sdk/core/agent";
import { Principal } from "@icp-sdk/core/principal";

import { REGISTRY_CANISTER_ID, registryIdl } from "./idl.js";

export interface SubnetCheck {
  subnetId: Principal;
  sevEnabled: boolean | null;
  vetKdKeys: string[];
}

type Opt<T> = [] | [T];
function unwrapOpt<T>(opt: Opt<T>): T | null {
  return opt.length === 0 ? null : opt[0]!;
}

/**
 * Resolves the canister's subnet and reads back the two properties we care about.
 *
 * Returns `null` when the registry cannot answer — which is the normal case on a
 * local network that has no NNS installed. That is not a failure; the caller
 * decides what to do about an unknown subnet.
 */
export async function inspectSubnet(
  agent: HttpAgent,
  canisterId: Principal,
): Promise<SubnetCheck | null> {
  const registry: any = Actor.createActor(registryIdl, {
    agent,
    canisterId: Principal.fromText(REGISTRY_CANISTER_ID),
  });

  let subnetId: Principal;
  try {
    const res = await registry.get_subnet_for_canister({ principal: [canisterId] });
    if ("Err" in res) return null;
    const id = unwrapOpt<Principal>(res.Ok.subnet_id);
    if (!id) return null;
    subnetId = id;
  } catch {
    return null;
  }

  try {
    const res = await registry.get_subnet({ subnet_id: [subnetId] });
    if ("Err" in res) return { subnetId, sevEnabled: null, vetKdKeys: [] };

    const features = unwrapOpt<any>(res.Ok.features);
    const sevEnabled = features ? unwrapOpt<boolean>(features.sev_enabled) : null;

    const chainKeyConfig = unwrapOpt<any>(res.Ok.chain_key_config);
    const vetKdKeys: string[] = [];
    for (const cfg of chainKeyConfig?.key_configs ?? []) {
      const keyId = unwrapOpt<any>(cfg.key_id);
      if (keyId && "VetKd" in keyId) vetKdKeys.push(keyId.VetKd.name);
    }

    return { subnetId, sevEnabled, vetKdKeys };
  } catch {
    return { subnetId, sevEnabled: null, vetKdKeys: [] };
  }
}

export interface PreflightOutcome {
  ok: boolean;
  lines: string[];
}

/**
 * Turns a subnet inspection into a pass/fail plus human-readable findings.
 *
 * `allowUnprotected` exists for local development, where no subnet is SEV-SNP.
 * It must never be the default: silently sealing to a subnet whose operators can
 * read the plaintext is exactly the failure this tool exists to prevent.
 */
export function evaluatePreflight(
  check: SubnetCheck | null,
  keyName: string,
  allowUnprotected: boolean,
): PreflightOutcome {
  const lines: string[] = [];

  if (check === null) {
    lines.push("subnet:   unknown (no NNS registry reachable — expected on a local network)");
    lines.push("sev-snp:  UNVERIFIED");
    lines.push(`vetkd:    UNVERIFIED (assuming "${keyName}" is present)`);
    return { ok: allowUnprotected, lines };
  }

  lines.push(`subnet:   ${check.subnetId.toText()}`);

  let ok = true;

  if (check.sevEnabled === true) {
    lines.push("sev-snp:  enabled");
  } else if (check.sevEnabled === false) {
    lines.push("sev-snp:  DISABLED — node operators can read the plaintext from a checkpoint");
    ok = false;
  } else {
    lines.push("sev-snp:  UNVERIFIED — the registry did not report the feature flag");
    ok = false;
  }

  if (check.vetKdKeys.includes(keyName)) {
    lines.push(`vetkd:    "${keyName}" present`);
  } else if (check.vetKdKeys.length > 0) {
    lines.push(
      `vetkd:    "${keyName}" NOT present — subnet holds [${check.vetKdKeys.join(", ")}]`,
    );
    ok = false;
  } else {
    lines.push(`vetkd:    "${keyName}" NOT present — subnet holds no vetKD keys at all`);
    ok = false;
  }

  return { ok: ok || allowUnprotected, lines };
}
