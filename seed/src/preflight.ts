/**
 * Subnet preflight.
 *
 * One property, checked before it is worth sealing anything: **the subnet's
 * nodes are SEV-SNP**. Without that, the plaintext is readable by node operators
 * out of a checkpoint once the canister decrypts it, which defeats the purpose
 * of sealing it. Read from a single `get_subnet` query on the NNS registry.
 *
 * Deliberately **not** checked: whether this subnet holds the vetKD key.
 * `vetkd_derive_key` is routed like any other chain-key request, to a subnet
 * enabled for that key (`system_api/routing.rs`, `route_chain_key_message`), so
 * the calling canister's subnet need not hold it. Key availability is settled
 * authoritatively one step later anyway: `icp_sealed_secret_set` decrypts before
 * storing, so an unavailable key fails there, immediately, with a typed error.
 * The keys this subnet happens to hold are still printed, as information.
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
 * **SEV-SNP cannot be verified on a local network at all.** PocketIC reports
 * `sev_enabled = null` for every subnet, so locally this is a known blind spot
 * rather than a finding. `allowUnverifiedSev` acknowledges that, and is why a
 * local run needs it.
 */
export function evaluatePreflight(
  check: SubnetCheck | null,
  opts: { allowUnverifiedSev: boolean },
): PreflightOutcome {
  const lines: string[] = [];

  if (check === null) {
    lines.push("subnet:   unknown (registry unreachable)");
    lines.push("sev-snp:  UNVERIFIED");
    return { ok: opts.allowUnverifiedSev, lines };
  }

  lines.push(`subnet:   ${check.subnetId.toText()}`);

  let ok = true;

  if (check.sevEnabled === true) {
    lines.push("sev-snp:  enabled");
  } else if (check.sevEnabled === false) {
    lines.push("sev-snp:  DISABLED — node operators can read the plaintext from a checkpoint");
    if (!opts.allowUnverifiedSev) ok = false;
  } else {
    lines.push(
      "sev-snp:  NOT REPORTED — expected on a local network, where SEV cannot be simulated",
    );
    if (!opts.allowUnverifiedSev) ok = false;
  }

  // Informational only. Which keys THIS subnet holds does not decide whether
  // `vetkd_derive_key` will work — the request is routed to a subnet enabled for
  // the key, which need not be this one.
  const held =
    check.vetKdKeys.length > 0 ? `[${check.vetKdKeys.join(", ")}]` : "none";
  lines.push(`vetkd:    keys on this subnet: ${held} (not a gate — see preflight.ts)`);

  return { ok, lines };
}
