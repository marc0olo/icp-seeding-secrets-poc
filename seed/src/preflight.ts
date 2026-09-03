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
 * The two checks fail for different reasons and must not be conflated:
 *
 * - **SEV-SNP cannot be verified on a local network at all.** PocketIC reports
 *   `sev_enabled = null` for every subnet, so locally this is a known blind spot
 *   rather than a finding. `allowUnverifiedSev` acknowledges that.
 *
 * - **The vetKD check *is* accurate locally.** The registry reports chain keys
 *   correctly — the fiduciary subnet shows `key_1`, the application subnet shows
 *   none. And a missing key here predicts a hard mainnet failure, because mainnet
 *   serves `vetkd_derive_key` from the calling canister's own subnet and rejects
 *   otherwise, while PocketIC does not enforce that. So locally this warning is
 *   the *only* signal that placement is wrong: the runtime will happily let you
 *   proceed. `allowMissingVetkdKey` is therefore a much sharper knife than it looks.
 */
export function evaluatePreflight(
  check: SubnetCheck | null,
  keyName: string,
  opts: { allowUnverifiedSev: boolean; allowMissingVetkdKey: boolean },
): PreflightOutcome {
  const lines: string[] = [];

  if (check === null) {
    lines.push("subnet:   unknown (registry unreachable)");
    lines.push("sev-snp:  UNVERIFIED");
    lines.push(`vetkd:    UNVERIFIED (assuming "${keyName}" is present)`);
    return { ok: opts.allowUnverifiedSev && opts.allowMissingVetkdKey, lines };
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

  if (check.vetKdKeys.includes(keyName)) {
    lines.push(`vetkd:    "${keyName}" present on this subnet`);
  } else {
    const held =
      check.vetKdKeys.length > 0
        ? `subnet holds [${check.vetKdKeys.join(", ")}]`
        : "subnet holds no vetKD keys";
    lines.push(`vetkd:    "${keyName}" NOT on this subnet — ${held}`);
    lines.push(
      "          On mainnet this is fatal: vetkd_derive_key is served by the",
    );
    lines.push(
      "          calling canister's own subnet. PocketIC does not enforce that,",
    );
    lines.push(
      "          so a local run will succeed anyway and hide the problem.",
    );
    if (!opts.allowMissingVetkdKey) ok = false;
  }

  return { ok, lines };
}
