/**
 * Candid interface for the NNS registry.
 *
 * The canister's own interface is **generated** — see
 * `src/declarations/sealed_secrets_canister.did.ts`, produced by
 * `npm run bindings` from `rust/canister/sealed_secrets_canister.did`. Do not
 * hand-write it: an earlier revision of this file did, and it silently drifted
 * from the canister twice (when `info` became an update, and when the
 * `test-hooks` endpoints appeared).
 *
 * The registry is hand-written on purpose. There is no `.did` for it in this
 * repo, we need two of its ~20 methods, and its `SubnetRecord` has some 25
 * fields of which we read two. Candid decoding is structural and permits
 * dropping record fields, so a partial declaration is valid. Variants are the
 * exception — `MasterPublicKeyId` must list every case, or decoding a subnet
 * that holds an ECDSA or Schnorr key would fail.
 */

import { IDL } from "@icp-sdk/core/candid";

/* ------------------------------------------------------------------ registry */

const VetKdKeyId = IDL.Record({
  curve: IDL.Variant({ bls12_381_g2: IDL.Null }),
  name: IDL.Text,
});

const MasterPublicKeyId = IDL.Variant({
  Schnorr: IDL.Record({
    algorithm: IDL.Variant({ ed25519: IDL.Null, bip340secp256k1: IDL.Null }),
    name: IDL.Text,
  }),
  Ecdsa: IDL.Record({
    curve: IDL.Variant({ secp256k1: IDL.Null }),
    name: IDL.Text,
  }),
  VetKd: VetKdKeyId,
});

const KeyConfig = IDL.Record({
  key_id: IDL.Opt(MasterPublicKeyId),
  pre_signatures_to_create_in_advance: IDL.Opt(IDL.Nat32),
  max_queue_size: IDL.Opt(IDL.Nat32),
});

const ChainKeyConfig = IDL.Record({
  key_configs: IDL.Vec(KeyConfig),
});

const SubnetFeatures = IDL.Record({
  canister_sandboxing: IDL.Bool,
  http_requests: IDL.Bool,
  sev_enabled: IDL.Opt(IDL.Bool),
});

/** Only the fields we need; Candid lets a client drop the rest. */
const SubnetRecord = IDL.Record({
  features: IDL.Opt(SubnetFeatures),
  chain_key_config: IDL.Opt(ChainKeyConfig),
});

export const registryIdl = () =>
  IDL.Service({
    get_subnet_for_canister: IDL.Func(
      [IDL.Record({ principal: IDL.Opt(IDL.Principal) })],
      [
        IDL.Variant({
          Ok: IDL.Record({ subnet_id: IDL.Opt(IDL.Principal) }),
          Err: IDL.Text,
        }),
      ],
      ["query"],
    ),
    get_subnet: IDL.Func(
      [IDL.Record({ subnet_id: IDL.Opt(IDL.Principal) })],
      [IDL.Variant({ Ok: SubnetRecord, Err: IDL.Text })],
      ["query"],
    ),
  });

export const REGISTRY_CANISTER_ID = "rwlgt-iiaaa-aaaaa-aaaaa-cai";
