/**
 * Candid interfaces for the target canister and for the NNS registry.
 *
 * The registry's `SubnetRecord` is declared with only the two fields we need.
 * Candid decoding is structural and permits dropping record fields, so a partial
 * declaration is valid and keeps this file small. Variants are the exception —
 * `MasterPublicKeyId` must list every case, or decoding a subnet that holds an
 * ECDSA or Schnorr key would fail.
 */

import { IDL } from "@icp-sdk/core/candid";

/* ------------------------------------------------------------------ canister */

export const SealedSecretsError = IDL.Variant({
  Internal: IDL.Text,
  TooMany: IDL.Record({ max: IDL.Nat64 }),
  InvalidCiphertext: IDL.Text,
  TooLarge: IDL.Record({ max: IDL.Nat64 }),
  NotFound: IDL.Null,
  Unauthorized: IDL.Null,
  InvalidName: IDL.Text,
  VetKdUnavailable: IDL.Record({ detail: IDL.Text, key_name: IDL.Text }),
});

export const SealedSecretInfo = IDL.Record({
  context: IDL.Vec(IDL.Nat8),
  max_secrets: IDL.Nat64,
  public_key: IDL.Vec(IDL.Nat8),
  max_ciphertext_len: IDL.Nat64,
  epoch: IDL.Nat32,
  key_name: IDL.Text,
  identity: IDL.Vec(IDL.Nat8),
  standard_version: IDL.Nat32,
});

export const SealedSecretEntry = IDL.Record({
  ciphertext_sha256: IDL.Vec(IDL.Nat8),
  ciphertext_len: IDL.Nat64,
  name: IDL.Text,
  updated_at_ns: IDL.Nat64,
  epoch: IDL.Nat32,
  created_at_ns: IDL.Nat64,
  revision: IDL.Nat64,
});

export const canisterIdl = () =>
  IDL.Service({
    icp_sealed_secret_info: IDL.Func(
      [],
      [IDL.Variant({ Ok: SealedSecretInfo, Err: SealedSecretsError })],
      ["query"],
    ),
    icp_sealed_secret_set: IDL.Func(
      [IDL.Text, IDL.Vec(IDL.Nat8)],
      [IDL.Variant({ Ok: IDL.Nat64, Err: SealedSecretsError })],
      [],
    ),
    icp_sealed_secret_unset: IDL.Func(
      [IDL.Text],
      [IDL.Variant({ Ok: IDL.Null, Err: SealedSecretsError })],
      [],
    ),
    secret_sha256: IDL.Func(
      [IDL.Text],
      [IDL.Variant({ Ok: IDL.Vec(IDL.Nat8), Err: SealedSecretsError })],
      [],
    ),
    icp_sealed_secret_list: IDL.Func(
      [],
      [IDL.Variant({ Ok: IDL.Vec(SealedSecretEntry), Err: SealedSecretsError })],
      ["query"],
    ),
  });

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
