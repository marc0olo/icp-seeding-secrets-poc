# Deployment

What a real deployment needs, what a local run cannot prove, and how to test.

## The one prerequisite: a SEV-SNP subnet

The canister decrypts the secret into replicated state, so without SEV-SNP memory
encryption a node operator can read the plaintext out of a checkpoint. `npm run
preflight` resolves the canister's subnet and fails unless the registry reports
`features.sev_enabled`. It is a separate command from sealing because it asks a
separate question, once per deployment, while sealing is per secret and touches no
network. It reads a registry flag, which is not an attestation.

The subnet does **not** need to hold the vetKD key. `vetkd_derive_key` is routed to a
subnet enabled for the key (`route_chain_key_message` in `system_api/routing.rs`),
which need not be the caller's, so a canister on a keyless subnet derives fine. That
is why the preflight does not gate on the key; it only reports the keys the subnet
holds, as information. Whether the key is usable is settled by
`icp_sealed_secret_set`, which decrypts before storing.

## Local vs mainnet

| | Local / PocketIC | Mainnet |
|---|---|---|
| **vetKD keys** | `key_1` on the II and fiduciary subnets, `test_key_1` and `dfx_test_key` on TestThresholdKeys | the production keys |
| **Caller's subnet must hold the key** | no, routed | no, routed |
| **`features.sev_enabled`** | always `null`: SEV cannot be simulated | reported |
| **Outcall fan-out** | **one** real HTTP request | one per node (13, 34, …) |

So a local run cannot rehearse two things:

- **SEV-SNP.** Locally the preflight can only be waived, with `--local`, which says
  nothing about your deployment.
- **Outcall fan-out.** A missing idempotency key or a response body that varies per
  node passes locally and breaks on mainnet. See
  [outcalls.md](outcalls.md#what-a-local-run-hides).

## On mainnet

```bash
npm run preflight -- --canister <id> --host https://icp-api.io

npm run seal -- --canister <id> --name DUMMY_API_KEY --source mainnet --out sealed.args
icp canister call <id> icp_sealed_secret_set --args-file sealed.args --network ic
```

| Step | Why |
|---|---|
| Run the preflight without `--local` | it hard-fails unless the subnet reports `sev_enabled` |
| Seal one secret right after install | `set` decrypts before storing, so a wrong master-key table, key name, or a subnet that cannot serve vetKD fails now, not in production |
| Seal with `--source mainnet` | mainnet and PocketIC both have a `key_1`, backed by different master public keys, so the key name does not identify a key |

Choosing the wrong `--source` yields a ciphertext the canister cannot decrypt, which
`set` catches and `rust/core/tests/golden.rs` pins by asserting the two derivations
differ. `ic-vetkeys`' own `compute_vrf` gets this wrong today; see
[FOLLOW-UPS.md](../FOLLOW-UPS.md#a-bug-to-fix-while-in-there). Sealing itself takes no
`--host`: it never talks to the network.

## Do not lose the canister id

vetKD derives the key from the canister id. That is what makes a ciphertext
decryptable by exactly one canister, and it makes the id something you must never
lose: deploy a _replacement_ canister and every secret sealed to the old one is
permanently unreadable.

icp-cli records mainnet canister ids in `.icp/data/mappings/<environment>.ids.json`,
and that directory is **deliberately not gitignored** here. Commit `.icp/data/`; only
`.icp/cache/` is disposable. Moving a canister to another subnet with its id changes
nothing, but re-creating it, or a snapshot transfer to a new canister, does.

## Testing locally

```bash
./scripts/local-test.sh
```

It deploys both canisters, seals a secret, reads it back in the clear, makes the
authenticated outcall, checks the secret survives an upgrade, and runs the negative
cases. It also asserts that a default build does not contain `secret_reveal`, with a
control that `icp_sealed_secret_set` is present, and that the generated bindings match
the `.did`.

Individually:

```bash
cargo test          # golden vectors, name validation, key derivation
cd seed && npm test # the same golden vectors, in TypeScript

# against a running canister. The suite is an in-process client with its own
# signing key, generated from a published seed. Authorise it once, then run it.
icp canister settings update <id> --add-controller "$(npm run --silent e2e -- --print-principal)" -e local
npm run e2e -- --canister <id> --host http://127.0.0.1:8010 --source pocketic
```

The e2e suite covers ciphertext sealed to the wrong key label, malformed blobs,
invalid names, anonymous callers, that rejected writes leave no trace, and that an
overwrite replaces the stored value. Its first assertion, that a well-formed seal
succeeds, is also the check that client and canister derived the same key.
