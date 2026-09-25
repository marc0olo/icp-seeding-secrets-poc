# Interface

The proposed standard in full. The [README](../README.md) has the overview.

```candid
// required
icp_sealed_secret_set     : (text, blob)    -> (variant { Ok : nat64; Err : SealedSecretsError });
icp_sealed_secret_unset   : (text)          -> (variant { Ok; Err : SealedSecretsError });
icp_sealed_secret_list    : ()              -> (variant { Ok : vec SealedSecretEntry; Err : … }) query;

// optional
icp_sealed_secret_matches : (text, blob)    -> (variant { Ok : bool; Err : SealedSecretsError });

// not part of the standard: the worked example of USING a secret
call_api_with_secret      : (text, text)    -> (variant { Ok : nat16; Err : SealedSecretsError });
strip_response            : (TransformArgs) -> (HttpRequestResult) query;
```

Install args are just `(record { key_name : text })`.

| Endpoint | Why it exists |
|---|---|
| `set` | the whole mechanism, and the only one a sealing tool needs. Returns the new revision. |
| `unset` | revoking a leaked credential should not need an upgrade |
| `list` | the inventory: what does this canister hold, and did my write land |
| `matches` | is the value I hold the one you have stored, without either side disclosing it |

- **`set` decrypts before storing, and that is the health check.** On a cold cache
  it exercises `vetkd_public_key`, `vetkd_derive_key`, verification and decryption
  on real data, so there is no separate `self_test`. The cache is cold after install
  in both canisters, and after an upgrade in the Rust one; the Motoko one keeps its
  vetKey across upgrades.
- **`matches` is optional.** An operator who wants to guarantee a value can simply
  `set` it again. `matches` earns its place where writing is not allowed, such as a
  monitoring probe.
- **There is no `info` endpoint.** A client needs nothing from the canister to seal:
  the context and label are constants, the public key is derived offline, and the
  deployer chose the vetKD key name at install. It would also cost an update call
  on every seal, since the canister's public key comes from `vetkd_public_key`.
- **Errors are a typed variant**, so tooling can branch on `VetKdUnavailable` versus
  `InvalidCiphertext` rather than parsing prose.
- **`list` is controller-gated**, because names alone (`billing_live_key`, …) are
  useful reconnaissance.
- **Nothing derived from a plaintext is exposed.** A digest of a plaintext would be an
  offline guessing oracle for a low-entropy secret. `list` shows `ciphertext_sha256`,
  a digest of a _randomised_ ciphertext, which reveals nothing but lets the client
  that produced it recognise its own upload. It cannot confirm a value is correct,
  since sealing the same secret twice gives different digests; that is `matches`.
- **Discovery needs no new mechanism.** `icp canister metadata <id> candid:service`
  returns the interface, so tooling can check which of these a canister has.

## Confirming the right secret is deployed

An operator already knows the value, so they need one bit back, not the secret. Seal
the value you expect and send it to `matches` instead of `set`; the argument is the
same:

```bash
DUMMY_API_KEY='the-value-i-expect' npm run seal -- \
  --canister <id> --name DUMMY_API_KEY --source mainnet --out check.args
icp canister call <id> icp_sealed_secret_matches --args-file check.args --network ic
# (true)
```

The canister decrypts the candidate and compares it with the stored plaintext in
constant time. Neither side puts the secret on the wire. A digest would be worse in
either direction: returned, it is brute-forceable offline for a low-entropy secret;
sent, it puts the same digest on the wire. `matches` is controller-gated, because for
anyone else it is an oracle for confirming guesses. **This is the intended
verification path, and safe in production.**

## Rotating a secret

Seal it again. `set` replaces the stored value and bumps the revision, so the next use
picks up the new value with no upgrade and no downtime.

There is no mechanism for rotating the _key label_. If a secret leaks you rotate the
secret. If the label ever has to change, the suite string is the version, and bumping
it is the format break.

## Seeing the plaintext

To _look_ at a stored value, which is the point of a PoC someone is deciding whether
to trust, build with `--features test-hooks` (which this repo's `icp.yaml` does) and
call `secret_reveal`:

```bash
icp canister call sealed-secrets-rust secret_reveal '("DUMMY_API_KEY")' -e local
```

`local-test.sh` step 8 prints both the sealed and the revealed value. Nothing
automated needs it, and **no real deployment should have it**. The same feature adds
`bench_ibe_decrypt`, which measures one decryption so the Rust and Motoko
implementations can be compared in instructions.

The hook is absent from a default build, not merely hidden, and all four checks
agree:

| Check | Default build | `--features test-hooks` |
|---|---|---|
| Candid interface (`candid-extractor`) | absent | present |
| Wasm export section | no `canister_update secret_reveal` | present |
| Byte scan of the whole binary | **0** occurrences of the string | present |
| Calling it on a deployed canister | `IC0536 Canister has no update method 'secret_reveal'` | returns the value |

`local-test.sh` and CI assert the byte scan on every run, with a control that
`icp_sealed_secret_set` _is_ present, so the check cannot pass by reading the wrong
file.

## Can I just add a getter?

Not in production, but not because it would hand the controller anything new: **a
controller can obtain the secret anyway**, with no endpoint at all.

1. **Install code that decrypts.** vetKD binds the key to the canister id, not to the
   module hash, so any module installed on that canister can derive the same key.
2. **Read it out of a snapshot.** `take_canister_snapshot`, then
   `read_canister_snapshot_data` with `kind = variant { stable_memory : record { offset; size } }`
   for the Rust canister (`wasm_memory` for the Motoko one).

What a getter costs:

- **It ships the plaintext to a boundary node.** The reply is not encrypted end to
  end, so this undoes on the way out what sealing achieved on the way in. A query
  is the less bad choice: an update reply is also written into replicated state.
- **It weakens what the code proves.** "The published code never returns the
  plaintext" is something a reader can check. "…unless the caller is a controller"
  makes the guarantee rest on the controller set being exactly what you believe.
- **It leaves no trace.** Installing leaky code changes the module hash, which is
  visible in the state tree. A call to a getter is not publicly visible.

`matches` survives all three: it returns one bit about a value the caller already
holds.

## Client bindings

`seed/src/declarations/` is **generated** from
`rust/canister/sealed_secrets_canister.did` by
[`@icp-sdk/bindgen`](https://www.npmjs.com/package/@icp-sdk/bindgen): run
`cd seed && npm run bindings` whenever the interface changes. `local-test.sh` fails if
you forget. Only the NNS registry interface in `seed/src/idl.ts` is hand-written,
because there is no `.did` for it here and it needs two of its methods.
