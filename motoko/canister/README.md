# A Motoko sealed-secrets canister

> ## ⚠️ EXPERIMENTAL
>
> Depends on an **unaudited** BLS12-381 implementation
> ([`../bls12-381`](../bls12-381)). It demonstrates that Motoko *can* do this,
> not that it should yet.

The same design as [`../../rust/canister`](../../rust/canister), on this repo's
pure-Motoko crypto instead of `ic-vetkeys`. It speaks the identical Candid
interface, so [`../../seed`](../../seed) drives it with no changes — which is the
claim worth testing, and `scripts/local-test.sh` step 13 tests it.

## What it proves

Everything in `mops test` runs against fixed vectors. This canister is the first
thing here that talks to a live subnet. Verified end to end on a local network:

| | |
|---|---|
| `vetkd_public_key` and `vetkd_derive_key` from Motoko | ✅ |
| The reply **verified** against a master key compiled into the Wasm — `public_key_matches_master = opt true` | ✅ |
| The unmodified TypeScript seeder seals to it, and it trial-decrypts before storing | ✅ |
| An authenticated HTTPS outcall returns **200**, and **401** with a wrong credential | ✅ |
| The secret survives an upgrade with no re-seeding | ✅ |
| A record-shape change is refused at install rather than breaking later | ✅ |

That last row matters more than it looks: `401` with a wrong credential is what
shows the *value* of the secret is what authenticated, rather than merely that a
request went out.

## Layout

Laid out per the `reviewing-motoko` skill: types at the bottom, `lib/` for logic
with state passed in, `mixins/` for endpoints, and a `main.mo` that holds only
state and composition.

| | |
|---|---|
| `Types.mo` | Candid types, mirroring `rust/canister/src/types.rs`. |
| `Store.mo` | Config and the stored secrets. `SealedRecord` holds the plaintext — the header comment says why. |
| `lib/Format.mo` | The wire format — the `rust/core` equivalent. Deliberately not in either library: it is specific to this application, not to vetKD. Its golden vectors are the same bytes `rust/core/tests/golden.rs` and `seed/src/format.test.ts` assert. |
| `lib/Keys.mo` | vetKD calls, verification, and the vetKey cache. Read the header comment — it is where the two canisters deliberately diverge. |
| `lib/Guard.mo` | Endpoint guards. In a module rather than at mixin top level, because a bare `func` there is implicitly stable and traps at runtime. |
| `lib/Http.mo` | The outcall surface, for the same reason. |
| `mixins/Secrets.mo` | The six endpoints meant to be a standard. |
| `mixins/Demo.mo` | `call_api_with_secret` and its transform — one application's answer to "now what", which a real canister replaces. |
| `Main.mo` | The composition root: state declarations and two `include`s, nothing else. |

## Where it differs from the Rust canister

**What persists.** The vetKey cache survives upgrades here and does not there.
Under orthogonal persistence that is free, whereas Rust would have to serialise
it into `ic-stable-structures` and then pay stable-memory access on every read.
Neither canister has a plaintext cache any more — the record holds the secret.
`lib/Keys.mo` has the full reasoning, including why none of this is a
confidentiality argument.

**No test hooks.** The Rust canister has `secret_reveal` behind
`--features test-hooks` so a human can watch the round trip work. Motoko has no
feature flags — and it turns out not to need any. `icp_sealed_secret_matches`
answers "is the right value set?" from a build that ships, which is what the Rust
canister's own documentation recommends over a reveal hook anyway. Step 13 of
`local-test.sh` verifies the secret without ever asking for it.

**How a schema change fails.** Changing `SealedRecord` — which this repo did,
moving from stored ciphertext to stored plaintext — is rejected by Motoko at
*install* time:

```
RTS error: Memory-incompatible program upgrade
```

The Rust canister accepts the same change and then **traps on the first read**,
inside `SealedRecord::from_bytes`, because `ic-stable-structures` decodes lazily
and Candid matches fields by hash. Motoko's failure is louder and earlier, which
is the better of the two: an upgrade that cannot work is refused rather than
installed and left to surface during a production call.

Neither is a bug. It is the cost of having a persisted-state schema, and the fix
is the same either way — a migration, or a `--mode reinstall` when the data is
disposable:

```bash
icp canister install sealed-secrets-motoko -e local --mode reinstall \
  --args '(record { key_name = "key_1" })' --yes
```

**No Candid metadata step.** `icp.yaml` re-marks the Rust canister's
`candid:service` public. Doing the same here breaks the build: `moc` already
embeds the section, and `ic-wasm metadata` *appends* rather than replaces, so the
module ends up with two and the replica rejects it outright —
`Wasm module has an invalid custom section. Invalid custom section: name
candid:service already exists`. Tooling resolves the interface from `moc`'s own
section without help.

## Running it

```bash
icp network start local --background
icp deploy -e local --yes
./scripts/local-test.sh     # steps 1-12 Rust, step 13 Motoko
```

```bash
mops test    # golden vectors for the wire format
```
