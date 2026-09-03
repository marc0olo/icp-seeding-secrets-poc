# Follow-ups

Everything deliberately left out of the [PoC](./README.md), and what it would take to
do properly. Three tracks, roughly in dependency order.

The PoC's job is to make these conversations concrete. None of this should start
before the interface in the README has been argued over.

---

## 1. Productize into `ic-vetkeys`

Target: a `sealed_secrets` module in
[`dfinity/vetkeys`](https://github.com/dfinity/vetkeys) under
`backend/rs/ic_vetkeys/src/`, with the PoC canister becoming the reference
implementation. `crates/core` here is already shaped to be that module's format layer.

### Macros, so adoption is three lines

`export_encrypted_maps_canister!` assumes the canister *is* the library. Sealed secrets
are almost always an add-on to a canister that already has its own `#[init]`, so the
state / lifecycle / endpoints split matters more here:

```rust
export_sealed_secrets_state!("", [memory(10), memory(11)]);  // state + accessors, no lifecycle
export_sealed_secrets_endpoints!();                          // the endpoints
export_sealed_secrets_canister!(…);                          // all of it, drop-in
```

```rust
#[init]
fn init(key_name: String) { sealed_secrets_setup(key_name); /* …your own init… */ }

#[update]
async fn ask_model(prompt: String) -> String {
    let key = sealed_secret_str("openai_api_key").await.expect("not sealed");
    call_api(&key, &prompt).await          // key is Zeroizing<String>
}
```

Name the internal accessor `sealed_secret_plaintext` so that
`#[update] fn leak() -> String { sealed_secret_plaintext("x") }` reads as an obvious
defect in review.

### Pluggable access control

A guard-function macro parameter, matching `ic_cdk`'s own `#[update(guard = …)]` idiom:

```rust
export_sealed_secrets_endpoints!(manage_guard = my_sns_guard);
```

**Not** the existing `AccessControl` trait — that is built for per-key, per-user rights
stored in stable memory (`Storable + IntoEnumIterator + Copy + Ord`) and would force a
type parameter through `SealedSecrets`, the handle, the macros and every accessor, for
a domain with exactly one privileged role.

### A Cargo feature split

The crate already builds host-side — `ic0` 1.1.0 has panicking `non_wasm` stubs
(`sys.rs:153`) and the vetkeys repo runs host `cargo test` today. So this is hygiene,
not a blocker. It matters because a CLI linking the crate wants neither
`ic-stable-structures` nor `ic-cdk`'s executor, and does not want to be dragged along
by `ic-cdk` major-version churn.

```toml
default = ["canister"]
canister = ["dep:ic-cdk", "dep:ic-stable-structures", "dep:futures", "dep:serde_cbor", …]
```

Gate `key_manager`, `encrypted_maps`, `types` and `utils::management_canister`; leave
all pure crypto unconditional. Keep the feature **positive and default-on** so Cargo's
additive unification points the right way. Minor version bump, not breaking — the only
theoretical break is a consumer already passing `default-features = false`, which is a
no-op today.

`crates/core` in this repo is a working demonstration of the seam.

### Idempotent re-seeding: `icp_sealed_secret_matches`

IBE is randomised, so a client can never compare its ciphertext to the stored one, and
re-sealing on every deploy is not free: replacing a ciphertext invalidates the
canister's plaintext cache and forces another `vetkd_derive_key`.

```candid
icp_sealed_secret_matches : (text, blob) -> (variant { Ok : bool; Err : … });
```

The client re-encrypts its candidate with a fresh seed; the canister decrypts both and
compares in constant time. No new key material, nothing plaintext-derived at rest, and
the oracle is confined to principals who could already read the plaintext by upgrading
the canister.

Rejected alternatives, and why:

- **A plaintext hash in `list`.** For structured or low-entropy secrets a public
  `SHA-256(plaintext)` is an offline-verifiable oracle for guesses.
- **An HMAC under a vetKD-derived key.** Cryptographically fine, operationally useless:
  the client cannot compute it, so it can only ask "does your tag equal X" — the same
  oracle by another name — and it puts a plaintext-bound value at rest.
- **Deterministic sealing** (deriving the IBE seed from the plaintext). That *is* a
  fingerprint again, and it destroys IND-CPA across re-uploads.

### Rotation

The PoC carries `epoch` in the identity and per record, but never bumps it. A `rotate`
endpoint would mean "new writes use the new identity" — non-destructive, because vetKD
derives a key for any identity, so the canister just derives one extra vetKey per epoch
still in use.

Be honest about the value: the derived key cannot be compromised independently of the
subnet master key, so if a secret leaks you rotate the *secret*, not the key. The real
uses are crypto-agility for a future ciphertext format, and forcing a re-seal sweep.
The field is in the wire format from day one only because retrofitting one is far more
painful than carrying four unused bytes.

### Also worth carrying over

- **`StableCell::init` keeps an existing value.** Editing a config constant in source
  and upgrading is a silent no-op. `self_test` must therefore report the *effective*
  config read back from stable memory, not the compiled-in one. The PoC already does.
- **Concurrency.** Two cold callers both derive. Accept it: derivation is deterministic
  in `(canister_id, context, input, key_id)`, so both get the identical key and the only
  cost is a duplicate fee. Rejecting the second caller is bad UX in a business path, and
  making it wait is not implementable — the two are separate message executions and
  neither can await the other's future.
- **The `async fn get(&self, …)` trap.** It cannot compile against state in
  `thread_local! { RefCell<…> }`: the borrow would be held across the await and panic on
  re-entry. `KeyManager` already works around this; the PoC splits into a synchronous
  stable-state type plus a `Clone` handle that owns its config and borrows nothing.

### A bug to fix while in there

`management_canister::compute_vrf` derives its public key via
`MasterPublicKey::for_mainnet_key(&key_id)`. `for_mainnet_key` matches `"test_key_1"`
and returns `PROD_G2_TEST_KEY_1`, which differs from `POCKETIC_G2_TEST_KEY_1`
(`utils/mod.rs:411` vs `:422`). Under PocketIC, `compute_vrf` with `test_key_1`
therefore derives the wrong public key. The PoC's `MasterKeySource` is explicit
precisely to avoid repeating this; `crates/core/tests/golden.rs` has the regression test.

Also: `derive_unencrypted_vetkey`'s doc comment claims `Ok(VetKey)` but it returns
`Result<Vec<u8>, _>`.

### Example and docs

A `dfinity/examples` entry, plus a **`VERIFYING.md`** covering module-hash verification
against a reproducible build, controller-set verification, and the subnet chain-key and
SEV checks. Without that last file the example teaches a false sense of security.

The README should also say plainly that `basic_timelock_ibe`'s all-zero transport seed
is correct *there* — the key is meant to become public — and wrong for confidential
secrets, since it makes the derived key readable by anyone who can read subnet state
and skips `decrypt_and_verify` entirely.

---

## 2. icp-cli integration

Deferred on purpose: seeding works fine as a client-side script, and the script's
preflight and derivation logic is exactly what the CLI would absorb.

### Command surface

```
icp canister secret set | list | unset
```

Files follow the existing `commands/canister/settings/` group; registering a subcommand
is three edits (module declaration, a variant in `commands/canister/mod.rs`, an arm in
`dispatch` in `main.rs`), then `./scripts/generate-cli-docs.sh`.

Value sources: `--from-env`, `--from-file`, `--from-stdin`, and a `dialoguer::Password`
prompt on a TTY. **No `--value` flag** — argv is world-readable via `ps`, lands in shell
history, and is echoed into CI logs.

### Manifest: names and env vars only

```yaml
canisters:
  - name: backend
    secrets:
      OPENAI_API_KEY: { env: OPENAI_API_KEY }
```

No inline values, no file paths. The manifest then cannot carry a secret, stays safe to
commit, and bundles are trivially safe because there is nothing to inline.

Placement is a **sibling of `settings`**, not inside it: `Settings` is the manifest
projection of the management canister's `canister_settings` record
(`impl From<Settings> for CanisterSettings`, `crates/icp/src/canister/mod.rs:230`), and
`icp canister settings show/sync` treat it as such. A sealed secret is application state
written through an application endpoint.

**A trap worth knowing:** `icp project show` does `serde_yaml::to_string(&project)`
(`commands/project/show.rs:25`), and today already prints file-backed
`environment_variables` values in the clear. The canonical `Canister` model must
therefore carry the *source*, never the resolved value; resolution happens inside the
operation, at seal time.

### Enforce the subnet properties

The CLI should hard-fail on mainnet when the subnet is not SEV-SNP or does not hold the
vetKD key, with an explicit override flag. It already resolves canister → subnet via
`get_subnet_for_canister` (`crates/icp/src/operations/canister_migration.rs:113`), so
this is one extra registry query — the same two checks
[`seed/src/preflight.ts`](./seed/src/preflight.ts) makes.

### Deploy integration

A new `Task::phase("Sealing secrets:")` in `operations/deploy.rs::deploy()`, after
install and before `sync()` — secrets are configuration, and a failure should not come
after a full asset upload.

Note `install_code` is **status-preserving**: a canister left Stopped is still Stopped
after install, so the update call would reject. The existing `start_canister` +
`wait_until_serving_queries` block lives inside `sync()` (`deploy.rs:528-578`) and only
covers canisters that have sync steps; it needs extracting into a shared
`ensure_running` helper.

Not a `SyncStep`: those only run during `icp deploy`, so one could never back
`icp canister secret set`, and you would end up with two implementations.

Values should be updatable rather than write-once — seal only what is missing by
default, `--reseal-secrets` to force, moving to `matches`-based diffing once available.

### Two mechanical gotchas

- **Key selection needs a network-manifest field**, `vetkd-key: <master>:<name>`, not
  inference from `NetworkSelection`. That tells you which network was *named*, not what
  it *is*, and a wrong guess produces undecryptable ciphertext silently. The `<master>`
  half is not redundant: mainnet and PocketIC hold different master keys under the same
  name.
- **`IbeSeed::random` will not compile there.** It is bound on `rand` 0.8 traits while
  icp-cli pins `rand` 0.10. Use `IbeSeed::from_bytes` with 32 bytes from the CLI's own
  CSPRNG — `from_bytes` uses a 32-byte input directly, so the security property is
  identical.

---

## 3. A Motoko library

**The gap.** Canister-side IBE decryption needs BLS12-381 **pairings**, plus G1/G2
decompression and a G2 scalar multiplication. `backend/mo/ic_vetkeys/src/` has only
`key_manager`, `encrypted_maps`, `ManagementCanister` and `Types` — no IBE, and no mops
package provides pairing arithmetic. It is a much harder target than the secp256k1 work
in `motoko-bitcoin`: a pairing is orders of magnitude more expensive than a scalar
multiplication, so per-message cycle cost needs benchmarking before anyone commits to a
pure-Motoko implementation.

There is no pairing-free route to "encrypt to a public key" with IBE.

### Does the Wasm component model solve it?

Right shape, not usable today. In **`dfinity/motoko`**, branch
**`bartosz/components-mvp`** (`168f5265`, 2025-10-23; siblings `bartosz/mo-wit-wac`,
`bartosz/no-prims`, and the older `ryan/component-call*` from 2024) there is an
`ic_sig_verifier` component wrapping `ic-verify-bls-signature` — the *same*
`ic_bls12_381` that `ic-vetkeys` uses — called from Motoko as:

```motoko
public func verifyBlsSig(signature : Blob, message : Blob, public_key : Blob) : Result.Result<(), Text> =
    ((prim "component:ic-sig-verifier:verify-bls-sig") : (Blob, Blob, Blob) -> Result.Result<(), Text>)(...)
```

That is almost exactly the boundary we would need. The blocker: the build emits a Wasm
**component** (`wasm-tools component new` + `wac compose`) run under `wasmtime run` with
a WASI adapter, and the IC replica installs **core modules**. Also stale since
2025-10-23, requires `MOC_UNLOCK_PRIM`, and has no record support yet — irrelevant for
us, since the API would be Blob-only.

### The two asks

1. **Motoko team.** What is the current state, and is a **core-module** composition path
   (e.g. Binaryen `wasm-merge`) on the roadmap? If so, a `mo:component/ic-vetkeys-ibe`
   exposing `decryptAndVerify(encryptedVetkey, tsk, dpk, input) -> Blob` and
   `ibeDecrypt(ct, vetkey) -> Blob` is small, purely synchronous and Blob-in/Blob-out.
   Motoko keeps the async `vetkd_derive_key` call it can already make via
   `ManagementCanister.mo`. This generalises well beyond sealed secrets.
2. **vetKeys team.** IBE in the Motoko library, so `mo:ic-vetkeys` reaches parity with
   the Rust crate.

Until one lands, a Motoko canister needing this has two options: put the
secret-consuming logic in a Rust canister, or have a small Rust canister hold the sealed
secret and serve it to one authorised Motoko caller on the same subnet — which keeps the
plaintext inside the same SEV trust domain, but is a real widening worth acknowledging.

### Why the golden vectors exist

[`crates/core/tests/golden.rs`](./crates/core/tests/golden.rs) and
[`seed/src/format.test.ts`](./seed/src/format.test.ts) assert byte-for-byte identical
values. A Motoko port asserting the same vectors is provably interoperable with both,
before any integration test is written.

---

## Considered and rejected

**A pairing-free construction.** The canister can obtain a vetKey with no pairing at all
by passing the G1 identity element as the transport key — the reply's `c3` field simply
*is* the 48-byte vetKey. HKDF that into a secp256k1 private key, publish the public key,
and let clients do standard ECIES. Motoko would then need one scalar multiplication
(`motoko-bitcoin` already has secp256k1), and no pairings.

Rejected on two grounds. It is a construction we would be inventing, and the cost
argument that motivated it does not hold: one `vetkd_derive_key` is roughly 1–3 US cents
(`VETKD_FEE` is 10B cycles at the 13-node reference, scaled by replication factor —
`ic/rs/config/src/subnet_config.rs:130`), paid once per canister lifetime plus once per
upgrade, because one identity serves every secret. Recorded here so the decision is not
relitigated.
