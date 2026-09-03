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
implementation. `rust/core` here is already shaped to be that module's format layer.

### Revisit `info` as a query

The PoC makes `icp_sealed_secret_info` an update, because the canister asks
`vetkd_public_key` for its own key rather than deriving it from a compiled-in constant.
That was a deliberate trade: an install-time `key_source` argument would let `info` be a
query, but getting it wrong silently orphans every sealed ciphertext, and it forces a
per-network build configuration for no security gain (the client-side comparison is
where the value is).

A library could have both: derive offline *when* a master key is compiled in for the
configured name, fall back to `vetkd_public_key` otherwise, and expose whichever it used
in `info` so a client knows what it is comparing against. Worth doing only if a query
turns out to matter to somebody — for a seeding flow, one update call is free.

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
async fn ask_model(prompt: String, idempotency_key: String) -> String {
    let key = sealed_secret_str("dummy_api_key").await.expect("not sealed");
    // key is Zeroizing<String>. See "Guidance for using a secret" below for what
    // this call has to get right — constant URL, transform, idempotency key, and
    // never returning the response body.
    call_api(&key, &prompt, &idempotency_key).await
}
```

Name the internal accessor `sealed_secret_plaintext` so that
`#[update] fn leak() -> String { sealed_secret_plaintext("x") }` reads as an obvious
defect in review.

### Guidance for *using* a secret, not just storing one

A library that only covers sealing and decryption ships half the problem. The hazards
adopters will hit are all downstream of `sealed_secret(...)` returning a plaintext, and
none of them are obvious. The PoC's `call_api_with_secret` is a worked example of all four;
the library should carry them as documentation, and possibly as a helper.

- **Outcalls fan out to every node**, so one logical call becomes N real HTTP requests. A
  `GET` does not care; a `POST` that charges a card or sends an email happens N times
  unless the API deduplicates. Any non-idempotent call needs an idempotency key, and it
  belongs in the *caller's* hands — only they know whether this is a retry of one
  operation or a new one.
- **A transform is mandatory**, because consensus needs byte-identical responses and
  `Date`, request ids and cookies are not. Stripping response headers also stops a hostile
  endpoint reflecting the credential into replicated state.
- **Never return the response body** to the caller of a canister method. Endpoints that
  echo request headers are common, and echoing your own `Authorization` header back
  through a reply undoes the sealing entirely.
- **Never take the URL as a parameter.** That is an exfiltration primitive; a controller
  could achieve it by installing code anyway, but shipping the capability as an endpoint
  is gratuitous.

There is a case for a `sealed_secrets::http` helper that takes a secret name, a header
name, a constant URL and an idempotency key, and enforces the last three points by
construction. Worth weighing against the extra surface: a canister that needs anything
unusual would bypass it, and a helper people bypass is worse than documentation people
read. The PoC deliberately does not have one.

Whatever form it takes, the security note belongs beside it: the request context, headers
included, enters replicated state on **every** node before any of them executes the call.
That is the moment the secret is most widely spread, and on a non-TEE subnet it is
readable by every node operator.

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

`rust/core` in this repo is a working demonstration of the seam.

### Idempotent re-seeding (`matches` now exists; the diffing does not)

`icp_sealed_secret_matches` is implemented in the PoC, because an operator needs to confirm
the right value is deployed. What is *not* implemented is using it to make `icp deploy`
idempotent.

IBE is randomised, so a client can never compare its ciphertext to the stored one, and
re-sealing on every deploy is not free: replacing a ciphertext invalidates the
canister's plaintext cache and forces another `vetkd_derive_key`.

```candid
icp_sealed_secret_matches : (text, blob) -> (variant { Ok : bool; Err : … });
```

The client re-encrypts its candidate with a fresh seed; the canister decrypts both and
compares in constant time. A deploy would call it per declared secret and re-seal only
what differs. No new key material, nothing plaintext-derived at rest, and
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
precisely to avoid repeating this; `rust/core/tests/golden.rs` has the regression test.

Also: `derive_unencrypted_vetkey`'s doc comment claims `Ok(VetKey)` but it returns
`Result<Vec<u8>, _>`.

### Example and docs

A `dfinity/examples` entry, plus a **`VERIFYING.md`** covering the subnet's chain-key and
SEV status, module-hash verification against a reproducible build, and — most importantly
— **verifying the controller set**, since that is the access-control boundary. It should
be explicit that the goal is a controller set that is small, known and not shared, *not*
an empty one: `set` is controller-gated, so a blackholed canister can neither be seeded
nor rotated.

Without that file the example teaches a false sense of security, and gets the emphasis
wrong in a way that costs adopters rotation.

The README should also say plainly that `basic_timelock_ibe`'s all-zero transport seed
is correct *there* — the key is meant to become public — and wrong for confidential
secrets, since it makes the derived key readable by anyone who can read subnet state
and skips `decrypt_and_verify` entirely.

---

## 2. icp-cli integration

Deferred on purpose: seeding works fine as a client-side script, and the script's
preflight and derivation logic is exactly what the CLI would absorb.

### What a canister must implement, and how the CLI finds out

Only **two** methods are load-bearing for a tool that seals:

```candid
icp_sealed_secret_info : () -> (variant { Ok : SealedSecretInfo; Err : … });
icp_sealed_secret_set  : (text, blob) -> (variant { Ok : nat64; Err : … });
```

`info` tells the client what to encrypt to and lets it cross-check its own offline
derivation; `set` receives the ciphertext. With those two a tool can seal.

The rest is graded rather than required. `matches` is the one worth pressing for — it is
what lets an operator confirm the right value is deployed, and what would let `icp deploy`
re-seal only what changed; a canister without it forces the CLI to re-seal blindly.
`unset` is housekeeping, `list` helps diffing, and `self_test` is a deploy-time health
check. A standard that demands two methods and recommends a third is a far easier sell
than one that demands six, and the CLI should degrade rather than refuse when the
optional ones are absent.

**Discovery is already solved and needs no new mechanism.** `icp canister metadata
<canister> candid:service` returns the canister's full interface without a single update
call, so the CLI can check which of these the canister has and fail early naming what
is missing, instead of surfacing a raw `CanisterError` from calling a method that does not
exist. This works only if the canister embeds `candid:service` in its wasm metadata —
which the `@dfinity/rust` recipe does by default, and which this PoC's build steps copy
from it.

**What the canister does with the secret is none of the CLI's business.** icp-cli seeds;
the canister uses. That boundary is worth stating because the two halves have very
different failure modes — a seeding bug is loud and immediate, while a usage bug (no
idempotency key on a mutating outcall, returning a response body that echoes the
credential) is silent and expensive. The CLI cannot check for those; documentation and the
library have to.

**Which canister receives which secret** is answered by the manifest: the `secrets:` block
sits under the canister that owns them, and icp-cli already resolves canister name →
canister ID per environment (`ctx.get_canister_id_for_env`). No new plumbing.

### The asymmetry that shapes the UX

`settings.environment_variables` works for *any* canister, because the **replica**
implements it — the canister just reads what it is given. Sealed secrets cannot work that
way: the decryption happens in the canister's own code, so it only works for canisters
that opted in by linking the library.

That has consequences the CLI design must absorb:

- It is **not** a drop-in replacement for plaintext env vars, and should not be presented
  as one. Some canisters simply cannot accept a sealed secret.
- `icp deploy` must fail clearly, and early, when a canister declares `secrets:` but does
  not implement the interface — before building or installing anything.
- A useful error names the fix: "canister `backend` declares 2 secrets but does not
  implement `icp_sealed_secret_set`; add `ic-vetkeys`' sealed-secrets macros to it."
- Documentation has to lead with the adoption cost, not bury it.

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
      DUMMY_API_KEY: { env: DUMMY_API_KEY }
```

No inline values, no file paths. The manifest then cannot carry a secret, stays safe to
commit, and bundles are trivially safe because there is nothing to inline.

Placement is a **sibling of `settings`**, not inside it: `Settings` is the manifest
projection of the management canister's `canister_settings` record
(`impl From<Settings> for CanisterSettings`, `rust/icp/src/canister/mod.rs:230`), and
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
`get_subnet_for_canister` (`rust/icp/src/operations/canister_migration.rs:113`), so
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

**The CLI needs no read-back endpoint to know it worked.** `set` trial-decrypts before
storing, so a successful `set` *is* the proof that the canister can read the secret. That
is worth stating explicitly, because the obvious alternative — a getter the tool calls to
confirm — is exactly the endpoint that must not exist (see the README on why). The
verification and the no-getter rule are the same design decision viewed from two sides.

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

`motoko/` holds an **experimental, unaudited** BLS12-381 implementation for
Motoko: the whole field tower (`Fp`, `Fp2`, `Fp6`, `Fp12`), both curve groups
with compression, the optimal ate pairing, HKDF-SHA256, SHAKE256,
`expand_message_xmd`, `hash_to_scalar`, RFC 9380 `hash_to_curve`, IBE decryption,
`decrypt_and_verify`, and offline derived-public-key computation. 102 tests — see [motoko/vetkeys/README.md](./motoko/vetkeys/README.md).

Upstream has none of this. `backend/mo/ic_vetkeys/src/` has `key_manager`,
`encrypted_maps`, `ManagementCanister` and `Types`, and no mops package provides
pairing arithmetic.

**How it is tested.** Every layer against vectors generated from `ic_bls12_381`
itself; the hash layer additionally against Python's `hashlib`, a third
implementation unrelated to either; and `decrypt_and_verify` against a real
`vetkd_derive_key` reply lifted from `ic-vetkeys`' own tests, where it is
annotated as having been produced by the replica's threshold implementation.

**What it costs.** 3.57 billion instructions to unwrap and verify the subnet's
reply, plus 1.79 billion to decrypt — about 5.4 billion cold against the 40
billion an update call gets, paid once because both results are cached. On the
decryption alone, the like-for-like comparison, that is about 10.8× the Rust
implementation measured the same way. 85% of the gap is one thing: this port
reduces with `%` where the reference uses Montgomery form, so it divides where
the reference multiplies. Fixing that, not switching to a limb representation, is
the optimisation if anyone ever needs one.

**What is missing.** A canister that actually runs it. Everything is exercised by
`mops test` and `mops bench`, which do run in a replica, but always against fixed
vectors. No Motoko canister has yet called `vetkd_derive_key` and verified what
came back.

**And it is unaudited.** Nothing here should reach production before a
cryptographer has been through it. The value is that the conversation can be
about reviewing an implementation rather than speculating about whether one is
possible.

**The asks.**

*vetKeys team:* IBE in the Motoko library, so `mo:ic-vetkeys` reaches parity with
the Rust crate. This port is evidence it can be done, and a starting point for
doing it properly.

*Motoko team:* [motoko/vetkeys/PROPOSAL.md](./motoko/vetkeys/PROPOSAL.md) — a measured case that
one missing runtime primitive accounts for most of the 10× gap. Motoko's `Nat` is
libtommath, which already implements Barrett and Montgomery reduction, modular
exponentiation and modular inversion; the runtime compiles in an explicit subset
that excludes all of them. The cheapest ask is bit shifts on `Nat`, because
`mp_div_2d` and `mp_mul_2d` are *already linked* and just unreachable — exposing
them would let libraries fix the rest themselves.

### Reusing the Rust implementation instead

Worth pursuing in parallel, since reusing audited Rust beats maintaining a second
implementation. Not usable today.

In **`dfinity/motoko`**, branch **`bartosz/components-mvp`** (`168f5265`,
2025-10-23; siblings `bartosz/mo-wit-wac`, `bartosz/no-prims`, and the older
`ryan/component-call*` from 2024) there is an `ic_sig_verifier` component
wrapping `ic-verify-bls-signature` — the *same* `ic_bls12_381` that `ic-vetkeys`
uses — called from Motoko as:

```motoko
public func verifyBlsSig(signature : Blob, message : Blob, public_key : Blob) : Result.Result<(), Text> =
    ((prim "component:ic-sig-verifier:verify-bls-sig") : (Blob, Blob, Blob) -> Result.Result<(), Text>)(...)
```

That is almost exactly the boundary needed. The blocker: the build emits a Wasm
**component** (`wasm-tools component new` + `wac compose`) run under `wasmtime
run` with a WASI adapter, and the IC replica installs **core modules**. The branch
is also stale since 2025-10-23, requires `MOC_UNLOCK_PRIM`, and has no record
support — the last of which does not matter here, since the API would be
Blob-only.

If a core-module composition path (e.g. Binaryen `wasm-merge`) lands, the thing to
ask for is a `mo:component/ic-vetkeys-ibe` exposing
`decryptAndVerify(encryptedVetkey, tsk, dpk, input) -> Blob` and
`ibeDecrypt(ct, vetkey) -> Blob`: small, purely synchronous, Blob-in/Blob-out,
with Motoko keeping the async `vetkd_derive_key` call it can already make via
`ManagementCanister.mo`. That generalises well beyond sealed secrets.

### Options for a Motoko canister today

In descending order of how much unreviewed code they require:

1. **Put the secret-consuming logic in a Rust canister.** Nothing new to trust.
2. **Have a small Rust canister hold the sealed secret** and serve it to one
   authorised Motoko caller on the same subnet. Keeps the plaintext inside the
   same SEV trust domain, but widens it — the secret crosses a canister boundary
   and its confidentiality now depends on that caller check being right.
3. **Use the port in `motoko/`.** Tested against the reference, but unaudited, and
   still needs the two pieces listed above. Reasonable for a prototype; not for
   production before a cryptographer has read it.

There is no pairing-free route to "encrypt to a public key" with IBE.

### Why the golden vectors exist

[`rust/core/tests/golden.rs`](./rust/core/tests/golden.rs) and
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
argument that motivated it does not hold: one `vetkd_derive_key` with `key_1` costs
26_153_846_153 cycles (`test_key_1`: 10_000_000_000), paid once per canister lifetime plus
once per upgrade, because one identity serves every secret. Recorded here so the decision
is not relitigated.
