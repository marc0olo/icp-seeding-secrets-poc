# Seeding a canister with secrets via vetKeys

A proof of concept for getting a secret — an API key, a token — into a **deployed**
canister without the plaintext ever appearing in an ingress message, a manifest, a
shell history, or a CI log.

The client encrypts the secret to a public key it derives **offline**, sends the
ciphertext in an ordinary update call, and only the target canister can recover the
plaintext. On a SEV-SNP subnet, memory encryption and a launch-measurement-keyed
data disk then protect the decrypted value from node operators.

This exists to be argued with. The interface is a starting proposal, not a standard.
For what productizing it would look like, see **[FOLLOW-UPS.md](./FOLLOW-UPS.md)**.

> **Do not deploy this as-is.** It ships a `secret_sha256` test hook, and the whole
> guarantee is void unless the canister is blackholed or governed — see
> [Security model](#security-model).

---

## The problem this solves

icp-cli's current answer to "my canister needs an API key" is a plaintext canister
setting:

```yaml
settings:
  environment_variables:
    API_KEY: { path: ./secrets/api-key }   # sent in the clear via update_settings
```

That value travels in an ingress message and lands in replicated state unencrypted.
This repo is the encrypted equivalent.

## Why it needs vetKD

To send a secret to someone you encrypt to their public key, and they decrypt with
their private key. **A canister has no private key and cannot make one:** its whole
memory is replicated across every node of its subnet, checkpointed to disk, and
shipped to new nodes during state sync. Even its randomness is not private —
`raw_rand` derives from the round's random tape, a threshold signature every node
sees. A canister fundamentally has no secrets from its own subnet's replicas.

vetKD supplies the missing piece. The subnet *collectively* holds a master secret,
split across nodes so no single node has it. From that:

- **anyone** can compute, offline, the public key belonging to a given
  (canister, context) pair, starting from a published master public key; and
- **only that canister** can ask the subnet to reconstruct the matching private key,
  via `vetkd_derive_key`.

That is a real asymmetric keypair for a canister. "Identity-based" means the public
key is *derived from a name* — the canister id plus a context string — rather than
being a random blob someone had to generate and distribute. That is why step 1 below
is arithmetic you can do on a laptop before the canister has executed a single
instruction.

**Is IBE required?** You need some public-key encryption where the canister holds the
private half, and vetKD is the only mechanism on the IC that gives a canister a
private key at all. Threshold ECDSA and Schnorr produce *signing* keys, and the
management canister exposes no decryption operation for them, so they cannot receive
a secret. Given vetKD, IBE is both the natural fit and the one already implemented
and reviewed on both sides by `ic-vetkeys`.

## The flow

```mermaid
sequenceDiagram
    autonumber
    actor Dev as Developer / CI
    participant Script as Seeding script (host)
    participant Reg as Registry canister
    participant Can as Target canister
    participant Mgmt as Management canister<br/>(own subnet)

    Dev->>Script: OPENAI_API_KEY=… npm run seal

    rect rgba(120,120,120,.12)
    note over Script,Reg: Preflight — two properties, both required, neither implies the other
    Script->>Reg: get_subnet_for_canister(cid)
    Reg-->>Script: subnet_id
    Script->>Reg: get_subnet(subnet_id)
    Reg-->>Script: SubnetRecord { features.sev_enabled, chain_key_config }
    Script->>Script: assert sev_enabled == true
    Script->>Script: assert the vetKD key is present
    end

    rect rgba(120,120,120,.12)
    note over Script: Offline — pure arithmetic, zero network calls
    Script->>Script: mpk = MasterPublicKey.productionKey(key_1)
    Script->>Script: dpk = mpk.deriveCanisterKey(cid).deriveSubKey(CONTEXT)
    end

    Script->>Can: icp_sealed_secret_info()  [query]
    Can-->>Script: { public_key, context, identity, epoch }
    Script->>Script: assert public_key == dpk — else ABORT

    Script->>Script: ct = IbeCiphertext.encrypt(dpk, identity, secret, random seed)
    Script->>Can: icp_sealed_secret_set("OPENAI_API_KEY", ct)

    rect rgba(120,120,120,.12)
    note over Can,Mgmt: set is async and trial-decrypts — a wrong key fails HERE, not in production
    Can->>Can: is_controller(caller)? ; IbeCiphertext::deserialize(ct)
    Can->>Mgmt: raw_rand()
    Mgmt-->>Can: 32 bytes
    Can->>Can: tsk = TransportSecretKey::from_seed(seed)
    Can->>Mgmt: vetkd_derive_key { context, identity, key_id, tsk.public_key() }
    Mgmt-->>Can: EncryptedVetKey (192 B)
    Can->>Can: dpk' = compiled-in master key → derive_canister_key(self) → derive_sub_key(CONTEXT)
    Can->>Can: vk = EncryptedVetKey.decrypt_and_verify(tsk, dpk', identity)
    Can->>Can: trial ct.decrypt(vk) — else Err(InvalidCiphertext)
    Can->>Can: store ct in STABLE memory ; cache vk + plaintext in heap
    end

    Can-->>Script: Ok(revision)
    Script-->>Dev: ✓ Sealed OPENAI_API_KEY
```

Later, whenever the secret is used, the canister decrypts from the stored ciphertext
and caches the plaintext in the heap. After an upgrade it repeats one
`vetkd_derive_key` and carries on — **you never re-seed**.

```mermaid
sequenceDiagram
    autonumber
    actor User
    participant Can as Canister
    participant Stable as Stable memory
    participant Heap as Heap caches
    participant Mgmt as Management canister

    User->>Can: some_endpoint()
    Can->>Heap: plaintext cache (name, revision)?
    alt cache hit — the normal case, free
        Heap-->>Can: Zeroizing<Vec<u8>>
    else cache miss — first use, or after an upgrade
        Can->>Stable: read ciphertext
        Can->>Heap: vetKey cache (epoch)?
        alt vetKey miss — once per epoch per canister lifetime
            Can->>Mgmt: raw_rand() then vetkd_derive_key
            Note over Can,Mgmt: 10B cycles at the 13-node reference, scaled by<br/>replication factor — 1 SDR cent, a few US cents.<br/>One identity serves ALL secrets.
            Mgmt-->>Can: EncryptedVetKey
            Can->>Can: decrypt_and_verify → vk
        end
        Can->>Can: ct.decrypt(vk) → plaintext
    end
    Can-->>User: a derived result — never the key
```

**Cost.** `VETKD_FEE` is 10B cycles at the 13-node reference subnet, scaled by
replication factor (`ic/rs/config/src/subnet_config.rs:130`), and the comment there puts
10B cycles at **1 SDR cent** — a few US cents on a 34-node subnet. It is paid once per
canister lifetime plus once after each upgrade, *not* per secret, because one identity
serves them all. That is why cost is no reason to deviate from IBE.

### Three decisions worth understanding

**The client computes the public key; it does not trust the one it is told.** If a
client asked the canister and believed the answer, anyone able to tamper with that
response could substitute a key they control and harvest the secret — and unlike the
canister's inter-canister calls, this response really does cross boundary nodes. So the
client derives the key from a master-key constant it ships with, uses
`icp_sealed_secret_info` purely as a cross-check, and aborts on mismatch.

The canister takes its own key from `vetkd_public_key`, which is authoritative for the
subnet it is on. Verifying against that is circular, but cheaply so: a subnet that would
lie about its public key already holds the master key and could decrypt everything
anyway. The non-circular audit lives in `self_test`, on demand.

**`set` is async and trial-decrypts before storing.** A wrong context, epoch or key
name otherwise produces a perfectly-accepted ciphertext that nobody discovers is
unreadable until a production call months later. Paying one key derivation at seal
time turns that into an error in front of the operator.

**One identity serves every secret.** A single `vetkd_derive_key` unlocks all of them.
Per-secret identities would multiply the cost by N and buy nothing: there is no
privilege boundary inside a canister, since its code can derive the key for any
identity whenever it likes.

## Quick start

Requires Rust with the `wasm32-unknown-unknown` target, Node 22+,
[icp-cli](https://github.com/dfinity/icp-cli), and `candid-extractor`
(`cargo install candid-extractor`).

**In one command:** `./scripts/local-test.sh` — see [Testing locally](#testing-locally).

Step by step:

```bash
# 1. local network (this project uses port 8010 to avoid clashing with others)
icp network start local --background
icp deploy -e local

# 2. an identity the canister will accept as a controller
icp identity export "$(icp identity default)" > /tmp/seed-id.pem
export SEAL_IDENTITY_PEM=/tmp/seed-id.pem

# 3. seal a secret — read from the environment, never from argv
cd seed && npm install
export OPENAI_API_KEY='sk-example-not-a-real-key'

CID=$(icp canister status sealed-secrets -e local --json | python3 -c 'import sys,json;print(json.load(sys.stdin)["id"])')

npm run seal -- \
  --canister "$CID" \
  --name OPENAI_API_KEY \
  --host http://127.0.0.1:8010 \
  --source pocketic \
  --local          # see "Local vs mainnet" below for what this waives
```

```
preflight
  subnet:   w5bul-v73ez-…-7ae
  sev-snp:  UNVERIFIED — the registry did not report the feature flag
  vetkd:    "key_1" NOT present — subnet holds no vetKD keys at all

key derivation
  source    pocketic:key_1
  context   01156963702d7365616c65642d736563726574732d763100
  identity  01156963702d7365616c65642d736563726574732d763100000000  (epoch 0)
  derived   a0d33e4e648337dafede99ae71fdc17a…
  verified  canister agrees with our offline derivation

sealing "OPENAI_API_KEY" (34 bytes → 170 bytes)
✓ sealed "OPENAI_API_KEY" at revision 0
  the canister trial-decrypted it before storing, so it is readable
```

Then confirm the canister really recovered the plaintext, and that the whole
derivation path is healthy:

```bash
icp canister call sealed-secrets secret_sha256 '("OPENAI_API_KEY")' -e local
icp canister call sealed-secrets icp_sealed_secret_self_test '(opt variant { PocketIc })' -e local
```

`self_test` takes the network you *believe* you are on and reports
`public_key_matches_master = opt true` when the subnet's own `vetkd_public_key` agrees
with the master key compiled into the Wasm. That is the one check in the design that is
not the subnet vouching for itself — pass `variant { Mainnet }` there and it correctly
returns `opt false`. Pass `null` to skip the audit.

### On mainnet

Drop `--local` and switch the master-key table:

```bash
npm run seal -- --canister <id> --name OPENAI_API_KEY \
  --host https://icp-api.io --source mainnet
```

The preflight then hard-fails unless the subnet reports `sev_enabled` **and** holds
the vetKD key. Both are real checks on mainnet; neither can be rehearsed locally.

> `--source` is not inferable from the key name. Mainnet and PocketIC each have a key
> called `key_1`, backed by **different** master public keys. Choosing wrong yields
> ciphertext nobody can ever decrypt — which is why the client verifies against the
> canister before encrypting, and why `crates/core/tests/golden.rs` asserts the two
> derivations differ. `ic-vetkeys`' own `management_canister::compute_vrf` has exactly
> this bug today.

## Testing locally

One command does the whole round trip:

```bash
./scripts/local-test.sh
```

It starts a local network, deploys, seals a secret, **reads it back in the clear**, and
checks it survives an upgrade — then runs the negative cases. It also asserts two things
that are easy to let rot: that a build *without* `--features test-hooks` exposes no
endpoint that can observe a secret, and that the generated TypeScript bindings still
match the canister's `.did`.

Individually:

```bash
cargo test          # golden vectors, name validation, key derivation
cd seed && npm test # the SAME golden vectors, in TypeScript

# against a running canister; needs a controller identity
icp identity export "$(icp identity default)" > /tmp/id.pem
cd seed && SEAL_IDENTITY_PEM=/tmp/id.pem npm run e2e -- \
  --canister <id> --host http://127.0.0.1:8010 --source pocketic
```

The Rust and TypeScript golden vectors are byte-for-byte identical on purpose: the two
implementations cannot drift without one suite failing. A future Motoko port should
assert the same values.

The e2e suite covers the cases that matter — ciphertext sealed to the wrong epoch,
malformed blobs, oversized input, invalid names, anonymous callers, that rejected writes
leave no trace, and that overwriting does not serve a stale cached plaintext.

### Seeing the decrypted secret

Verifying that decryption *worked* does not require handing out the plaintext:
`secret_sha256` returns a digest, and the e2e suite compares it against a locally
computed one. That is the check to rely on.

But if you want to see it with your own eyes, build with `--features test-hooks` (which
`icp.yaml` already does) and call `secret_reveal`. `local-test.sh` step 7 does exactly
this and prints both values.

### Can I just add a getter?

Not in production — but the reason is more interesting than "it would leak the key",
because **a controller can obtain the secret anyway**. Two routes, no endpoint required:

1. **Install code that decrypts.** vetKD binds the key to the **canister ID**, not to the
   module hash — `vetkd_public_key` takes `{ canister_id, context, key_id }` and nothing
   about the code. The ciphertext sits in stable memory and survives an upgrade, so any
   module a controller installs on that canister can derive the same key. There is no way
   to pin a sealed secret to a particular code version.
2. **Read the heap out of a snapshot.** `take_canister_snapshot`, then
   `read_canister_snapshot_data` with `kind = variant { wasm_memory : record { offset; size } }`.
   The decrypted plaintext cache is right there.

So what does a getter actually cost you?

- **It ships the plaintext to a boundary node.** Replies are not encrypted end-to-end; the
  boundary node terminates TLS and sits *outside* the subnet's SEV-SNP trust boundary. That
  undoes in the outbound direction exactly what sealing achieved on the way in. (Note a
  `query` is the *less* bad choice here — an `update` reply is written into replicated state
  on every node, whereas a query reply is ephemeral.)
- **It destroys the property that makes the code auditable.** "The published code never
  returns the plaintext" is something a reader can verify by reading it. Replace it with
  "…unless the caller is a controller" and the guarantee now rests on the controller set
  being, and remaining, exactly what you believe.
- **It leaves no trace.** Installing leaky code changes the module hash, which is visible
  in the state tree. A call to a getter leaves nothing behind.

The corollary is the one that matters for deployment: **since a controller can always get
the secret, the canister must be blackholed or SNS/NNS-governed for any of this to mean
anything.** On a blackholed canister a controller-gated getter is inert — nobody is a
controller — but by then you have no way to observe the secret anyway, which is the point.

## Client bindings

`seed/src/declarations/` is **generated** from `crates/canister/sealed_secrets_canister.did`
by [`@icp-sdk/bindgen`](https://www.npmjs.com/package/@icp-sdk/bindgen):

```bash
cd seed && npm run bindings
```

Regenerate whenever the canister interface changes; `local-test.sh` fails if you forget.

Only the NNS registry interface in `seed/src/idl.ts` is hand-written, because there is no
`.did` for it here and we need two of its ~20 methods. An earlier revision hand-wrote the
canister interface too, and it silently drifted twice. Generating it also turned two
latent bugs in the e2e suite into compile errors, because the generated result types are
proper discriminated unions rather than `any`.

## Wire format

```
context  := 0x01 || u8(len(SUITE)) || SUITE || u8(len(app_separator)) || app_separator
identity := 0x01 || u8(len(SUITE)) || SUITE || be_u32(epoch)
SUITE     = "icp-sealed-secrets-v1"
```

Both variable-length fields are length-prefixed so no two distinct inputs can encode
identically. The application domain separator is **always empty** in this PoC — it
exists so a canister that later needs vetKD for several purposes can adopt one without
a format break, and is not exposed as configuration. Golden values:

| Value | Bytes |
|---|---|
| `context("")` | `01156963702d7365616c65642d736563726574732d763100` |
| `context("demo")` | `01156963702d7365616c65642d736563726574732d76310464656d6f` |
| `identity(0)` | `01156963702d7365616c65642d736563726574732d763100000000` |

Secret names are `[A-Za-z0-9_.-]{1,64}` — matching environment-variable conventions,
and sidestepping the Unicode confusables an arbitrary Candid `text` would admit.

## Interface

```candid
icp_sealed_secret_info      : ()               -> (variant { Ok : SealedSecretInfo; Err : SealedSecretsError });
icp_sealed_secret_set       : (text, blob)     -> (variant { Ok : nat64; Err : SealedSecretsError });
icp_sealed_secret_unset     : (text)           -> (variant { Ok; Err : SealedSecretsError });
icp_sealed_secret_list      : ()               -> (variant { Ok : vec SealedSecretEntry; Err : … }) query;
icp_sealed_secret_self_test : (opt KeySource)  -> (variant { Ok : SelfTestReport; Err : … });
```

Install args are just `(record { key_name : text })`.

- **`info` is an update**, because `public_key` comes from `vetkd_public_key` —
  authoritative for whichever subnet the canister is actually on. It is cached, so only
  the first call pays. Earlier drafts derived it from a compiled-in master key so `info`
  could be a query, but that meant an install-time `key_source` argument that silently
  orphaned every ciphertext if set wrong. Asking the subnet means one build runs
  anywhere with nothing to configure, and it makes the client's comparison *stronger*:
  the canister now reports what the subnet says, and the client checks it against an
  independent constant, rather than the two agreeing because they share a constant.
- **Errors are a typed variant**, so tooling can branch on `VetKdUnavailable` versus
  `InvalidCiphertext` rather than parsing prose.
- **`list` is controller-gated.** It looks harmless but is not: IBE overhead is a fixed
  136 bytes, so `ciphertext_len` reveals the exact plaintext length, and names alone
  are useful reconnaissance.
- **Nothing derived from a plaintext is ever exposed.** A digest of the plaintext would
  be an offline guessing oracle for low-entropy secrets; `ciphertext_sha256` is a
  digest of a *randomised* ciphertext, so it reveals nothing while still letting a
  client confirm its upload landed.
- **There is no `get` in a default build.** No endpoint returns a plaintext. The
  `test-hooks` feature adds `secret_reveal`, which does — see
  [Seeing the decrypted secret](#seeing-the-decrypted-secret) and
  [Can I just add a getter?](#can-i-just-add-a-getter).
- **`secret_len`** is the demo of *using* a secret internally: it reads the plaintext and
  returns only a derived value. The length is not a new disclosure, since `list` already
  implies it.

## Security model

**What sealing gives you.** The secret is encrypted to a key derivable only by this
canister on this subnet. It never appears in an ingress message, a Candid argument, a
shell history, a CI log, or the canister's interface. The ciphertext is bound to the
canister id, so replaying it elsewhere is useless.

**What it does not.** Once decrypted, the plaintext is in the Wasm heap — which is
replicated state, checkpointed to disk on every node, and shipped in state sync.
Keeping it out of `StableBTreeMap` does **not** keep it off disk. On a non-TEE subnet
a node operator reads it out of a checkpoint.

**What SEV-SNP adds — load-bearing, not a bonus.** Guest memory encrypted under a key
the hypervisor cannot access, plus a LUKS data partition keyed to the SEV launch
measurement. This is the *only* thing that moves "node operators can read the
plaintext" to "cannot". **Without a SEV-SNP subnet this scheme protects the secret in
transit and at rest in the ingress history, and nothing more.**

### What is still exposed

- **Controllers.** A controller can `install_code` with code that returns the
  plaintext, *or* take a snapshot and `read_canister_snapshot_data` the Wasm memory
  directly — no upgrade required. **Public source is necessary and nowhere near
  sufficient.** The canister must be blackholed or SNS/NNS-governed, with a
  reproducible build, a verified module hash, and a verified controller set.
- **The canister's own code.** vetKD hands it the key on demand. The guarantee is
  exactly "the published, verified code does not expose the plaintext".
- **Any non-SEV node in the subnet.** Replicated state is on all of them, so the
  protection is only as strong as the weakest node.
- **Attestation.** Nothing here proves the subnet is SEV-SNP. Verify out of band.

### HTTPS outcalls

Using a secret in an outcall header does **not** widen the trust boundary beyond what
decryption already crossed, but it is worth knowing exactly where the bytes go:

| Where the plaintext is | Protected on a SEV subnet? |
|---|---|
| `CanisterHttpRequestContext { url, headers, body }` in replicated state, on every node, checkpointed | ✅ memory encryption + measurement-keyed LUKS |
| The request built by `ic-https-outcalls-adapter` | ✅ it is a GuestOS service, inside the SEV guest |
| On the wire to the endpoint | ✅ TLS, terminated by the adapter |
| Through a SOCKS proxy on another node | ✅ the proxy sees ciphertext only — TLS wraps the tunnel |

**A trap:** `flexible_http_request` lets a canister set `replication.total_requests`
as low as 1. That reduces how many nodes open a connection, but **not** how many hold
the header bytes — the request context enters replicated state before any node
executes it. It is an egress knob, not a confidentiality control.

Still leaked even on SEV, because it is outside the encrypted payload: the destination
host (TLS SNI, DNS), timing, and request/response sizes. The key itself is not.

## Prerequisites for a real deployment

Two **independent** subnet properties — neither implies the other:

1. **The subnet holds the vetKD key** (an NI-DKG transcript for `bls12_381_g2:key_1`
   reshared to it). A SEV-SNP subnet is not automatically a vetKD subnet, and without
   the key every `vetkd_derive_key` is rejected.
2. **The subnet's nodes are SEV-SNP.**

The seeding script checks both from a single registry `get_subnet` query and refuses to
seal unless both hold, with a separate override per check because they fail for very
different reasons — see below.

### Local vs mainnet — what a local run does and does not prove

`icp network start` always creates NNS, **fiduciary**, **TestThresholdKeys** and
application subnets. PocketIC attaches vetKD keys only to the **II and fiduciary**
subnets (`pocket_ic.rs`: `if subnet_kind == II || Fiduciary` → `key_1`, `test_key_1`,
`dfx_test_key`), which is where local `key_1` comes from.

| | Local / PocketIC | Mainnet |
|---|---|---|
| **Registry reports the subnet's vetKD keys** | ✅ **accurate** — fiduciary shows `key_1`, application shows none | ✅ accurate |
| **Placement enforced when deriving** | ❌ **not enforced** — a canister on a keyless subnet derives happily | ✅ rejected: `Subnet {id} does not hold NiDkgTranscript for key {key_id}` |
| **`features.sev_enabled`** | ❌ always `null` — SEV cannot be simulated | ✅ reported |

Two consequences, and they point in opposite directions.

**The vetKD check works locally, and you should not skip it.** The registry tells the
truth: deploy this PoC and it lands on the *application* subnet, and the preflight
correctly reports `"key_1" NOT on this subnet`. It is right — and mainnet would reject
every derive. But PocketIC does not enforce placement (verified: our canister id
`7fffffffffa00002…` falls in the application range, and derivation succeeded anyway),
so **the local runtime hides the very mistake the preflight caught**. That is why
`--allow-missing-vetkd-key` is a sharper knife than it looks, and why it is a separate
flag rather than folded into one blanket override.

PocketIC does check that the key exists *somewhere* in the instance — install with a
key name no subnet has and `self_test` reports `vetkd_public_key_ok = false` — but that
is a weaker check than mainnet's.

**SEV cannot be exercised locally at all.** `sev_enabled` is `null` for every local
subnet, so `--allow-unverified-sev` is unavoidable locally and says nothing about your
deployment. On mainnet it is the check that carries the entire security argument: without
a SEV-SNP subnet, node operators can read the plaintext out of a checkpoint the moment
the canister decrypts it, and this scheme protects the secret only in transit and in the
ingress history.

**So the mainnet checklist is not optional and cannot be rehearsed locally:**

1. Place the canister on a subnet that actually holds `key_1` — on mainnet, a fiduciary
   subnet. Confirm from the registry *before* deploying.
2. Confirm that subnet reports `sev_enabled = true`.
3. Run `icp_sealed_secret_self_test(opt variant { Mainnet })` immediately after install
   and check `public_key_matches_master = opt true`.

## Layout

```
crates/core/           wire format + offline key derivation. No canister APIs; host-testable.
crates/core/tests/     golden vectors — the contract other implementations must meet.
crates/canister/       the canister: endpoints, stable store, key derivation and caches.
seed/src/              the host-side seeding script and the e2e suite.
seed/src/declarations/ GENERATED from the .did — do not edit; `npm run bindings`.
scripts/local-test.sh  the whole round trip, one command.
icp.yaml               local (port 8010) and ic environments.
```

The core/canister split is deliberate. It keeps the format layer free of `ic-cdk` and
`ic-stable-structures`, which is the shape a library version would need — see
[FOLLOW-UPS.md](./FOLLOW-UPS.md).

## Deliberately out of scope

Rotation, `icp_sealed_secret_matches` for idempotent re-seeding, the macros that would
make this three lines in someone else's canister, splitting `ic-vetkeys` itself along a
Cargo feature, and any icp-cli integration. All of it is discussed in
**[FOLLOW-UPS.md](./FOLLOW-UPS.md)**; none of it belongs in something whose job is to
start a design conversation.

## Licence

Apache-2.0.
