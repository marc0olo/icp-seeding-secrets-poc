# BLS12-381 for Motoko — experimental

> # ⚠️ EXPERIMENTAL AND UNAUDITED
>
> This is a proof-of-concept port. It has **not** been reviewed by a cryptographer,
> it has **not** been audited, and it makes **no** attempt at constant-time
> execution. **Do not use it in production.**
>
> It exists for one reason: so the [sealed-secrets PoC](../../README.md) can
> demonstrate the same seeding and HTTPS-outcall flow from a **Motoko** canister
> as well as a Rust one. That is a demonstration, not a recommendation.

## Why this has to exist at all

Canister-side vetKD decryption needs BLS12-381 pairings. The Motoko ecosystem has
no pairing implementation and no building block close to one:

| On mops | Not on mops |
|---|---|
| `sha2`, `hmac`, `blake2b`, `ripemd160` | **BLS12-381 — nothing** |
| `ecdsa`, `libsecp256k1` (secp256k1) | **any pairing** |
| `tweetnacl` (ed25519 / curve25519) | **any bignum or field-arithmetic library** |
| `ic-vetkeys` 0.6 — management API, KeyManager, EncryptedMaps | IBE, transport keys, vetKey decryption |

The vetKeys skill states it directly: *"Motoko has no low-level crypto. No IBE,
transport keys, `MasterPublicKey`/`DerivedPublicKey`, or vetKey decryption."*
The curves that *are* available are the wrong family — nothing in a secp256k1 or
curve25519 implementation is reusable for a 381-bit pairing-friendly curve. This
starts from integers.

## Is it fast enough? Measured, not guessed

The question that decides the whole approach. `mops bench`, marginal cost per
operation:

| Operation | Instructions |
|---|---:|
| `add` | ~4,000 |
| `mul` | **~53,500** |
| `square` | ~51,400 |
| `inverse`, `sqrt` | ~43,000,000 |

A pairing is on the order of **30,000 field multiplications** — roughly 64
Miller-loop iterations over `Fp12`, where one `Fp12` multiplication is itself tens
of `Fp` multiplications, plus a final exponentiation of similar magnitude. So:

> **~30,000 × 53,500 ≈ 1.6 billion instructions ≈ 4% of the 40 billion available
> to an update call.**

**Now measured, and better than the estimate:**

| | Instructions | Share of an update call |
|---|---:|---:|
| Miller loop | 487,669,141 | 1.2% |
| Final exponentiation | 590,961,027 | 1.5% |
| **Full pairing** | **1,078,628,674** | **2.7%** |
| `hashToCurve` (RFC 9380) | 190,523,836 | 0.5% |
| **Full IBE decryption** | **1,792,820,565** | **4.5%** |
| **`decryptAndVerify`** | **3,573,000,849** | **8.9%** |
| **Both — the cold path** | **≈ 5,365,821,414** | **≈ 13.4%** |

The number that matters is the last one. A canister cannot just decrypt: it must
first unwrap the reply from `vetkd_derive_key` and check that what came back is
genuinely its own vetKey, which is `decryptAndVerify` — two multipairings and a
hash-to-curve, and the more expensive half by a factor of two. Quoting the IBE
decryption alone would understate the real cost by a third.

Together they are about **13% of what a single update call is allowed**, and they
are paid once: the Rust PoC caches both the vetKey and the decrypted value, and a
Motoko port would do the same.

### Against the Rust implementation

Measured the only way that is meaningful — the same operation, on the same
vector, counted as **canister instructions** inside a deployed canister. Native
benchmarks would not compare, because what the replica charges is wasm-specific.
The Rust side is `bench_ibe_decrypt` in `rust/canister`, behind `test-hooks`.

| | Instructions | |
|---|---:|---|
| Rust, first call | 535,470,526 | includes one-time setup |
| **Rust, steady state** | **165,592,933** | |
| **Motoko** | **1,792,820,565** | **≈ 10.8× the Rust steady state** |

(Both sides measure IBE decryption alone, which is the like-for-like comparison;
the Motoko `decryptAndVerify` figure above has no Rust counterpart benchmarked.)

Two things to read from that.

**The first Rust call costs three times the rest**, because `ic-vetkeys` builds a
`lazy_static` precomputed multiplication table for the `G2` generator
(`utils/mod.rs:219`) on first use. Quoting that number as "the Rust cost" would
flatter this port considerably — it was the first figure measured here, and it is
the wrong one.

**Roughly 10× is far better than a `Nat`-based port has any right to expect**,
and the reason is that the comparison is wasm-to-wasm. Rust's `[u64; 6]`
Montgomery arithmetic needs 64×64→128 multiplication, which wasm does not have
natively either, so much of its advantage over arbitrary-precision `Nat`
evaporates before it reaches the replica.

### Where the performance gap actually is

Measured, not guessed. Splitting a field multiplication into its two halves, per
operation:

| | Instructions | Share |
|---|---:|---:|
| `(a * b) % P` — the whole thing | 53,789 | 100% |
| the multiplication alone | 8,868 | 16% |
| **the reduction (`%`) alone** | **46,010** | **85%** |

**The modulus is the cost, not the arithmetic.** Multiplying two 381-bit numbers
is cheap; dividing the 762-bit product by a 381-bit prime is not, and that
division happens tens of thousands of times per pairing.

Which is precisely what Montgomery form exists to avoid. The reference never
divides: it keeps elements in a transformed representation where reduction is a
multiply-and-shift, costing about what the multiplication costs rather than five
times more. That one difference accounts for most of the 10×.

So the optimisation path is clear, and it is not "rewrite in limbs":

1. **Montgomery reduction** on the existing `Nat` representation would remove
   that 85%, and could plausibly bring this within 2–3× of Rust.
2. **A precomputed `G2` table**, which the reference has and this does not — the
   plain double-and-add in `decrypt` looks to be around 700 million of the 1.79
   billion, going by the pairing figures.

Neither is worth doing yet. At about 13% of an update call for the full cold
path — verify plus decrypt, paid once — there is nothing to buy with the savings,
and both add code that would need reviewing.

And there is a third option that is not ours to take: **[PROPOSAL.md](./PROPOSAL.md)
sets out what the Motoko runtime would need to close most of this gap.** The short
version is that libtommath — which already backs Motoko's `Nat` — implements
Barrett and Montgomery reduction, modular exponentiation and modular inversion,
and the runtime simply does not compile them in. A userland fix is blocked because
`Nat` has no shift operator, and writing one as `x / (2 ** k)` costs nearly as much
as the division it would replace.

One caveat stands: **queries get 5 billion instructions, not 40**, so decryption
must happen in an update call — which is what the Rust PoC already does.

## Why it does not mirror the Rust representation

`ic_bls12_381` stores a field element as `[u64; 6]` in Montgomery form, with
hand-written carry propagation over 64×64→128 multiplication. Motoko has no
`Nat128`, so each of those would become four 32-bit multiplies and a carry chain,
across ~1,000 lines whose correctness lives entirely in carries nobody can see.

This port keeps the **semantics** and drops the **representation**: an element is
a `Nat` in `[0, p)` and the operations are ordinary modular arithmetic. It is a
fraction of the code, it can be reviewed by reading it, and the benchmark says the
speed is affordable. The cost is roughly a thousandfold over native — which the
instruction budget absorbs.

If that ever stops being true, the limb representation is the fallback, and the
test vectors here are what would make that port safe to attempt.

## Testing

```bash
mops test    # unit tests
mops bench   # instruction counts
```

Pinned to the newest `moc` (1.15.1) rather than the 1.13.0 minimum the vetKeys
skill names — same numbers on both, but there is no reason to sit on an old
compiler.

Test vectors are **generated from the Rust reference**, not hand-written:

```bash
cargo run -p vectorgen > motoko/vetkeys/test/vectors.json
```

This matters. The reference's own `fp` unit tests are written against its internal
Montgomery limbs (`Fp([0xdc90_6d9b_e3f9_5dc8, ...])`), so porting them literally
would assert nothing about agreement between the two implementations. What matters
is that they agree on *values*, so the vectors are real curve points serialized
through the same encoding the protocol uses, and the strongest check asserts that
every one of them satisfies `y² = x³ + 4` — exercising the modulus, `add`, `mul`
and `square` together against data this code had no hand in producing.

## The two vectors that decide it

Most of the suite checks one layer at a time. Two vectors check the whole thing,
and they are the ones to look at first.

### Decrypting a reference ciphertext

`test/vectors.json` carries a complete IBE triple — a derived public key, an
identity, a vetKey, a ciphertext and the plaintext it must yield. The generator
**decrypts it in Rust before emitting it**, so it cannot send the port chasing a
phantom.

`test/Ibe.test.mo` decrypts that ciphertext and recovers the exact plaintext.
Every layer has to be simultaneously correct for the authenticated check at the
end of `decrypt` to pass — the field tower, both group laws, the Miller loop, the
final exponentiation, HKDF, SHAKE256, `expand_message_xmd`, and every
serialization format.

The suite also checks the failure directions, which matter as much: a tampered
ciphertext and a wrong vetKey are both **rejected**, not mis-decrypted into
plausible garbage.

### Verifying a real subnet reply

Decryption alone proves the port computes what the reference computes. It does
not prove the port can be *trusted with* a subnet's reply, because a canister
never receives a bare vetKey — it receives an `EncryptedVetKey` and has to unwrap
and verify one.

So `test/vectors.json` also carries an `encrypted_vetkey` block: a transport
secret key, a derived public key, a real 192-byte reply, and the vetKey that must
fall out of them. Unlike everything else in the file, these values are **not
generated by this repository**. They are lifted from `ic-vetkeys`'
`transport_key_works_with_bls_and_ibe` (`tests/utils.rs:245`), where they are
annotated "generated by internal library" — the threshold implementation running
in the replica. `test/VetKey.test.mo` recovers exactly that vetKey from them.

Five negative cases sit alongside it — wrong transport key, wrong identity,
substituted derived public key, tampered `c1`, tampered `c3` — because the
positive case alone cannot distinguish a correct implementation from one that
skips verification and returns whatever it unwrapped.

## Status

| Layer | State |
|---|---|
| `Fp` — base field | ✅ 11 tests against reference vectors |
| `Fp2` — quadratic extension | ✅ 11 tests, anchored on the G2 curve equation |
| `Fp6` — sextic extension | ✅ 9 tests, incl. Frobenius re-derived and checked as `x^p` |
| `Fp12` — dodecic extension, the pairing target | ✅ 9 tests, incl. conjugation-is-inversion in the cyclotomic subgroup |
| `G1` — curve group over `Fp` | ✅ 9 tests, incl. scalar mult reproducing reference multiples |
| `G2` — curve group over `Fp2` | ✅ 8 tests, same |
| Pairing — Miller loop, final exponentiation | ✅ 8 tests, bilinear and non-degenerate |
| `Scalar`, `Hash` — group order, HKDF, SHAKE256, `expand_message_xmd` | ✅ 10 tests against Python and reference vectors |
| **IBE decryption** | ✅ **6 tests — decrypts the reference ciphertext** |
| `hash_to_curve` — RFC 9380, simplified SWU + 11-isogeny | ✅ 4 tests against reference vectors |
| **`decryptAndVerify`** | ✅ **10 tests against a real `vetkd_derive_key` reply** |
| `derive_canister_key` / `derive_sub_key` | ⬜ not implemented — see [Coverage](#coverage) |

### Coverage

This is a library, not a canister. It covers what happens to a `vetkd_derive_key`
reply once a canister has it: unwrap it, **verify** it, decrypt the sealed
secret. Fetching the reply is an ordinary management-canister call that Motoko
can already make via `mo:ic-vetkeys`' `ManagementCanister.mo`.

**One piece of the Rust PoC has no counterpart here:** offline derived-public-key
computation — `MasterPublicKey::for_mainnet_key(…).derive_canister_key(…)
.derive_sub_key(…)`. The Rust canister uses it to check the subnet's reply against
a master key compiled into its own Wasm, which is the one step in the design that
is not the subnet vouching for itself. A Motoko canister today would have to take
the derived public key from `vetkd_public_key` instead, which is weaker.

Closing it is small — roughly 30 lines over the existing `G2.mul`, `G2.add` and
`Scalar.hashToScalar`, plus the four hardcoded master-key constants — but it is
not written yet, and until it is, `verifyBlsSignature` can only be as trustworthy
as the key handed to it.

The largest single piece already here is `hash_to_curve` — 3,314 lines of the reference,
across `map_g1.rs`, `expand_msg.rs`, `chain.rs` and `mod.rs`. It is easy to
mistake for optional, because `IbeCiphertext::decrypt` never calls it: decryption
needs only a pairing and a `G2` scalar multiplication. Verification is what needs
it, and the difference between the two is a security property — a canister that
cannot verify takes the subnet's word for the key it was handed. See
[Verifying a real subnet reply](#verifying-a-real-subnet-reply).

### Two coordinate conventions coexist here

`G1.Point` is **Jacobian**: `(X : Y : Z)` denotes `(X/Z², Y/Z³)`. The simplified
SWU map and the 11-isogeny inside `HashToCurve` are **homogeneous**: `(X/Z,
Y/Z)`. Both use the same record type, and each is internally consistent, so
nothing in the `G1` test suite can detect a value crossing from one to the other
— it simply yields points that are not on the curve.

`HashToCurve.toJacobian` is the conversion, `(X·Z : Y·Z² : Z)`, three
multiplications and no inversion. Anything leaving `isoMap` must go through it
before it touches `G1.add`, `G1.mul` or `G1.toAffine`.
