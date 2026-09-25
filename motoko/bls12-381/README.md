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

Canister-side vetKD decryption needs BLS12-381 pairings, and `mo:ic-vetkeys` 0.6
has none — the vetKeys skill states it directly: *"Motoko has no low-level
crypto. No IBE, transport keys, `MasterPublicKey`/`DerivedPublicKey`, or vetKey
decryption."* The curves that are on mops for signatures (`ecdsa`,
`libsecp256k1`, `tweetnacl`) are the wrong family; nothing in them is reusable
for a 381-bit pairing-friendly curve.

Since this port was written, ICDevs has published
[`bls12-381`](https://github.com/icdevsorg/bls12-381.mo) on mops, aimed at
Ethereum's EIP-2537 precompiles. It is a separate implementation of the same
curve; this one stays because its vectors are generated from `ic_bls12_381`,
the implementation `ic-vetkeys` uses, and the vetKD layer in
[`../vetkeys`](../vetkeys) is built and tested against it.

## Cost

`mops bench` on moc 1.15.1, against the 40 billion instructions an update call
gets:

| Operation | Instructions | Share of an update call |
|---|---:|---:|
| `Fp.add` | 4,948 | |
| `Fp.mul` | 32,085 | |
| `Fp.inverse` | 3,990,567 | |
| `Fp.sqrt` | 19,380,448 | |
| Miller loop | 324,687,996 | 0.8% |
| Final exponentiation | 384,145,317 | 1.0% |
| **Full pairing** | **708,832,301** | **1.8%** |
| `hashToCurve` (RFC 9380, via `vetkeys`' bench) | 79,417,048 | 0.2% |

Those are the primitives. What a canister actually pays is the vetKD layer built
on them — decrypting a sealed secret, and first verifying the vetKey it decrypts
with — which comes to about **7.8% of a single update call**, paid once.
[`../vetkeys/README.md`](../vetkeys/README.md#cost) has that table, next to the
code it measures.

`Nat` arithmetic costs depend on the values, so these are not constant-time,
and a benchmark on degenerate inputs (a Miller-loop product that collapses to
one, say) will look far cheaper than real use.

### Against the Rust implementation

Measured as canister instructions, on the same vector, for IBE decryption alone.
Native benchmarks would not compare, because what the replica charges is
wasm-specific. The Rust side is `bench_ibe_decrypt` in `rust/canister`, behind
`test-hooks`.

| | Instructions | |
|---|---:|---|
| Rust, first call | 535,470,526 | includes one-time setup |
| **Rust, steady state** | **165,592,933** | |
| **Motoko** | **1,094,607,711** | **≈ 6.6× the Rust steady state** |

**The first Rust call costs three times the rest**, because `ic-vetkeys` builds a
`lazy_static` precomputed multiplication table for the `G2` generator
(`utils/mod.rs:219`) on first use. Quoting that number as "the Rust cost" would
flatter this port considerably.

### Where the cost is

A base-field multiplication, split (`bench/Why.bench.mo`, `bench/Shift.bench.mo`,
per operation):

| | Instructions |
|---|---:|
| `(a * b) % P` | 53,789 |
| **`Fp.mul`** — product plus Barrett reduction | **31,717** |
| the product alone | 9,182 |
| `big % P` | 45,440 |
| `big / (2 ** 381)` | 39,532 |
| `Nat.bitshiftRight(big, 381)` | 3,070 |

Dividing by `P` is what a naive port pays for, and dividing by a power of two
is no cheaper — `Nat` division does not special-case it. A shift is, which is
what lets `Fp.mul` replace the division with Barrett reduction: two further
multiplications and two shifts. The same applies to walking an exponent's bits:
`n % 2` and `n / 2` cost about 29,000 instructions each on a 381-bit value, so
`Bits` reads them through shifts instead.

The reduction is still about 70% of a multiplication. What would remove more:

1. **A precomputed `G2` table**, which the reference has and this does not.
   The generator multiplication in `Ibe.decrypt` is about 380 million of its
   1.09 billion instructions.
2. **Runtime support.** [PROPOSAL.md](./PROPOSAL.md) sets out what `Nat` would
   need — libtommath, which already backs it, implements Montgomery reduction,
   modular exponentiation and modular inversion, and the runtime does not
   compile them in.

One caveat stands: **queries get 5 billion instructions, not 40**, so decryption
belongs in an update call — which is what the Rust PoC already does.

## Why it does not mirror the Rust representation

`ic_bls12_381` stores a field element as `[u64; 6]` in Montgomery form, with
hand-written carry propagation over 64×64→128 multiplication. Motoko has no
widening 64-bit multiply, so each partial product would have to go through
`Nat` anyway, across ~1,000 lines whose correctness lives entirely in carries
nobody can see.

This port keeps the **semantics** and drops the **representation**: an element is
a `Nat` in `[0, p)` and the operations are ordinary modular arithmetic. It is a
fraction of the code, it can be reviewed by reading it, and the benchmark says the
speed is affordable.

## Testing

```bash
mops test    # unit tests
mops bench   # instruction counts
```

Test vectors are **generated from the Rust reference**, not hand-written — see
[`../vectors.json`](../vectors.json), and [`../README.md`](../README.md) for
where the generator lives.

This matters. The reference's own `fp` unit tests are written against its internal
Montgomery limbs (`Fp([0xdc90_6d9b_e3f9_5dc8, ...])`), so porting them literally
would assert nothing about agreement between the two implementations. What matters
is that they agree on *values*, so the vectors are real curve points serialized
through the same encoding the protocol uses, and the strongest check asserts that
every one of them satisfies `y² = x³ + 4` — exercising the modulus, `add`, `mul`
and `square` together against data this code had no hand in producing.

## What proves it works

Each layer has vectors of its own (see [Status](#status)), but a field
implementation can pass every unit test and still be subtly wrong in a way only
a full protocol run exposes. The two end-to-end vectors that do that live with
the layer that uses them: [`../vetkeys`](../vetkeys) decrypts a ciphertext
produced by the Rust reference and verifies a real `vetkd_derive_key` reply.
Neither passes unless everything here is simultaneously correct.

## Status

| Layer | State |
|---|---|
| `Fp` — base field | ✅ 14 tests against reference vectors, incl. Barrett and Euclid against division and Fermat |
| `Bits` — shift-based bit access | ✅ 2 tests against the division-based definitions |
| `Fp2` — quadratic extension | ✅ 11 tests, anchored on the G2 curve equation |
| `Fp6` — sextic extension | ✅ 9 tests, incl. Frobenius re-derived and checked as `x^p` |
| `Fp12` — dodecic extension, the pairing target | ✅ 9 tests, incl. conjugation-is-inversion in the cyclotomic subgroup |
| `G1` — curve group over `Fp` | ✅ 9 tests, incl. scalar mult reproducing reference multiples |
| `G2` — curve group over `Fp2` | ✅ 8 tests, same |
| Pairing — Miller loop, final exponentiation | ✅ 9 tests, bilinear and non-degenerate; the shared multi-pair loop equals the product of single loops |
| `Scalar`, `Hash` — group order, HKDF, SHAKE256, `expand_message_xmd` | ✅ 10 tests against Python and reference vectors |
| `hash_to_curve` — RFC 9380, simplified SWU + 11-isogeny | ✅ 4 tests against reference vectors |

### Scope

This package is the curve only — the `ic_bls12_381` equivalent. The vetKD layer
built on it (`Ibe`, `VetKey`, `PublicKey`) is a separate package,
[`../vetkeys`](../vetkeys), because that is exactly what `mo:ic-vetkeys` is
missing, and keeping the boundary as a directory says so more durably than prose
does.

It is a library, not a canister, and nothing in it is IC-specific: the curve is
the curve. Anything needing BLS12-381 pairings could use it, once it has been
audited — and once decompression checks subgroup membership, which
`ic_bls12_381` does and this port does not yet.

The largest single piece is `hash_to_curve` — 3,314 lines of the reference,
across `map_g1.rs`, `expand_msg.rs`, `chain.rs` and `mod.rs`. It is easy to
mistake for optional, because `IbeCiphertext::decrypt` never calls it: decryption
needs only a pairing and a `G2` scalar multiplication. Verification is what needs
it, and the difference between the two is a security property — a canister that
cannot verify takes the subnet's word for the key it was handed.

### Two coordinate conventions coexist here

`G1.Point` is **Jacobian**: `(X : Y : Z)` denotes `(X/Z², Y/Z³)`. The simplified
SWU map and the 11-isogeny inside `HashToCurve` are **homogeneous**: `(X/Z,
Y/Z)`. Both use the same record type, and each is internally consistent, so
nothing in the `G1` test suite can detect a value crossing from one to the other
— it simply yields points that are not on the curve.

`HashToCurve.toJacobian` is the conversion, `(X·Z : Y·Z² : Z)`, three
multiplications and no inversion. Anything leaving `isoMap` must go through it
before it touches `G1.add`, `G1.mul` or `G1.toAffine`.
