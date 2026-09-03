# BLS12-381 for Motoko — experimental

> # ⚠️ EXPERIMENTAL AND UNAUDITED
>
> This is a proof-of-concept port. It has **not** been reviewed by a cryptographer,
> it has **not** been audited, and it makes **no** attempt at constant-time
> execution. **Do not use it in production.**
>
> It exists for one reason: so the [sealed-secrets PoC](../README.md) can
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

Even pessimistically — double the operation count, add the `G2` scalar
multiplications the decrypt path needs — the full path lands in the low single
digit billions. **It fits, with headroom.**

Two caveats worth stating plainly. The 30,000 figure is an estimate from the
structure of the algorithm, not a measurement; only a finished Miller loop settles
it. And **queries get 5 billion instructions, not 40** — so decryption must happen
in an update call, which is what the Rust PoC already does.

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
cargo run -p vectorgen > motoko/test/vectors.json
```

This matters. The reference's own `fp` unit tests are written against its internal
Montgomery limbs (`Fp([0xdc90_6d9b_e3f9_5dc8, ...])`), so porting them literally
would assert nothing about agreement between the two implementations. What matters
is that they agree on *values*, so the vectors are real curve points serialized
through the same encoding the protocol uses, and the strongest check asserts that
every one of them satisfies `y² = x³ + 4` — exercising the modulus, `add`, `mul`
and `square` together against data this code had no hand in producing.

## The finish line

`test/vectors.json` carries a complete IBE triple — a derived public key, an
identity, a vetKey, a ciphertext and the plaintext it must yield. The generator
**decrypts it in Rust before emitting it**, so it cannot send the port chasing a
phantom.

When this Motoko code turns `vetkey` + `ciphertext` back into `plaintext`, the
port works. Nothing short of that proves it, and every layer below is scaffolding
toward it.

## Status

| Layer | State |
|---|---|
| `Fp` — base field | ✅ 11 tests against reference vectors |
| `Fp2` — quadratic extension | ✅ 11 tests, anchored on the G2 curve equation |
| `Fp6` — sextic extension | ✅ 9 tests, incl. Frobenius re-derived and checked as `x^p` |
| `Fp12` — dodecic extension, the pairing target | ✅ 9 tests, incl. conjugation-is-inversion in the cyclotomic subgroup |
| `G1`, `G2` — curve groups, compression | ⬜ not started |
| Pairing — Miller loop, final exponentiation | ⬜ not started |
| `hash_to_curve` | ⬜ not started — needed only if the canister verifies the vetKey |
| IBE decryption | ⬜ not started |

The reference is ~12,500 lines of implementation. The decrypt path needs most of
it: everything except `map_g2` and `map_scalar`, so roughly 11,500 lines. Skipping
`decrypt_and_verify` in favour of the unencrypted-transport-key shortcut would drop
`hash_to_curve` (~3,200 lines) at the cost of the integrity check — a trade the
Rust PoC deliberately declines, and one that would make the two implementations
differ in a security property, which defeats the point of a side-by-side demo.
