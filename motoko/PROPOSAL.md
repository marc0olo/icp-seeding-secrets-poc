# What would make BLS12-381 fast in Motoko

A note for the Motoko team, from porting `ic_bls12_381` to Motoko so that a
Motoko canister can decrypt a vetKD-sealed secret. The port works — it verifies a
real `vetkd_derive_key` reply and decrypts a ciphertext produced by the Rust
reference — at about **10.8× the instruction cost of the same operation in
Rust**, measured inside a canister on the same vector.

That ratio is better than we expected. But almost all of it comes from **one
missing capability**, and the fix appears to be cheap.

Everything below is measured on `moc` 1.15.1. Reproduce with `mops bench` in this
directory.

---

## The finding

A base-field multiplication is `(a * b) % P` where `P` is the 381-bit BLS12-381
prime. Split in two:

| | Instructions | Share |
|---|---:|---:|
| `(a * b) % P` | 53,789 | 100% |
| the multiplication | 8,868 | 16% |
| **the reduction (`%`)** | **46,010** | **85%** |

The arithmetic is not the problem. **The modular reduction is.** A pairing
performs tens of thousands of these, so 85% of a 1.79-billion-instruction
decryption is spent dividing.

This is exactly the cost that Montgomery and Barrett reduction exist to remove.
Neither is reachable from Motoko.

## Why it cannot be worked around in userland

Barrett reduction replaces the division with two multiplications and two shifts
by a power of two. Motoko `Nat` has no shift operator, so a shift must be written
as `x / (2 ** k)` — and that turns out to cost nearly as much as the division it
was meant to replace:

| | Instructions |
|---:|---:|
| `big % P` | 45,440 |
| `big / (2 ** 381)` | **39,532** |
| `x * y` | 8,849 |

So a userland Barrett would cost roughly `2 × 8,849 + 2 × 39,532 ≈ 97,000`
against the 45,440 it replaces — **more than twice as expensive as doing
nothing**. The workaround is closed off.

`Nat` division does not appear to special-case powers of two.

## Why this is cheap to fix

Motoko's `Nat` is [libtommath](https://github.com/libtom/libtommath) with 64-bit
digits (`rts/Makefile`, `-DMP_64BIT`), and `%` maps to `mp_div` with the quotient
discarded (`rts/motoko-rts/src/bigint.rs`, `bigint_rem`).

**libtommath already implements everything needed here.** The runtime simply does
not compile it in. `rts/Makefile` carries an explicit list:

```make
# We manually list all the .c files of libtommath that we care about.
TOMMATHFILES = \
   mp_init mp_zero mp_add mp_sub mp_mul mp_cmp \
   ...
   mp_div mp_init_copy mp_neg mp_abs mp_2expt mp_expt_u32 mp_set mp_sqr \
   ... mp_mul_2d mp_rshd mp_mul_d mp_div_2d mp_mod_2d \
   ...
```

Absent from that list, and all present upstream:

| libtommath | what it would give Motoko |
|---|---|
| `mp_reduce`, `mp_reduce_setup` | Barrett reduction |
| `mp_montgomery_reduce`, `mp_montgomery_setup` | Montgomery reduction |
| `mp_exptmod` | modular exponentiation, windowed |
| `mp_invmod` | modular inverse by extended Euclid |
| `mp_mod` | remainder without computing the quotient |
| `mp_sqrtmod_prime` | modular square root |

## What we would ask for, in order of value per unit of work

### 1. Expose shifts on `Nat` — cheapest, and unblocks userland work

`mp_mul_2d`, `mp_div_2d` and `mp_mod_2d` are **already compiled in**. They are
simply not reachable from Motoko. Surfacing them as `Nat.shiftLeft` /
`Nat.shiftRight` (or making `/` and `%` recognise powers of two) would:

- turn a 39,532-instruction "shift" into something proportional to a memory move;
- make a **userland** Barrett or Montgomery implementation viable, so libraries
  could solve this without waiting for anything else on this list.

This looks like the smallest change with the largest unblocking effect.

### 2. `Nat.mulMod(a, b, m)`

The operation this whole port is bottlenecked on. Backed by `mp_reduce` or
`mp_montgomery_reduce`, it should approach the cost of the multiplication alone —
plausibly a **4–5× reduction** in the dominant cost of every elliptic-curve and
pairing operation in Motoko.

If a modulus-specific setup cost is a concern, an opaque prepared-modulus value
(`Nat.prepareModulus(m)` returning a handle reused across calls) would match how
`mp_reduce_setup` and `mp_montgomery_setup` are meant to be used, and matters
here because the modulus is fixed for the lifetime of the program.

### 3. `Nat.powMod(base, exp, modulus)`

`mp_exptmod`. Our square-and-multiply costs **43 million instructions** for a
381-bit exponent; a windowed implementation over Montgomery arithmetic should be
several times cheaper. Modular exponentiation is ubiquitous well beyond this port
— RSA, Diffie–Hellman, and every "is this a quadratic residue" test.

### 4. `Nat.invMod(a, m)` and `Nat.sqrtMod(a, p)`

`mp_invmod` and `mp_sqrtmod_prime`. We currently compute an inverse as
`a^(P-2)`, which is 43 million instructions where extended Euclid would be a
fraction of that. Square roots are needed to decompress any elliptic-curve point.

### 5. Longer term: a 64×64→128 multiply

Not needed for the above, but it is what would let someone write a
limb-representation field implementation that competes with Rust's directly. Rust
gets much of its advantage from `[u64; 6]` Montgomery arithmetic; wasm lacks a
widening 64-bit multiply too, which is a large part of why the gap is 10× rather
than 100×.

## What this would be worth

The port currently spends **1.79 billion instructions** per IBE decryption, about
4.5% of an update call's budget — already usable. Items 1 and 2 alone would
plausibly bring that under 500 million, which is the difference between "a
canister can do this" and "a canister can do this without thinking about it".

More broadly: **no pairing-friendly cryptography exists on mops today**, and the
reason is not that nobody wants it. `sha2`, `hmac`, `ecdsa`, `libsecp256k1` and
`tweetnacl` are all there. What is missing is the arithmetic layer underneath, and
what makes that layer slow is one missing primitive that the runtime's own
dependency already implements.

## Reproducing

```bash
cd motoko
mops bench Why      # the 85% split
mops bench Shift    # shifts cost as much as reductions
mops bench Ibe      # end-to-end decryption
mops test           # 95 tests, incl. verifying a real vetKD reply
```

The Rust side of the comparison is `bench_ibe_decrypt` in `crates/canister`,
measured with `ic0.performance_counter` inside a deployed canister on the same
vector — native benchmarks would not be comparable, since what matters is what
the replica charges.

---

*From [icp-seeding-secrets-poc](https://github.com/marc0olo/icp-seeding-secrets-poc).
The Motoko implementation is experimental and unaudited; see
[motoko/README.md](./README.md).*
