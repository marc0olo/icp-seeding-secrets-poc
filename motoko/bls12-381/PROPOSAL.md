# What would make BLS12-381 faster in Motoko

A note for the Motoko team, from porting `ic_bls12_381` to Motoko so that a
Motoko canister can decrypt a vetKD-sealed secret. The port works — it verifies a
real `vetkd_derive_key` reply and decrypts a ciphertext produced by the Rust
reference — at about **6.6× the instruction cost of the same operation in
Rust**, measured inside a canister on the same vector.

Everything below is measured on `moc` 1.15.1. Reproduce with `mops bench` in this
directory.

---

## The finding

A base-field multiplication is a product of two 381-bit numbers followed by a
reduction modulo the BLS12-381 prime `P`. Per operation:

| | Instructions |
|---|---:|
| `(a * b) % P` | 53,789 |
| `Fp.mul` — the product, then Barrett reduction | 31,717 |
| the product alone | 9,182 |

**The reduction is the cost, not the arithmetic.** With `%` it is 85% of a
multiplication. Barrett reduction brings that down to about 70%, and a pairing
performs tens of thousands of these.

## What userland can already do

Barrett reduction replaces the division with two multiplications and two shifts
by a power of two. That only pays because `Nat.bitshiftRight` is cheap — the
runtime implements it with libtommath's `mp_div_2d`:

| | Instructions |
|---:|---:|
| `big % P` | 45,440 |
| `big / (2 ** 381)` | 39,532 |
| `Nat.bitshiftRight(big, 381)` | 3,070 |

`Nat` division does not special-case powers of two, so code that writes a shift
as `x / (2 ** k)` — or tests a bit with `n % 2` — pays for a full division.
Recognising those forms in the compiler would help any code that has not been
rewritten to use the shift functions.

What userland cannot avoid is that every intermediate is a freshly allocated
bignum, and that Barrett needs two full-width products on top of the one being
reduced.

## Why runtime support would be cheap to add

Motoko's `Nat` is [libtommath](https://github.com/libtom/libtommath) with 64-bit
digits (`rts/Makefile`, `-DMP_64BIT`), and `%` maps to `mp_div` with the quotient
discarded (`rts/motoko-rts/src/bigint.rs`, `bigint_rem`).

**libtommath already implements the missing operations.** The runtime simply does
not compile them in. `rts/Makefile` carries an explicit list (`TOMMATHFILES`),
and absent from it, all present upstream:

| libtommath | what it would give Motoko |
|---|---|
| `mp_montgomery_reduce`, `mp_montgomery_setup` | Montgomery reduction |
| `mp_reduce`, `mp_reduce_setup` | Barrett reduction, without allocating the intermediates |
| `mp_exptmod` | modular exponentiation, windowed |
| `mp_invmod` | modular inverse |
| `mp_sqrtmod_prime` | modular square root |

## What we would ask for, in order of value per unit of work

### 1. `Nat.mulMod(a, b, m)`

The operation this port is bottlenecked on. Backed by `mp_montgomery_reduce` or
`mp_reduce`, it would do the reduction in place, with no intermediate `Nat`s. We
have not measured how close to the 9,182-instruction product that gets.

If a modulus-specific setup cost is a concern, an opaque prepared-modulus value
(`Nat.prepareModulus(m)` returning a handle reused across calls) would match how
`mp_reduce_setup` and `mp_montgomery_setup` are meant to be used, and matters
here because the modulus is fixed for the lifetime of the program.

### 2. `Nat.powMod(base, exp, modulus)`

`mp_exptmod`. Our square-and-multiply costs **19 million instructions** for a
381-bit exponent; a windowed implementation over native Montgomery arithmetic
should be several times cheaper. Modular exponentiation is ubiquitous well
beyond this port — RSA, Diffie–Hellman, and every "is this a quadratic residue"
test.

### 3. `Nat.invMod(a, m)` and `Nat.sqrtMod(a, p)`

`mp_invmod` and `mp_sqrtmod_prime`. Our extended Euclid costs about 4 million
instructions and our square root 19 million. Square roots are needed to
decompress any elliptic-curve point.

### 4. Longer term: a 64×64→128 multiply

Not needed for the above, but it is what would let someone write a
limb-representation field implementation that competes with Rust's directly.

## What this would be worth

The port spends **1.09 billion instructions** per IBE decryption, about 2.7% of
an update call's budget, and 3.1 billion for the full cold path of verifying a
vetKey and then decrypting — already usable. Native modular multiplication
would target the reduction, which is about 70% of every base-field
multiplication.

## Reproducing

```bash
cd motoko/bls12-381
mops bench Why      # the product/reduction split
mops bench Shift    # division versus shift
mops test           # 85 tests, the curve layer

cd ../vetkeys
mops bench Ibe      # end-to-end decryption
mops bench VetKey   # unwrapping and verifying a real vetKD reply
mops test           # 23 tests
```

The Rust side of the comparison is `bench_ibe_decrypt`, a `test-hooks` endpoint
of the Rust canister on the
[`standardization-proposal`](../../../../tree/standardization-proposal) branch,
measured with `ic0.performance_counter` inside a deployed canister on the same
vector — native benchmarks would not be comparable, since what matters is what
the replica charges.

---

*From [icp-seeding-secrets-poc](https://github.com/marc0olo/icp-seeding-secrets-poc).
The Motoko implementation is experimental and unaudited; see
[motoko/bls12-381/README.md](./README.md).*
