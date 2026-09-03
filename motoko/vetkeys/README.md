# vetKeys for Motoko — experimental

> ## ⚠️ EXPERIMENTAL AND UNAUDITED
>
> A proof of concept. No cryptographer has reviewed it. Do not use it in
> production. See the [sealed-secrets PoC](../../README.md) for what it is for.

The vetKD layer: everything that happens to a `vetkd_derive_key` reply once a
canister has it, plus the offline derivation that makes verifying one meaningful.

| Module | Rust equivalent | What it does |
|---|---|---|
| `VetKey` | `EncryptedVetKey`, `TransportSecretKey` | Parses the subnet's 192-byte reply, unwraps it with the transport key, and **verifies** the result is a genuine BLS signature. |
| `Ibe` | `IbeCiphertext` | Decrypts a secret sealed to this canister's identity. Decryption only — a canister never encrypts. |
| `PublicKey` | `MasterPublicKey`, `DerivedPublicKey` | Computes a derived public key offline from a master key compiled into the canister. |

## Why this is a separate package

**This is what `mo:ic-vetkeys` is missing.** That library today has
`key_manager`, `encrypted_maps`, `ManagementCanister` and `Types` — and no way to
decrypt anything, because there is no BLS12-381 underneath it. These three
modules are the gap, and keeping them in their own package makes the
upstreaming scope a directory rather than a paragraph.

The curve they sit on is [`../bls12-381`](../bls12-381), which would have to
exist as a package in its own right, and be audited, before any of this could be
upstreamed.

One wrinkle: `Ibe` reaches into `bls12-381`'s `Hash` for HKDF and SHAKE256.
Upstream those come from the `sha2` and `sha3` crates rather than from
`ic_bls12_381`, so that import is a convenience of this port and not part of the
boundary.

## What a canister still has to do itself

Fetching the reply. `vetkd_derive_key` is an ordinary management-canister call
that Motoko has always been able to make; it was never the obstacle. See
[`../canister/src/Keys.mo`](../canister/src/Keys.mo) for a worked example,
including the per-key-name cycle fee and the caching that keeps the cost to once
per canister lifetime.

## The trust story

`VetKey.decryptAndVerify` is only as good as the derived public key handed to it.
A canister that fetches that key from `vetkd_public_key` is asking the subnet to
vouch for itself. `PublicKey` closes that loop: it derives the same key from a
master public key compiled into the Wasm, which an auditor can read in the
source.

That is the one check in the whole design that is not circular, and it is why
these two modules belong together.

## Cost

Measured inside a canister, against the 40 billion instructions an update call
gets. Both results are cached, so a canister pays this once.

| | Instructions | Share of an update call |
|---|---:|---:|
| `decryptAndVerify` — two multipairings and a hash-to-curve | 3,573,000,849 | 8.9% |
| `Ibe.decrypt` — one pairing | 1,792,820,565 | 4.5% |
| **The cold path — both** | **≈ 5,365,821,414** | **≈ 13.4%** |

Quoting the decryption figure alone understates the real cost by a third: a
canister cannot just decrypt, it must first establish that the key it is
decrypting with is its own.

For where that cost comes from and what would remove it, see
[`../bls12-381/README.md`](../bls12-381/README.md#where-the-performance-gap-actually-is)
and [`../bls12-381/PROPOSAL.md`](../bls12-381/PROPOSAL.md).

## Status

| Module | State |
|---|---|
| `Ibe` — IBE decryption | ✅ 6 tests — decrypts the reference ciphertext |
| `VetKey` — unwrap and verify | ✅ 10 tests against a real `vetkd_derive_key` reply |
| `PublicKey` — offline derivation | ✅ 7 tests, matching the Rust reference byte for byte |

```bash
mops test    # 23 tests
mops bench   # instruction counts
```

## The two vectors that decide it

Most of the suite checks one layer at a time. Two vectors check the whole thing,
and they are the ones to look at first.

### Decrypting a reference ciphertext

[`../vectors.json`](../vectors.json) carries a complete IBE triple — a derived public key, an
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

So [`../vectors.json`](../vectors.json) also carries an `encrypted_vetkey` block: a transport
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
