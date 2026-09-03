# Motoko

| | |
|---|---|
| [`bls12-381/`](./bls12-381) | **EXPERIMENTAL, UNAUDITED** BLS12-381 for Motoko, plus the vetKD layer built on it. A mops package, no canister code. |
| `canister/` | A Motoko canister using it, mirroring the Rust one in [`../rust/canister`](../rust/canister). |

The library holds what Rust splits across two crates, because splitting a
single unaudited proof of concept into two packages would be ceremony:

| Motoko module | Rust equivalent |
|---|---|
| `Fp`, `Fp2`, `Fp6`, `Fp12`, `G1`, `G2`, `Pairing`, `HashToCurve`, `Hash`, `Scalar` | `ic_bls12_381` — the curve, general-purpose, ~1,900 lines |
| `Ibe`, `VetKey`, `PublicKey` | `ic_vetkeys` — the vetKD layer, IC-specific, ~380 lines |

The directory is named for the larger, lower half. If any of this were ever
upstreamed, that is also the seam it would split along: the curve as a package in
its own right — useful for anything needing pairings, not just vetKD — and the
three vetKD modules into `mo:ic-vetkeys`, which today has no BLS12-381 at all.

The sealed-secrets wire format is deliberately *not* here. It belongs with the
canister, the way `rust/core` sits beside `rust/canister`.

Neither directory is production code. Start at [`../README.md`](../README.md).
