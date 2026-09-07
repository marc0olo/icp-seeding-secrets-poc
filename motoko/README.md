# Motoko

Three packages, split along the boundary that matters for upstreaming.

| | |
|---|---|
| [`bls12-381/`](./bls12-381) | **EXPERIMENTAL, UNAUDITED.** The curve: field tower, both groups, the optimal ate pairing, RFC 9380 hash-to-curve. Nothing IC-specific — useful for anything needing pairings. |
| [`vetkeys/`](./vetkeys) | **EXPERIMENTAL, UNAUDITED.** The vetKD layer on top of it: IBE decryption, vetKey verification, offline derived-public-key computation. |
| [`canister/`](./canister) | A canister using them, mirroring the Rust one in [`../rust/canister`](../rust/canister). Verified end to end against a live subnet. |

The split mirrors Rust, where `ic_bls12_381` is the curve crate and `ic-vetkeys`
is a separate one layered on it — and it makes the upstreaming scope a directory
rather than a paragraph:

- **`vetkeys/` is what `mo:ic-vetkeys` is missing.** Today that library has
  `key_manager`, `encrypted_maps`, `ManagementCanister` and `Types`, and no way
  to decrypt anything — because it has no BLS12-381 underneath.
- **`bls12-381/` is what would have to exist first**, as a package in its own
  right, and what would have to be audited.

`vetkeys/` reaches into `bls12-381/`'s `Hash` for HKDF and SHAKE256. Upstream
those come from the `sha2` and `sha3` crates rather than from `ic_bls12_381`, so
that one import is a convenience of this port, not part of the boundary.

[`vectors.json`](./vectors.json) is shared, and covers both layers. It was
generated from `ic_bls12_381` and `ic-vetkeys` — the audited Rust
implementations — so what these packages assert against is not their own
arithmetic restated, but values a reviewed implementation produced.

The generator is **not** in this branch. It is a 400-line dev tool that nobody
reading the PoC needs, and it lives on the
[`standardization-proposal`](../../../tree/standardization-proposal) branch,
under rust/vectorgen there. The consequence is worth knowing: these vectors are now fixed
constants. Upgrading `ic_bls12_381` will not re-derive them, so if you change
anything about the reference, regenerate them from that branch.

The two constants the PoC uses — its vetKD context and its IBE identity — are
deliberately not in either library. They belong to the application, and they live
in the canister next to the code that uses them.

None of this is production code. Start at [`../README.md`](../README.md).
