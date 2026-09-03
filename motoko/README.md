# Motoko

Two things, deliberately separate:

| | |
|---|---|
| [`vetkeys/`](./vetkeys) | **EXPERIMENTAL, UNAUDITED** BLS12-381 + vetKeys for Motoko. A mops package, no canister code. |
| `canister/` | A Motoko canister using it, mirroring the Rust one in [`../rust/canister`](../rust/canister). |

The split exists because the library is not sealed-secrets-specific — any
canister that needs to decrypt a vetKD-derived key needs all of it. The
sealed-secrets wire format lives with the canister instead.

Neither is production code. Start at [`../README.md`](../README.md).
