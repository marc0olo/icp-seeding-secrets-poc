# Security model

**What sealing gives you.** The secret is encrypted to a key derivable only for this
canister, so it never appears in an ingress message, a Candid argument, or the
canister's interface. The ciphertext is bound to the canister id, so replaying it
elsewhere is useless.

**What SEV-SNP gives you, and nothing else does.** Once decrypted, the plaintext is
canister state: stable memory in the Rust canister, the persistent heap in the Motoko
one. That is replicated, checkpointed to disk on every node and shipped in state sync.
SEV-SNP encrypts the guest's memory under a key the hypervisor cannot access, and its
data disk under a key tied to the launch measurement. **Without a SEV-SNP subnet,
sealing protects the secret in transit and in the ingress history, and nothing more.**

## Who this protects against

| Who | Protected by |
|---|---|
| anyone on the network path: boundary nodes, anyone reading ingress messages or blocks | sealing: they see only IBE ciphertext |
| node operators | SEV-SNP, and only SEV-SNP. On any other subnet they can read the plaintext out of a checkpoint |
| every other principal | controller-gating on every endpoint that touches a secret |
| your repo, CI logs, shell history | the seeder reads the value from the environment, never from argv or a file, so keep it in a secret store rather than an inline assignment |

## Who it does not protect against

**The controller can read the secret**, by installing code that decrypts it (vetKD
binds the key to the canister id, not to the module hash) or by reading it out of a
snapshot. There is no way to pin a sealed secret to a particular code version.

For the case this is built for, that is not a defect: **the controller is whoever
seeded the secret, and already knows it.** The controller set is the access-control
boundary, and what matters is that it is small, known and not shared.

Also not protected: **metadata**. The destination host of an outcall (TLS SNI, DNS),
timing, and request and response sizes are outside the encrypted payload.

And nothing here proves the subnet is SEV-SNP: the preflight reads the registry's
`sev_enabled` flag, not an attestation. Verify that out of band.

## When the controller _is_ in your threat model

An application holding _other people's_ secrets, where users need protection from
whoever operates the canister, does put the controller in scope. Then a single
controller key is not enough, and the answer is **SNS or NNS governance**, so that
installing new code needs a public proposal and a vote. That does not make extraction
impossible; it makes it public.

**Blackholing is not the answer.** `icp_sealed_secret_set` is controller-gated, so a
canister with no controllers could never be seeded or rotated, and API keys expire,
leak and get revoked.
