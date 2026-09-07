# Workflow layout

One workflow per thing being tested, so a red check names the culprit without
opening it.

| Workflow | Answers |
|---|---|
| `rust.yml` | Does the Rust canister build and lint, and does the committed `.did` still match it? |
| `motoko.yml` | Do the two experimental crypto packages compile warning-free and pass their unit tests? |
| `client.yml` | Does the seeding script typecheck, and does the README's diagram still parse? |
| `e2e.yml` | Against a real replica: do secrets sealed by the client come back out of both canisters unchanged? |

`e2e.yml` is the one that matters. The others fail faster.

The Motoko packages test against `motoko/vectors.json`, which was generated from
the audited Rust implementations. The generator is not in this branch — see
[`motoko/README.md`](../../motoko/README.md).
