# Workflow layout

One workflow per thing being tested, so a red check names the culprit without
opening it.

| Workflow | Answers |
|---|---|
| `rust.yml` | Does the Rust canister build and lint, and does the committed `.did` still match it? |
| `motoko.yml` | Do the two experimental Motoko crypto packages compile warning-free and pass their unit tests, against vectors generated from the Rust reference? |
| `client.yml` | Does the TypeScript seeding script typecheck? |
| `e2e.yml` | Against a real replica: does a secret sealed by the client come back out of both canisters unchanged? |

`e2e.yml` is the one that matters. The others fail faster.
