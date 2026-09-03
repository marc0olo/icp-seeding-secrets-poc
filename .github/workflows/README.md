# Workflow layout

One workflow per thing being tested, so a red check names the culprit without
opening it.

| Workflow | Answers |
|---|---|
| `rust.yml` | Does the Rust canister build, lint, pass its golden vectors — and does the default build still refuse to expose a secret? |
| `motoko.yml` | Do the three Motoko packages compile warning-free and pass their unit tests, against vectors generated from the Rust reference? |
| `client.yml` | Does the TypeScript seeder typecheck, agree with the Rust golden vectors, and are the generated bindings current? |
| `e2e.yml` | Against a real replica: does sealing and spending a secret work — separately for each canister, so a failure names the implementation? |

`e2e.yml` is one workflow rather than two because both canisters share a network
and a deploy; splitting it would double the slowest part. The phases inside it
are named steps instead — see `scripts/local-test.sh`, which takes the same phase
names so you can reproduce any single step locally.
