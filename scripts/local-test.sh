#!/usr/bin/env bash
#
# Local verification of the whole round trip, for both canisters.
#
#   ./scripts/local-test.sh            everything, in order
#   ./scripts/local-test.sh build      build-level assertions; no network needed
#   ./scripts/local-test.sh setup      identity, network, deploy
#   ./scripts/local-test.sh rust       seal and spend a secret, Rust canister
#   ./scripts/local-test.sh motoko     the same, Motoko canister
#
# The phases exist so CI can run them as separately named steps: a single
# opaque "round trip" step tells you it broke but not which implementation.
# Each phase re-derives what it needs, so they can also be run one at a time
# while iterating.
#
# Starts a local network, deploys, seals a secret, and proves the canister
# recovered the exact plaintext — including reading it back in the clear via the
# `test-hooks` build, so you can see it with your own eyes.
#
# Also asserts that a build WITHOUT `--features test-hooks` exports no endpoint
# that can observe a secret.

set -euo pipefail

cd "$(dirname "$0")/.."

CANISTER=sealed-secrets-rust
ENV=local
HOST=http://127.0.0.1:8010
SECRET_NAME=DUMMY_API_KEY
# postman-echo's /basic-auth accepts this documented credential and rejects
# anything else, which lets the outcall test assert BOTH branches with no setup.
# A published credential proves nothing about secrecy — but this is proving the
# mechanism, and for that it is exactly right.
OUTCALL_SECRET_NAME=DEMO_AUTH_HEADER
OUTCALL_GOOD='Basic cG9zdG1hbjpwYXNzd29yZA=='
OUTCALL_BAD='Basic d3Jvbmc6d3Jvbmc='

SECRET_VALUE="sk-local-test-$(date +%s)-do-not-use"
TEST_IDENTITY=sealed-secrets-test

# Nothing here exports an identity. Sealing does not need one (encryption is
# offline; `icp canister call` signs the send). The e2e harness brings its own,
# generated in-process from a fixed seed — authorise_e2e adds its principal as a
# controller, which is also what lets the suite test the controller gate with a
# second, anonymous caller.
ARGS_FILE="$(mktemp -t sealed-secrets-args.XXXXXX)"

say()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
fail() { printf '\033[31mFAIL: %s\033[0m\n' "$*" >&2; exit 1; }

cleanup() { rm -f "$ARGS_FILE"; }
trap cleanup EXIT

# Re-derived per phase rather than passed between them, so any phase can run
# alone. Both are cheap: a status query and a key export.
resolve_cid() {
  icp canister status "$1" -e "$ENV" --json | jq -r .id
}

ensure_client() {
  ( cd seed && [ -d node_modules ] || npm install --silent >/dev/null 2>&1 )
}

# The e2e suite calls controller-gated endpoints in-process, so its own
# principal has to be a controller. Idempotent: adding one twice is a no-op.
authorise_e2e() {
  ensure_client
  local principal
  principal=$(npm --prefix seed run --silent e2e -- --print-principal | tail -1)
  icp canister settings update "$1" --add-controller "$principal" -e "$ENV" --force >/dev/null
}

# The two halves of sealing, which is the whole point of splitting them:
# encryption is offline and needs no identity, the call needs a controller.
# Pass "verify" as $5 to ask matches() instead of storing.
#   $1 canister name  $2 canister id  $3 secret name  $4 value  [$5 "verify"]
seal() {
  local flags=(--canister "$2" --name "$3" --source pocketic --out "$ARGS_FILE")
  local method=icp_sealed_secret_set
  if [ "${5:-}" = verify ]; then
    flags+=(--verify)
    method=icp_sealed_secret_matches
  fi
  env "$3=$4" npm --prefix seed run --silent seal -- "${flags[@]}" >/dev/null 2>&1 \
    || fail "could not encrypt $3 for $1"
  icp canister call "$1" "$method" --args-file "$ARGS_FILE" -e "$ENV"
}

phase_build() {
say "1. the default build exposes no way to observe a secret"
# Checked against the wasm binary, not just the extracted Candid: a canister
# method IS a wasm export, so a name absent from the bytes cannot be called at
# all. Confirmed once by hand — calling secret_reveal on a default build is
# rejected by the replica with IC0536 "Canister has no update method".
cargo build -p sealed-secrets-canister --target wasm32-unknown-unknown --release --locked >/dev/null 2>&1
PROD_WASM=target/wasm32-unknown-unknown/release/sealed_secrets_canister.wasm
for hook in secret_reveal; do
  if grep -aq "$hook" "$PROD_WASM"; then
    fail "'$hook' is present in the default build; test-hooks is leaking into production"
  fi
done
# A control, so this cannot pass by looking at the wrong file or a stale build.
grep -aq "icp_sealed_secret_set" "$PROD_WASM" \
  || fail "control failed: icp_sealed_secret_set missing from $PROD_WASM"
echo "  ok — secret_reveal absent from the binary (control: set present)"


say "2. the generated TypeScript bindings match the canister"
( cd seed && [ -d node_modules ] || npm install --silent >/dev/null 2>&1 )
# git is the portable diff here: no shasum/sha256sum, which differ across macOS
# and slim Linux images. The declarations are tracked, so regenerating and
# finding no change is the check.
cargo build -p sealed-secrets-canister --target wasm32-unknown-unknown --release --locked \
  --features test-hooks >/dev/null 2>&1
candid-extractor target/wasm32-unknown-unknown/release/sealed_secrets_canister.wasm \
  > rust/canister/sealed_secrets_canister.did
# Compare the working tree against itself across a regeneration, rather than
# against HEAD: this must pass mid-change, before anything is committed. CI runs
# the stricter "regenerated output matches what is committed" check.
GEN_PATHS="rust/canister/sealed_secrets_canister.did seed/src/declarations"
BEFORE=$(git diff -- $GEN_PATHS; git status --porcelain -- $GEN_PATHS)
npm --prefix seed run --silent bindings >/dev/null 2>&1
AFTER=$(git diff -- $GEN_PATHS; git status --porcelain -- $GEN_PATHS)
[ "$BEFORE" = "$AFTER" ] \
  || fail "seed/src/declarations was stale — regenerating changed it. Review and commit."
echo "  ok — declarations are up to date with the .did"

}

phase_setup() {
say "3. make sure there is a non-anonymous identity"
# The network seeds cycles to the default identity at start-up, so this has to
# happen BEFORE the network comes up.
#
# "a default exists" is not the test: a fresh container defaults to the ANONYMOUS
# identity, which exists and has no key, so it cannot control a canister. Check
# for a usable one, and only then create ours. That keeps a developer's own
# default untouched locally while still working in CI, where `plaintext` storage
# is required because a container has no keyring and no TTY for a password
# prompt.
IDENTITY=$(icp identity default 2>/dev/null || true)
if [ -z "$IDENTITY" ] || [ "$IDENTITY" = "anonymous" ]; then
  if ! icp identity list 2>/dev/null | awk '{print $1}' | grep -qx "$TEST_IDENTITY"; then
    icp identity new "$TEST_IDENTITY" --storage plaintext --quiet >/dev/null
    echo "  created '$TEST_IDENTITY' (default was ${IDENTITY:-unset})"
  fi
  icp identity default "$TEST_IDENTITY" >/dev/null
  IDENTITY="$TEST_IDENTITY"
fi
echo "  using '$IDENTITY' ($(icp identity principal))"

say "4. start the local network"
if icp network status "$ENV" >/dev/null 2>&1; then
  echo "  already running"
else
  icp network start "$ENV" --background
fi

say "5. deploy (with --features test-hooks, per icp.yaml)"
# --yes skips the Candid compatibility prompt: this script tests whatever is in
# the working tree, and an interface change mid-development is expected here in a
# way it would not be for a production upgrade.
icp deploy -e "$ENV" --yes >/dev/null
CID=$(icp canister status "$CANISTER" -e "$ENV" --json | jq -r .id)
echo "  canister: $CID"

}

phase_rust() {
  CID=$(resolve_cid "$CANISTER")
  ensure_client
say "6. preflight — is this subnet SEV-SNP?"
# Locally it cannot be, so this only exercises the code path. On mainnet it is
# the check the whole security argument rests on.
npm --prefix seed run --silent preflight -- --canister "$CID" --host "$HOST" --local

say "7. seal a secret — which is also the health check"
# There is no separate health-check endpoint. set() derives the vetKey, verifies
# it and decrypts, so a subnet that cannot serve vetKD, a wrong key name or a
# mis-derived key all fail right here. And the seeder refuses to encrypt at all
# unless its own offline derivation matches what the canister reports."
seal "$CANISTER" "$CID" "$SECRET_NAME" "$SECRET_VALUE"

say "8. read it back IN THE CLEAR (test-hooks build only)"
REVEALED=$(icp canister call "$CANISTER" secret_reveal "(\"$SECRET_NAME\")" -e "$ENV" 2>/dev/null \
  | tr -d '\n' | sed -n 's/.*= "\(.*\)".*/\1/p')
echo "  sealed:   $SECRET_VALUE"
echo "  revealed: $REVEALED"
[ "$REVEALED" = "$SECRET_VALUE" ] || fail "the canister did not recover the plaintext"
echo "  ok — byte-for-byte match"

say "9. an operator can confirm the right value WITHOUT revealing it"
# This is the production-safe check: seal the expected value and ask the canister
# whether it matches. One bit back, nothing disclosed in either direction.
SEALED_MATCHES=$(icp canister call "$CANISTER" icp_sealed_secret_matches \
  "(\"$SECRET_NAME\", blob \"\")" -e "$ENV" 2>&1 || true)
echo "  (matches() with an empty blob is correctly rejected as malformed)"
grep -q "InvalidCiphertext" <<<"$SEALED_MATCHES" \
  || fail "matches() did not reject a malformed candidate"
echo "  ok — matches() validates its input"

say "10. the actual use case: an authenticated HTTPS outcall"
# The point of the whole exercise. The canister reads the plaintext, puts it in
# an Authorization header, calls out, and returns only the status code — never
# the body, which on an echoing endpoint would hand the header straight back.
seal_secret() {
  seal "$CANISTER" "$CID" "$OUTCALL_SECRET_NAME" "$1" >/dev/null
}
outcall_status() {
  icp canister call "$CANISTER" call_api_with_secret \
    "(\"$OUTCALL_SECRET_NAME\", \"$1\")" -e "$ENV" 2>&1 | tr -d '\n '
}

seal_secret "$OUTCALL_GOOD"
GOOD_STATUS=$(outcall_status "demo-op-0001")
case "$GOOD_STATUS" in
  *"Ok=200"*) echo "  ok — the call SUCCEEDS with the sealed credential (200)" ;;
  *Ok=*)      fail "expected 200 with the correct credential, got: $GOOD_STATUS" ;;
  *)          echo "  WARN could not reach the API; skipping (external dependency): $GOOD_STATUS" ;;
esac

# And prove the secret's VALUE is what did it, not merely that a request went out.
if [[ "$GOOD_STATUS" == *"Ok=200"* ]]; then
  seal_secret "$OUTCALL_BAD"
  BAD_STATUS=$(outcall_status "demo-op-0002")
  case "$BAD_STATUS" in
    *"Ok=401"*) echo "  ok — and FAILS with a wrong one (401): the value is what authenticated" ;;
    *)          fail "expected 401 with a wrong credential, got: $BAD_STATUS" ;;
  esac
  seal_secret "$OUTCALL_GOOD"
fi

say "11. it survives an upgrade with no re-seeding"
icp deploy -e "$ENV" --yes >/dev/null
AFTER=$(icp canister call "$CANISTER" secret_reveal "(\"$SECRET_NAME\")" -e "$ENV" 2>/dev/null \
  | tr -d '\n' | sed -n 's/.*= "\(.*\)".*/\1/p')
[ "$AFTER" = "$SECRET_VALUE" ] || fail "the secret did not survive the upgrade"
echo "  ok — still readable after upgrade, the secret lives in stable memory"

say "12. the negative cases"
authorise_e2e "$CANISTER"
npm --prefix seed run --silent e2e -- --canister "$CID" --host "$HOST" --source pocketic

}

phase_motoko() {
  ensure_client
say "13. the same round trip against the Motoko canister"
# The point of this step is that nothing below is Motoko-specific except the
# canister name. The same seeding script, the same wire format, the same
# interface — driven against a canister whose decryption runs on this repo's
# experimental pure-Motoko BLS12-381 rather than on ic-vetkeys.
MO_CANISTER=sealed-secrets-motoko
MO_CID=$(icp canister status "$MO_CANISTER" -e "$ENV" --json | jq -r .id)
echo "  canister: $MO_CID"

mo_seal() {
  seal "$MO_CANISTER" "$MO_CID" "$OUTCALL_SECRET_NAME" "$1" >/dev/null
}
mo_seal "$OUTCALL_GOOD"
echo "  ok — the unmodified seeder sealed to it, and it trial-decrypted before storing"

# No secret_reveal here. Motoko has no feature flags, and it turns out not to
# need any: matches() answers "is the right value set?" from a build that ships,
# which is what the Rust canister's own documentation recommends over a reveal
# hook anyway.
seal "$MO_CANISTER" "$MO_CID" "$OUTCALL_SECRET_NAME" "$OUTCALL_GOOD" verify \
  | grep -q "true" \
  || fail "the Motoko canister does not hold the value we sealed"
echo "  ok — matches() confirms the value without either side disclosing it"

mo_status() {
  icp canister call "$MO_CANISTER" call_api_with_secret \
    "(\"$OUTCALL_SECRET_NAME\", \"$1\")" -e "$ENV" 2>&1 | tr -d '\n '
}
MO_GOOD=$(mo_status "motoko-op-0001")
case "$MO_GOOD" in
  *"Ok=200"*) echo "  ok — authenticated HTTPS outcall SUCCEEDS (200)" ;;
  *Ok=*)      fail "expected 200 from the Motoko canister, got: $MO_GOOD" ;;
  *)          echo "  WARN could not reach the API; skipping (external dependency): $MO_GOOD" ;;
esac

if [[ "$MO_GOOD" == *"Ok=200"* ]]; then
  mo_seal "$OUTCALL_BAD"
  MO_BAD=$(mo_status "motoko-op-0002")
  case "$MO_BAD" in
    *"Ok=401"*) echo "  ok — and FAILS with a wrong one (401)" ;;
    *)          fail "expected 401 from the Motoko canister, got: $MO_BAD" ;;
  esac
  mo_seal "$OUTCALL_GOOD"
fi

icp deploy -e "$ENV" --yes >/dev/null
MO_AFTER=$(mo_status "motoko-after-upgrade")
case "$MO_AFTER" in
  *"Ok=200"*) echo "  ok — survives an upgrade with no re-seeding" ;;
  *)          fail "the Motoko canister lost its secret across an upgrade: $MO_AFTER" ;;
esac

# The same 14 assertions step 12 runs against the Rust canister, with nothing
# changed but the canister id. That is the claim this repo makes -- one wire
# format, one client, two implementations -- and running the suite twice is what
# tests it. It needs no test hooks, which is why the Motoko canister can pass it
# without shipping an endpoint that discloses a secret.
say "14. the full negative-case suite against the Motoko canister"
authorise_e2e "$MO_CANISTER"
npm --prefix seed run --silent e2e -- --canister "$MO_CID" --host "$HOST" --source pocketic

}

case "${1:-all}" in
  build)  phase_build ;;
  setup)  phase_setup ;;
  rust)   phase_rust ;;
  motoko) phase_motoko ;;
  all)    phase_build; phase_setup; phase_rust; phase_motoko ;;
  *)      fail "unknown phase '$1' — use build, setup, rust, motoko, or all" ;;
esac

say "done"
echo "Stop the network with: icp network stop"
