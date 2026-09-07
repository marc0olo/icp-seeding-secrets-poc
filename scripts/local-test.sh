#!/usr/bin/env bash
#
# Proves the whole thing works, end to end, in one command.
#
#   ./scripts/local-test.sh
#
# Starts a local network, deploys both canisters, seals a secret to each with
# the seeding script, reads it back, and checks it came out identical to what
# went in.
#
# Reading the secret back is only possible because these canisters ship a
# `get_dummy_secret` endpoint that exists purely so you can watch decryption
# work. A real canister must not have one — see the README.

set -euo pipefail
cd "$(dirname "$0")/.."

ENV=local
HOST=http://127.0.0.1:8010
SECRET="hunter2-$(date +%s)"
PEM=/tmp/dummy-secret-id.pem

say()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
fail() { printf '\033[31mFAIL: %s\033[0m\n' "$*" >&2; exit 1; }
trap 'rm -f "$PEM"' EXIT

say "1. an identity we can export"
# A fresh container defaults to the ANONYMOUS identity, which exists, has no key
# and cannot be exported. So check for a usable one before creating ours.
IDENTITY=$(icp identity default 2>/dev/null || true)
if [ -z "$IDENTITY" ] || [ "$IDENTITY" = "anonymous" ]; then
  icp identity list 2>/dev/null | awk '{print $1}' | grep -qx dummy-secret-test \
    || icp identity new dummy-secret-test --storage plaintext --quiet >/dev/null
  icp identity default dummy-secret-test >/dev/null
  IDENTITY=dummy-secret-test
fi
icp identity export "$IDENTITY" > "$PEM"
echo "  using '$IDENTITY'"

say "2. start the local network and deploy"
icp network status "$ENV" >/dev/null 2>&1 || icp network start "$ENV" --background
icp deploy -e "$ENV" --yes >/dev/null
( cd seed && [ -d node_modules ] || npm install --silent >/dev/null 2>&1 )

# Everything below runs identically against both canisters. That is the point:
# one wire format, one client, two implementations.
for canister in dummy-secret-rust dummy-secret-motoko; do
  CID=$(icp canister status "$canister" -e "$ENV" --json | jq -r .id)

  # Each canister names its methods the way its language does.
  MOTOKO=""; GETTER=get_dummy_secret
  if [ "$canister" = dummy-secret-motoko ]; then MOTOKO=--motoko; GETTER=getDummySecret; fi

  say "3. seal a secret into $canister ($CID)"
  SEAL_IDENTITY_PEM="$PEM" DUMMY_SECRET="$SECRET" \
    npm --prefix seed run --silent seal -- \
      --canister "$CID" --host "$HOST" --source pocketic $MOTOKO

  say "4. read it back out of $canister"
  METHOD="$GETTER"
  GOT=$(icp canister call "$canister" "$METHOD" '()' -e "$ENV" 2>/dev/null \
    | tr -d '\n' | sed -n 's/.*opt "\([^"]*\)".*/\1/p')

  [ "$GOT" = "$SECRET" ] || fail "$canister returned '$GOT', expected '$SECRET'"
  echo "  sent:     $SECRET"
  echo "  returned: $GOT"
  echo "  ok — the canister decrypted exactly what the client encrypted"
done

say "done"
echo "Stop the network with: icp network stop"
