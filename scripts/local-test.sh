#!/usr/bin/env bash
#
# Proves the whole thing works, end to end, in one command.
#
#   ./scripts/local-test.sh
#
# Starts a local network, deploys both canisters, encrypts a secret for each,
# sends it, reads it back, and checks it came out identical to what went in.
#
# Note what this does NOT do: export your identity. Encrypting needs no
# identity at all — only the call does, and `icp canister call` signs that with
# the identity icp-cli already holds.
#
# Reading the secret back is only possible because these canisters ship a
# getter that exists purely so you can watch decryption work. A real canister
# must not have one — see the README.

set -euo pipefail
cd "$(dirname "$0")/.."

ENV=local
SECRET="hunter2-$(date +%s)"
ARG=$(mktemp)

say()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
fail() { printf '\033[31mFAIL: %s\033[0m\n' "$*" >&2; exit 1; }
trap 'rm -f "$ARG"' EXIT

# Printed because it decides everything below: whoever deploys becomes the
# canister's controller, and `set_dummy_secret` accepts only the controller.
# On a fresh container with no identity configured this is the ANONYMOUS
# principal, which still works — it deploys, so it is the controller — but the
# check is then vacuous, since anyone can call as anonymous. Fine locally;
# not something to replicate on mainnet.
say "1. start the local network and deploy (as $(icp identity default 2>/dev/null || echo anonymous))"
icp network status "$ENV" >/dev/null 2>&1 || icp network start "$ENV" --background
icp deploy -e "$ENV" --yes >/dev/null
( cd seed && [ -d node_modules ] || npm install --silent >/dev/null 2>&1 )

# Everything below runs identically against both canisters. That is the point:
# one wire format, one client, two implementations.
for canister in dummy-secret-rust dummy-secret-motoko; do
  CID=$(icp canister status "$canister" -e "$ENV" --json | jq -r .id)

  # Each canister names its methods the way its own language does.
  SETTER=set_dummy_secret GETTER=get_dummy_secret
  if [ "$canister" = dummy-secret-motoko ]; then
    SETTER=setDummySecret GETTER=getDummySecret
  fi

  say "2. encrypt a secret for $canister ($CID) — offline, no identity"
  DUMMY_SECRET="$SECRET" npm --prefix seed run --silent seal -- \
    --canister "$CID" --source pocketic --out "$ARG"

  say "3. send it — icp-cli signs with the identity it already has"
  icp canister call "$canister" "$SETTER" --args-file "$ARG" -e "$ENV" >/dev/null

  say "4. read it back out of $canister"
  GOT=$(icp canister call "$canister" "$GETTER" '()' -e "$ENV" 2>/dev/null \
    | tr -d '\n' | sed -n 's/.*opt "\([^"]*\)".*/\1/p')

  [ "$GOT" = "$SECRET" ] || fail "$canister returned '$GOT', expected '$SECRET'"
  echo "  sent:     $SECRET"
  echo "  returned: $GOT"
  echo "  ok — the canister decrypted exactly what the client encrypted"
done

say "done"
echo "Stop the network with: icp network stop"
