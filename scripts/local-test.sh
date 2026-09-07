#!/usr/bin/env bash
#
# Proves the whole thing works, end to end, in one command.
#
#   ./scripts/local-test.sh
#
# Starts a local network, deploys both canisters, encrypts a secret for each,
# sends it, reads it back, and checks it came out identical to what went in.
#
# Note what this does NOT do: export your identity. Encrypting needs no identity
# at all; only the call does, and what it needs is a controller of the canister.
# Any identity that controls it, from any client — this just uses icp-cli,
# because you already have it and it already holds one.
#
# Reading the secret back is only possible because these canisters ship a
# getter that exists purely so you can watch decryption work. A real canister
# must not have one — see the README.

set -euo pipefail
cd "$(dirname "$0")/.."

ENV=local
# The timestamp is not decoration: it makes every run's secret distinct, so a
# value left over from a previous run cannot make the comparison pass.
SECRET="super-secret-value-$(date +%s)"

say()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
fail() { printf '\033[31mFAIL: %s\033[0m\n' "$*" >&2; exit 1; }
# Printed because it decides everything below: whoever deploys becomes the
# canister's controller, and `set_dummy_secret` accepts only the controller.
# On a fresh container with no identity configured this is the ANONYMOUS
# principal, which still works — it deploys, so it is the controller — but the
# check is then vacuous, since anyone can call as anonymous. Fine locally;
# not something to replicate on mainnet.
say "1. start the local network and deploy (as $(icp identity default 2>/dev/null || echo anonymous))"
icp network status "$ENV" >/dev/null 2>&1 || icp network start "$ENV" --background

# Repeated runs drain these: a cold `vetkd_derive_key` costs 26 billion cycles,
# and a reinstall resets the cache so the next run derives again. Cycles are free
# on a local network, so top up when the canisters already exist — otherwise the
# fourth or fifth run fails on install with "out of cycles" and looks like a bug.
for c in dummy-secret-rust dummy-secret-motoko; do
  icp canister top-up "$c" --amount 5t -e "$ENV" >/dev/null 2>&1 || true
done

icp deploy -e "$ENV" --yes >/dev/null
( cd seed && [ -d node_modules ] || npm install --silent >/dev/null 2>&1 )

# Everything below runs identically against both canisters. That is the point:
# one wire format, one client, two implementations.
#
# Two secrets, seeded independently, to show what the shared key label buys: the
# canister derives its vetKey once and that one key opens both. Adding a third
# would cost nothing further.
for canister in dummy-secret-rust dummy-secret-motoko; do
  GETTER=get_dummy_secret
  [ "$canister" = dummy-secret-motoko ] && GETTER=getDummySecret

  # Two secrets a canister would plausibly hold: credentials for the HTTPS
  # outcalls it makes. The names are map keys, so any strings would do.
  for name in exchange-rate-api-key rpc-provider-key; do
    # Deliberately the same command the README tells you to run, so the
    # documented path is the tested one.
    say "2. seal '$name' into $canister"
    DUMMY_SECRET="$SECRET-$name" ./scripts/seal.sh "$canister" "$name" "$ENV" >/dev/null

    say "3. read '$name' back out of $canister"
    GOT=$(icp canister call "$canister" "$GETTER" "(\"$name\")" -e "$ENV" 2>/dev/null \
      | tr -d '\n' | sed -n 's/.*opt "\([^"]*\)".*/\1/p')

    [ "$GOT" = "$SECRET-$name" ] || fail "$canister returned '$GOT', expected '$SECRET-$name'"
    echo "  sent:     $SECRET-$name"
    echo "  returned: $GOT"
    echo "  ok — the canister decrypted exactly what the client encrypted"
  done

  # Both were sealed to the same label, so the second used the cached key.
  say "4. $canister still holds the first secret after the second was set"
  FIRST=$(icp canister call "$canister" "$GETTER" '("exchange-rate-api-key")' -e "$ENV" 2>/dev/null \
    | tr -d '\n' | sed -n 's/.*opt "\([^"]*\)".*/\1/p')
  [ "$FIRST" = "$SECRET-exchange-rate-api-key" ] \
    || fail "$canister lost 'exchange-rate-api-key': got '$FIRST'"
  echo "  ok — two secrets, independently set, one derived key"
done

say "done"
echo "Stop the network with: icp network stop"
