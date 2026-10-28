#!/usr/bin/env bash
# Runs inside WSL. Starts a local solana-test-validator with the registry
# program deployed as an upgradeable program whose upgrade authority is a
# throwaway test keypair (initialize_registry requires that authority).
#
#   localnet.sh run          start the validator in the foreground
#   localnet.sh program-id   print the registry program id
#
# Requires `make anchor-build` first. State lives outside the repo except for
# the git-ignored test keypair in .local/.
set -euo pipefail
export PATH="$HOME/.local/share/solana/install/active_release/bin:$PATH"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEPLOY_DIR="${KYC_REGISTRY_DEPLOY_DIR:-$HOME/build/kyc-registry/target/deploy}"
SO="$DEPLOY_DIR/kyc_registry.so"
KEYPAIR="$ROOT/.local/test-authority-keypair.json"
LEDGER="${KYC_LEDGER_DIR:-$HOME/build/test-ledger}"

[ -f "$SO" ] || { echo "missing $SO: run 'make anchor-build' first" >&2; exit 1; }
PROGRAM_ID="$(solana-keygen pubkey "$DEPLOY_DIR/kyc_registry-keypair.json")"

case "${1:-}" in
program-id)
	echo "$PROGRAM_ID"
	;;
run)
	mkdir -p "$ROOT/.local"
	[ -f "$KEYPAIR" ] || solana-keygen new --no-bip39-passphrase --silent -o "$KEYPAIR"
	# --reset so every run starts from an empty chain.
	exec solana-test-validator --reset --quiet --ledger "$LEDGER" \
		--upgradeable-program "$PROGRAM_ID" "$SO" "$KEYPAIR"
	;;
*)
	echo "usage: $0 run|program-id" >&2
	exit 2
	;;
esac
