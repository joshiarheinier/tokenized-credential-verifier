#!/usr/bin/env bash
# Run anchor against a WSL-native copy of this workspace.
# yarn/cargo can't reliably write to /mnt/c (drvfs: EPERM, slow builds), so sync
# the sources to the Linux filesystem and run there. Usage: anchor-wsl.sh test
set -euo pipefail
export PATH="$HOME/.local/share/solana/install/active_release/bin:$PATH"
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DST="${CREDENTIAL_REGISTRY_BUILD_DIR:-$HOME/build/credential-registry}"
mkdir -p "$DST/target/deploy"
rsync -a --delete --exclude target --exclude node_modules --exclude test-ledger --exclude .anchor "$SRC/" "$DST/"
# Keep the program keypair stable so it matches declare_id!.
cp -n "$SRC"/target/deploy/*-keypair.json "$DST/target/deploy/" 2>/dev/null || true
cd "$DST"
# Throwaway local-dev wallet (not your real id.json); lives outside the repo.
WALLET="${CREDENTIAL_REGISTRY_WALLET:-$HOME/build/credential-registry-dev-wallet.json}"
[ -f "$WALLET" ] || solana-keygen new --no-bip39-passphrase --silent -o "$WALLET"
export ANCHOR_WALLET="$WALLET"
[ -d node_modules ] || yarn install
anchor "$@"
