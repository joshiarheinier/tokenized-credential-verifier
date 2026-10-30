# Running against Solana devnet

A one-off manual check (Phase 5, step 4b) of what a real network does that the
local validator does not: confirmation delays, rate limits, and a real deploy
with a real wallet as the upgrade authority. It is not part of CI; localnet stays
the place for automated tests. The program does not change: same build, same
program id.

Only the deploy needs WSL. The backend, inspector, wallet and dApp run on Windows
as in `guide_demo_setup.md` and reach devnet directly.

The wallet that deploys the program must also be the registry authority, because
`initialize_registry` requires the program's upgrade authority to sign.

## 1. Deploy (WSL)

Use throwaway keys, never your Phantom keys. `.local/` is git-ignored.

```bash
REPO=/mnt/c/Users/Joshia/GolandProjects/tokenized-credential-verifier
export PATH="$HOME/.local/share/solana/install/active_release/bin:$PATH"
DEPLOY=$HOME/build/credential-registry/target/deploy

# the program must be built; if this is missing or older than your program
# sources, build it first (see the note below this block)
ls -l $DEPLOY/credential_registry.so

# the program keypair must still give the id in declare_id
solana-keygen pubkey $DEPLOY/credential_registry-keypair.json   # 6NY7DBX4GQTq25E8pcrxUw4wDtGAC3EX1QVwD8jUDUMy

solana-keygen new --no-bip39-passphrase -o $REPO/.local/devnet-deploy-keypair.json
solana-keygen new --no-bip39-passphrase -o $REPO/.local/devnet-issuer-keypair.json
```

To build, run `make anchor-build` from the repository root in Windows (not inside
WSL, since the recipe itself calls `wsl`). If `make` reports `wsl: No such file or
directory`, its shell lacks `C:\Windows\System32` on its `PATH`; run the recipe
directly instead (it does nothing if the program is already up to date):

```text
wsl -e bash -ic 'cd contracts/credential-registry && ./scripts/anchor-wsl.sh build'
```

Fund both addresses (`solana-keygen pubkey <file>`). The deploy wallet needs
roughly 2 to 5 SOL; the issuer key about 1 SOL for fees and credential records.
`solana airdrop 2 <address> --url devnet` is rate-limited and often refuses; the
web faucet at <https://faucet.solana.com> is the fallback. To see the rent:

```bash
solana rent $(( $(stat -c%s $DEPLOY/credential_registry.so) * 2 )) --url devnet
```

Deploy:

```bash
solana program deploy $DEPLOY/credential_registry.so \
  --program-id $DEPLOY/credential_registry-keypair.json \
  --keypair $REPO/.local/devnet-deploy-keypair.json \
  --upgrade-authority $REPO/.local/devnet-deploy-keypair.json \
  --url devnet
```

## 2. Run the stack (Windows)

Save as `.local/devnet.env`, pasting the seed you use for `.local/demo.env`:

```text
APP_ENV=development
HTTP_ADDR=127.0.0.1:8080
ISSUER_ID=did:example:demo-issuer
ISSUER_SIGNING_KEY_SEED=<the seed>
SOLANA_RPC_URL=https://api.devnet.solana.com
SOLANA_PROGRAM_ID=6NY7DBX4GQTq25E8pcrxUw4wDtGAC3EX1QVwD8jUDUMy
SOLANA_REGISTRY_AUTHORITY_KEYPAIR=.local/devnet-deploy-keypair.json
SOLANA_ISSUER_AUTHORITY_KEYPAIR=.local/devnet-issuer-keypair.json
SOLANA_BOOTSTRAP=true
SOLANA_TX_TIMEOUT=60s
APPROVAL_SIMULATION_ENABLED=true
CORS_ALLOWED_ORIGINS=http://localhost:9091
```

```bash
go run ./cmd/api -env-file .local/devnet.env
go run ./cmd/onchaininspect -rpc https://api.devnet.solana.com -program 6NY7DBX4GQTq25E8pcrxUw4wDtGAC3EX1QVwD8jUDUMy
cd demo-wallet && go run . serve
cd demo-dapp && go run .
```

The inspector defaults to the local validator, so it needs `-rpc`. Then follow
section 7 of `guide_demo_setup.md` with Phantom as usual. Accounts can be looked at in
the Solana Explorer by adding `?cluster=devnet`, for example
`https://explorer.solana.com/address/6NY7DBX4GQTq25E8pcrxUw4wDtGAC3EX1QVwD8jUDUMy?cluster=devnet`.

## 3. What to watch

- How long issuing takes now that it waits for devnet, and whether 60s suffices.
- Whether the public RPC throttles or refuses `getProgramAccounts` (used by the
  inspector). A free devnet RPC key from a provider is the fix.
- That a slow or failing RPC makes verification answer *unavailable*, never
  *verified*.
- That revoking a credential or suspending the issuer shows in the Explorer and is
  honored on the next verification.

## Notes

- Devnet is occasionally reset; an empty registry later is not a bug.
- Rent for credential records is never reclaimed (see the Phase 5 plan, section 8).
- Never commit keypair files.
