# Trying the end-to-end flow by hand

Every component runs on its own, in its own terminal, and talks to the others
over the network. Nothing here depends on a particular shell, except that the
Solana validator runs in WSL (see the README for why).

```text
demo-wallet ──presents──▶ demo-dapp ──verify──▶ backend (cmd/api) ──reads/writes──▶ Solana validator
     └──────────requests a credential──────────────▲                                       ▲
                                         curl ──▶ onchaininspect ──────reads─────────────┘
```

| Component | Where it runs | Default address |
|---|---|---|
| Solana validator + registry program | WSL | `http://127.0.0.1:8899` |
| Backend (`cmd/api`) | Windows | `http://127.0.0.1:8080` |
| On-chain inspector (`cmd/onchaininspect`) | Windows | `http://127.0.0.1:9100` |
| Demo dApp (`demo-dapp/`) | Windows | `http://127.0.0.1:9090` |
| Demo wallet (`demo-wallet/`) | Windows | interactive prompt |

Prerequisite: the program is built (`make anchor-build`, see the README). All
commands run from the repository root unless noted.

## 1. Start the chain (two WSL terminals)

```bash
bash scripts/localnet.sh run     # leave running; every run starts from an empty chain
bash scripts/localnet.sh fund    # once the validator is up: creates the issuer's key, airdrops SOL
```

## 2. Configure and start the backend

Generate an issuer signing seed with `go run ./cmd/issuerkeygen`, and save this
as `.local/demo.env` (git-ignored), pasting your seed:

```text
APP_ENV=development
HTTP_ADDR=127.0.0.1:8080
ISSUER_ID=did:example:demo-issuer
ISSUER_SIGNING_KEY_SEED=<the seed>
SOLANA_RPC_URL=http://127.0.0.1:8899
SOLANA_PROGRAM_ID=6NY7DBX4GQTq25E8pcrxUw4wDtGAC3EX1QVwD8jUDUMy
SOLANA_REGISTRY_AUTHORITY_KEYPAIR=.local/test-authority-keypair.json
SOLANA_ISSUER_AUTHORITY_KEYPAIR=.local/demo-issuer-authority-keypair.json
SOLANA_BOOTSTRAP=true
APPROVAL_SIMULATION_ENABLED=true
```

(`bash scripts/localnet.sh program-id` prints the program id if yours differs.)

```bash
go run ./cmd/api -env-file .local/demo.env
```

On start, `SOLANA_BOOTSTRAP` creates the registry and registers this issuer. It
is a development convenience and is refused in production. Real environment
variables override the file.

## 3. Start the on-chain inspector, the dApp and the wallet

```bash
go run ./cmd/onchaininspect -program 6NY7DBX4GQTq25E8pcrxUw4wDtGAC3EX1QVwD8jUDUMy
cd demo-dapp && go run .          # prompt: status, log, help, quit
cd demo-wallet && go run .        # prompt: request, list, present, help, exit
```

## 4. Use it

In the wallet prompt:

| Command | What it does |
|---|---|
| `request` | Gets a KYC credential from the issuer (the backend signs it and registers it on chain) and stores it |
| `request -kyc-verified=false` | Same, for a person who failed KYC |
| `request -country SG -over-18=false` | Other claim values |
| `list` | Shows stored credentials |
| `present` | Presents the newest credential to the dApp (`present -id <id>` for another) |

`present` prints `granted` with the claims the app learned, or `denied` with a
coarse reason. The dApp prompt shows each decision as it happens (`log` lists
them; `status` checks that the verifier is reachable).

Expected: a normal `request` then `present` is **granted**; after
`request -kyc-verified=false`, `present` is **denied** (`policy_not_satisfied`).

## 5. Look at the on-chain data

```bash
curl http://127.0.0.1:9100/registry       # authority, paused, version
curl http://127.0.0.1:9100/issuers        # issuer id, signing key, authority, active
curl http://127.0.0.1:9100/credentials    # credential ref, issuer id, state, expiry
```

(In Windows PowerShell 5.1 write `curl.exe`; plain `curl` is a different command there.)

Only hashes and status are on chain. Each credential's `ref` and each issuer's
`issuer_id` are SHA-256-derived ids, and the claims never leave the credential.
Run `request` and watch `/credentials` gain an entry. `account` is the address
you can also look up with `solana account <address> --url http://127.0.0.1:8899`
in WSL.

## Starting over

Restarting the validator (`localnet.sh run`) wipes the chain. After that,
restart the backend (it re-registers the issuer) and clear the wallet's
credentials: they were registered on the old chain, so the verifier would
reject them as not registered. The wallet stores them in `./.wallet` of the
directory you started it from (override with `-dir` or `WALLET_DIR`).

## Not wired into the demo yet

Revoking a credential, and showing the expired and untrusted-issuer cases, are
the remaining Phase 4 steps. The verification code already rejects all of them
(covered by unit and integration tests); the demo has no way to trigger them yet.
