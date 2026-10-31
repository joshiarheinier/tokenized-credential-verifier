# Tokenized Credential Verifier

## Project Summary

A privacy-preserving, reusable credential verification system: a trusted issuer
signs a credential, the holder keeps it, and applications verify it — checking
issuer trust and credential status against a Solana registry — without the
issuer's underlying records ever being shared. It is meant to serve as shared
infrastructure for different credential products. The first credential type is
KYC status (simulated); other uses such as ticketing or memberships are future
work.

## Rationale

### Why blockchain

Credential systems without a blockchain keep the list of trusted issuers and
revoked credentials in a database that someone owns. This project puts only that
trust data (no personal data) in an on-chain registry instead:

- **No single gatekeeper.** Every application reads the same public registry
  directly; none has to integrate with, or trust, one vendor's API.
- **Tamper-evident.** Issuer trust and revocations are public and auditable; a
  silent edit is not possible.
- **No call home.** The credential is verified with a signature check plus a
  registry lookup, so the issuer never learns where or when it is used.

**Example: KYC.** Alice wants to open an account at a crypto exchange that requires
KYC. She has already been verified by a KYC provider. The parties involved:

- **Alice (holder):** the user who owns the credential.
- **The KYC provider (issuer):** a company, such as a bank or an identity
  verification service, that checked Alice's documents and vouches for her.
- **The exchange (verifier):** the application that needs proof she passed KYC.
- **The Solana registry (this project only):** a public on-chain list of trusted
  issuers and revoked credentials. It holds no personal data.

*Typical centralized KYC:* Alice tells the exchange she is verified. The exchange
calls the KYC provider's API ("is Alice verified?") and trusts the answer. The
provider sees every such request, and if its API is down or it stops offering the
service, the exchange cannot verify anyone.

*This project:* the KYC provider signs a credential once and Alice keeps it in her
wallet. She shows it to the exchange, which checks the provider's signature and
looks the provider up in the Solana registry to confirm it is still trusted and the
credential is not revoked. The provider is never contacted, and the exchange sees
only the claims it asked for (for example "over 18").

|                                     | Typical centralized KYC | This project |
|-------------------------------------|---|---|
| Who the verifier asks               | The KYC provider's API: "is user 42 verified?" | The user's wallet for the credential, and the Solana registry for issuer and status |
| What the issuer learns              | Every check: which app, when, how often | Nothing; it is not contacted |
| If the issuer is down or shuts down | Verification fails | Verification still works |
| Who can change the trust list       | The provider, privately | The registry authority, on a public ledger |
| What the verifier receives          | Often a full profile or a yes/no from a private database | Only the claims the policy needs, signed and checkable by anyone |

**Another example: loyalty membership.** Bob is a Gold member of an airline's
loyalty programme and wants the lounge access and discounts that come with it at
partner shops. (Membership is not a built-in credential type yet; this shows how
the same design carries over.) The parties involved:

- **Bob (holder):** the member.
- **The airline (issuer):** runs the programme and decides who is Gold.
- **The partner shop (verifier):** wants to know Bob is Gold before applying the
  discount.
- **The Solana registry:** lists the airline as a trusted issuer and records
  whether Bob's membership is still valid.

*Typical centralized loyalty:* each partner shop integrates with the airline's
membership API and sends it Bob's member number at every purchase. The airline
learns where and when Bob shops, every partner needs its own integration and
contract, and a lapsed membership only stops working once each partner's copy of
the data catches up.

*This project:* the airline issues Bob a membership credential carrying one claim,
such as "tier: Gold". At the till, Bob's wallet shows it to the shop, which checks
the airline's signature and the registry. No member number or name is shared, any
shop can verify without a contract with the airline, and when the airline revokes
the membership the registry shows it immediately.

## Requirements

| Tool | Version | Needed for |
|---|---|---|
| Go | **1.26+** (see `go.mod`) | Backend (all phases) |
| Git | any recent | Source control |
| GNU Make | optional | Shortcuts below; every target is a plain `go` command |
| Rust, Solana CLI, Anchor | see [Solana toolchain and local validator](#solana-toolchain-and-local-validator) | On-chain program and integration tests only |

The Go backend has no dependency on the Solana toolchain; you can build and
test it without installing Rust, Solana or Anchor.

## Quick start

```sh
git clone <repo-url> tokenized-credential-verifier
cd tokenized-credential-verifier

cp .env.example .env    # optional; every variable has a default
go test ./...
go run ./cmd/api
```

In another terminal:

```sh
curl -i http://localhost:8080/healthz   # 200 {"status":"ok"}
curl -i http://localhost:8080/readyz    # 200 {"status":"ready"}
```

Stop the server with `Ctrl+C`; it shuts down gracefully.

### Loading `.env`

The process reads **environment variables only**; it does not parse `.env`
itself. `make run` loads `.env` automatically. Without Make:

```sh
# bash / Git Bash / WSL
set -a; . ./.env; set +a; go run ./cmd/api
```

```powershell
# PowerShell
Get-Content .env | Where-Object { $_ -match '^\s*[^#].*=' } | ForEach-Object {
  $k, $v = $_ -split '=', 2; Set-Item "env:$($k.Trim())" $v.Trim() }
go run ./cmd/api
```

## Make targets

| Target | Equivalent | Purpose |
|---|---|---|
| `make run` | `go run ./cmd/api` | Run the API (loads `.env`) |
| `make build` | `go build -o bin/ ./cmd/api` | Build the binary |
| `make test` | `go test ./...` | Run all tests |
| `make test-race` | `go test -race ./...` | Tests with race detector (needs cgo/gcc) |
| `make cover` | `go test -coverprofile=...` | Coverage report |
| `make lint` | `gofmt -l .` + `go vet ./...` | Format check and vet |
| `make fmt` | `gofmt -w .` | Format code |
| `make anchor-build` / `anchor-test` | via WSL | Build / test the Anchor program |
| `make integration-test` | `scripts/integration-test.sh` | Go integration tests against a local validator |

On Windows, Make is available via WSL, MSYS2 (`pacman -S make`), or
`winget install GnuWin32.Make`. It is optional.

## Configuration

All configuration comes from environment variables (see `.env.example`).
Invalid values make the process exit at startup with a message naming each bad
variable.

| Variable | Default | Description |
|---|---|---|
| `APP_ENV` | `development` | `development`, `test` or `production` |
| `HTTP_ADDR` | `:8080` | Listen address |
| `HTTP_READ_TIMEOUT` | `10s` | Max time to read a request (incl. headers) |
| `HTTP_WRITE_TIMEOUT` | `15s` | Max time to write a response |
| `HTTP_IDLE_TIMEOUT` | `60s` | Keep-alive idle timeout |
| `HTTP_SHUTDOWN_TIMEOUT` | `15s` | Grace period for in-flight requests on shutdown |
| `LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |
| `LOG_FORMAT` | `json` | `json` (machine) or `text` (human) |
| `ISSUER_ID` | `did:example:issuer-dev` | Issuer identifier placed in the `iss` claim |
| `ISSUER_SIGNING_KEY_SEED` | *(empty)* | Base64url 32-byte Ed25519 seed (**secret**). Empty = ephemeral key (non-production only). Required in production. |
| `CREDENTIAL_TTL` | `720h` | Validity period of issued credentials |
| `APPROVAL_SIMULATION_ENABLED` | `true` (`false` in production) | Enables the simulate/issue endpoints. The process refuses to start with this on in production. |
| `SOLANA_RPC_URL` | *(empty)* | RPC endpoint of the registry cluster. Empty = off-chain checks only (non-production). **Required in production.** |
| `SOLANA_PROGRAM_ID` | *(empty)* | Deployed registry program id. Required with `SOLANA_RPC_URL`. |
| `SOLANA_COMMITMENT` | `confirmed` | `confirmed` or `finalized` (used for reads and confirming writes) |
| `SOLANA_REGISTRY_AUTHORITY_KEYPAIR` | *(empty)* | Path to the registry authority keypair (**secret**). Only for administration/bootstrap. |
| `SOLANA_ISSUER_AUTHORITY_KEYPAIR` | *(empty)* | Path to the issuer authority keypair (**secret**). Needed to register issued credentials on chain. |
| `SOLANA_REQUEST_TIMEOUT` | `10s` | Timeout of a single RPC call |
| `SOLANA_TX_TIMEOUT` | `30s` | How long to wait for a submitted transaction to confirm |
| `SOLANA_BOOTSTRAP` | `false` | Dev/test only: create the registry and register this issuer at startup (idempotent). Needs both keypairs and a fixed `ISSUER_SIGNING_KEY_SEED`. Refused in production. |

Generate an issuer signing seed with `go run ./cmd/issuerkeygen` (the seed is
printed to stdout, the public key and key id to stderr).

## Solana toolchain and local validator

Only needed for the on-chain program and the integration tests. The Go backend
does not depend on any of it, and `go test ./...` needs no blockchain.

1. **Windows only: set up WSL2.** Anchor and the Solana CLI are supported on
   Linux/macOS, so on Windows install **WSL2** (Ubuntu) and run the toolchain
   steps below inside it. The Go backend can stay on native Windows.
2. **Install the toolchain.** Follow <https://solana.com/docs/intro/installation>.
   It installs Rust, the Solana CLI and Anchor (via the Anchor Version Manager,
   `avm`).
3. **Verify the install** (inside WSL on Windows):

   ```sh
   rustc --version
   solana --version
   anchor --version
   ```

   The program is tested with Rust 1.99.1, Solana CLI 3.1.10 and Anchor 1.1.2.
4. **Build the program** from the repository root:

   ```sh
   make anchor-build      # runs in WSL on Windows
   ```

5. **Run the integration tests.** The tests (build tag `integration`) run the Go
   adapter and the application against a real `solana-test-validator` with the
   registry program deployed. The script starts the validator in WSL, runs the
   tests and stops the validator:

   ```sh
   bash scripts/integration-test.sh      # from Git Bash on Windows
   ```

   Without the environment this script sets up, the integration tests skip.

To run a validator by hand for the demo, see
[`docs/guide_demo_setup.md`](docs/guide_demo_setup.md). Keep keypairs outside
the repository.

## Project layout

The code follows a layered, domain-driven structure.

```text
cmd/
  api/                           Composition root: loads config, builds and wires everything, runs the HTTP server
  issuerkeygen/                  Generates an issuer signing seed
  onchaininspect/                Read-only HTTP view (curl) of what the registry holds on Solana
internal/
  domain/                        Business rules and concepts; no dependency on the layers below
    credential/                  Credential model, schemas, Ed25519 signer and verifier
    credential/kyc/              The KYCStatus credential type (first registered type)
    issuer/                      Issuer identity and signing-key loading
    challenge/                   Challenge-response protocol model: challenges, the text a holder signs, holder binding
    registry/                    The trust registry's model: issuer records, credential status, ids, shared errors
    verification/                Relying-application policy: accepted types and issuers, required and disclosed claims
  application/                   Use cases; orchestrate the domain
    approval/                    Issuer approval decisions: recorded once, consumed once at issuance (in memory)
    credential/                  Issuance: check the approval, register on chain, sign; revoke; suspend the issuer
    challenge/                   Challenge-response protocol: create challenges, accept holder-bound responses, serve results
    verification/                Verification: signature, policy and on-chain checks, with coarse rejection reasons
  gateways/
    http/                        HTTP gateway: routes, middleware (request logging, panic recovery), handlers
  infrastructure/                Technical adapters
    challengestore/              In-memory store for challenges
    client/blockchain/           Solana implementation of the registry (the only package importing the Solana SDK)
    logging/                     slog logger construction
  config/                        Environment-variable configuration with validation
  testutil/                      Helpers for integration tests (build tag `integration`)
demo-wallet/                     Demo credential wallet: a CLI, and a browser wallet using Phantom (`serve`); separate module, talks to the backend over HTTP
demo-dapp/                       Demo relying application: a members-only page that asks the wallet to prove one claim (and a CLI prompt); separate module, asks the verifier API
contracts/credential-registry/   Anchor program: the on-chain trust registry
scripts/                         Local validator and integration-test runners (WSL)
docs/                            Design and reference documents
```

Dependencies point inward: `gateways` call `application`, which uses `domain`;
`domain` imports nothing else from the project, and `infrastructure` implements
what the domain describes. The application services import no infrastructure:
they define small interfaces (`BlockchainClient`) in domain terms, and the
Solana client satisfies them. `cmd/api` is the only place that knows every
layer, and it is where dependencies are constructed and injected.

The HTTP gateway package is named `http`, like its directory. Code that also
imports `net/http` aliases it (`httpgateway` in `cmd/api`).

Packages from the target layout in the design doc (`repository`, `migrations/`,
`api/openapi.yaml`) are added in the phase that gives them real
responsibilities.

## Security notes

- Never commit private keys, seed phrases, Solana keypairs, or `.env`. The
  `.gitignore` excludes `.env*` (except `.env.example`), `*.pem`, `*.key`,
  `*-keypair.json`, `id.json`, `keys/` and `secrets/`.
- Request logs record only method, path, status and latency — never headers,
  query strings or bodies, which may carry credentials or personal data.

## Documentation

More detail lives in [`docs/`](docs/):

| Document | Read it for |
|---|---|
| [`api_contract.md`](docs/api_contract.md) | HTTP endpoints, reason codes and the credential format |
| [`credential_types.md`](docs/credential_types.md) | How credential types and their claim schemas work, and how to add one |
| [`challenge_response_protocol.md`](docs/challenge_response_protocol.md) | How a holder proves a credential to an application |
| [`solana_registry.md`](docs/solana_registry.md) | The on-chain program: accounts and instructions |
| [`go_solana_integration.md`](docs/go_solana_integration.md) | How the Go backend talks to the registry program |
| [`glossary.md`](docs/glossary.md) | Shared vocabulary: issuer, holder, registry authority and more |
| [`guide_demo_setup.md`](docs/guide_demo_setup.md) | Running the whole flow by hand: wallet, backend, dApp and on-chain data |
| [`guide_devnet_setup.md`](docs/guide_devnet_setup.md) | Deploying and running against Solana devnet |
| [`td_init_project.md`](docs/td_init_project.md) | The full technical design (written when this was a KYC-only project, so its framing predates the rename) |
