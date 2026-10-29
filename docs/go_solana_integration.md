# Go ↔ Solana Integration

How the Go backend uses the registry program. Program details are in `solana_registry.md`; terms are in `glossary.md`. Where this file and `td_init_project.md` disagree, the TD wins.

## Where the code lives

| Package | Role |
|---|---|
| `internal/infrastructure/client/blockchain` | Client for the registry program. It imports nothing else from the project, and is the only package that imports the Solana SDK. Reads accounts, builds and confirms transactions, maps ids. Built with `blockchain.NewClient(blockchain.Config{...})`. |
| `internal/application/verification` | Applies the on-chain checks, depending only on a small `BlockchainClient` interface (the read side of the client). |
| `internal/application/credential` | Issues credentials; calls an optional `BlockchainClient` (the register side of the client) before returning one. |
| `internal/domain/...` | Credential model, signing and verification, and policy. No blockchain dependency: signing and verification never touch the chain. |
| `cmd/api` | Composition root: builds the client from configuration, injects it into the services, and runs the optional dev-only registry bootstrap. |

SDK: `github.com/gagliardetto/solana-go` v1.25.0. The TD names `github.com/solana-foundation/solana-go`, but the repository moved orgs without changing its module path, so Go only accepts the old path. It is the same code.

## Identifier mapping

The credential layer and the program use different identifiers. `internal/infrastructure/client/blockchain/helper.go` maps between them with domain-separated SHA-256:

| Credential claim | On-chain id |
|---|---|
| `iss` (issuer string) | `issuer_id = sha256("credential-registry/issuer/v1\0" + iss)` |
| `jti` (random 128-bit id) | `credential_ref = sha256("credential-registry/credential/v1\0" + jti)` |

`jti` is random, so `credential_ref` reveals nothing about the subject and cannot be linked to a credential by anyone who does not hold it.

## Reading

`GetRegistry`, `GetIssuer` and `GetCredentialStatus` read at the configured commitment (`confirmed` by default) and treat the response as untrusted: the account must be owned by the program, have the right discriminator and exact size, valid field values, and the id it claims. A missing account is `ErrNotFound`; anything else that prevents an answer is `ErrUnavailable` or `ErrInvalidAccount`. These are never conflated.

Transient RPC errors are retried with exponential backoff (default 3 attempts, 200 ms base, 10 s per call).

## Writing

Every write is idempotent and confirmed before it reports success:

1. Read current state. If it already matches the request, return a no-op (`Changed: false`). If a different record exists, return `ErrConflict` without sending anything.
2. Sign and send (transient send failures are retried with the same signed transaction; resending it cannot land twice).
3. Poll signature status until it reaches the configured commitment. Success is reported only then.
4. If the transaction is rejected, re-read state: a concurrent request that created the identical record counts as success.

Outcomes of a write that did not succeed:

| Error | Meaning | Safe to retry? |
|---|---|---|
| `ErrTxRejected` | Preflight or on-chain failure. No effect. | Only after fixing the cause |
| `ErrTxExpired` | Blockhash expired before confirmation. Cannot land. | Yes |
| `ErrTxUncertain` | Timed out waiting. May still land. | Re-check state first; retrying is idempotent |

Signing roles: the **registry authority** key signs initialize, register-issuer and set-issuer-status; the **issuer authority** key signs credential registration and revocation. A client without the needed key returns `ErrSignerMissing`. The program, not the client, enforces who may do what (tested with a deliberately unauthorized signer).

## Verification

With the registry enabled, the verification service first applies the local checks (signature, expiry, the type's policy including its issuer allow-list), then checks the chain:

1. The issuer exists on chain and is active.
2. The on-chain `issuer_signing_key` equals the key the credential was verified with.
3. The credential reference exists, belongs to that issuer, is not revoked and is not past its on-chain expiry.

| Chain says | Reason returned | HTTP |
|---|---|---|
| Issuer absent, suspended or key differs | `untrusted_issuer` | 200 |
| Credential absent or for another issuer | `not_registered` | 200 |
| Credential revoked | `revoked` | 200 |
| Credential past on-chain expiry | `expired` | 200 |
| Chain unreachable, bad account, unknown state | `verification_unavailable` | **503** |

The last row fails closed: the credential is never accepted, and callers can tell "we could not check" from "this credential is bad".

Local-only failures (bad signature, expired, malformed) are decided without touching the chain.

## Issuance

When the registry is enabled, `IssueFromApproval` validates and consumes the approval, registers the credential on chain, and only then returns it. If registration fails no credential is returned.

Consequence: a registration failure leaves that simulated approval consumed, and the caller must obtain a new one. The alternative (registering first) would let invalid requests spend transaction fees.

## Configuration notes

- `SOLANA_RPC_URL` is required in production, so verification cannot silently skip the registry.
- `SOLANA_BOOTSTRAP` (dev/test) initializes the registry and registers this process's issuer. The registry authority key must also be the program's **upgrade authority**, because `initialize_registry` requires it. Bootstrap needs a fixed `ISSUER_SIGNING_KEY_SEED`; the registry refuses to re-register an issuer under a different key.
- Keypair files are read from paths; their contents are never logged or included in errors.

## Known limitations

- Verification still trusts only this process's own issuer key locally, then requires the chain to agree. Resolving other issuers' keys from the registry is not implemented.
- No revocation or issuer-administration HTTP endpoints yet (TD: later phases). The client methods exist.
- `set_paused` and `update_registry_authority` have no Go client methods yet.
- `/readyz` does not check the RPC endpoint yet.
- A failed registration burns the simulated approval (see Issuance).
- Reads are not cached; every verification makes two RPC calls.

## Tests

- `go test ./...`: unit tests with a fake RPC. Cover the wire format (discriminators pinned to the IDL), account decoding, retries, confirmation, idempotency, conflicts, and fail-closed behaviour. No validator needed.
- `bash scripts/integration-test.sh`: starts `solana-test-validator` in WSL with the program deployed, then runs the `integration`-tagged tests against it, one package at a time:
  - `internal/infrastructure/client/blockchain`: the client alone (full registry lifecycle, concurrent identical requests, program-side authorization).
  - `internal/application/verification`: end-to-end issue and verify against real chain state, and an unreachable chain.
  - `cmd/api`: the running server with bootstrap, over HTTP.
  - Shared helpers live in `internal/testutil`; the client's own integration test keeps its own copies.
