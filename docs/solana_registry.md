# Solana Registry Program

Anchor program in `contracts/credential-registry`. It stores only issuer trust and credential status; no personal data, credential contents or user identifiers go on-chain. Signature verification stays off-chain (see `td_init_project.md` §5).

Program ID (localnet): `6NY7DBX4GQTq25E8pcrxUw4wDtGAC3EX1QVwD8jUDUMy`

## Accounts

All accounts carry Anchor's 8-byte discriminator before the fields below.

### RegistryConfig — 8 + 35 bytes

PDA seeds: `["registry_config"]`

| Field | Type | Notes |
|---|---|---|
| authority | Pubkey | Registry administrator |
| paused | bool | Blocks new issuers and new credentials only |
| version | u8 | Layout version (currently 1) |
| bump | u8 | PDA bump |

### IssuerRecord — 8 + 106 bytes

PDA seeds: `["issuer", issuer_id]` (`issuer_id` is 32 bytes)

| Field | Type | Notes |
|---|---|---|
| issuer_id | [u8; 32] | Opaque issuer identifier |
| issuer_signing_key | Pubkey | Ed25519 key that signs credentials; checked off-chain only |
| authority | Pubkey | Solana key that registers/revokes this issuer's credentials; kept separate from the signing key (TD §4.2) |
| active | bool | Suspended issuers cannot register new credentials |
| created_at | i64 | Unix seconds |
| bump | u8 | PDA bump |

### CredentialStatus — 8 + 74 bytes

PDA seeds: `["credential", credential_ref]` (`credential_ref` is 32 random bytes)

| Field | Type | Notes |
|---|---|---|
| credential_ref | [u8; 32] | Random opaque id; never derived from personal data |
| issuer_id | [u8; 32] | Links to the `IssuerRecord` |
| status | u8 | `0` active, `1` revoked |
| expires_at | i64 | Unix seconds. Expiry is evaluated by the verifier, not stored as a status |
| bump | u8 | PDA bump |

`credential_ref` is unique across all issuers (one PDA per ref). Refs must be random so one issuer cannot squat another's.

## Instructions

| Instruction | Signer | Rules |
|---|---|---|
| `initialize_registry` | Program upgrade authority | One-time. Prevents front-running initialization after deploy |
| `update_registry_authority(new)` | Registry authority | `new` must not be the zero pubkey |
| `set_paused(paused)` | Registry authority | Works in either direction |
| `register_issuer(id, signing_key, authority)` | Registry authority | Fails while paused, on duplicate id, or on zero issuer authority |
| `set_issuer_status(active)` | Registry authority | Fails if the status is unchanged. Works while paused |
| `register_credential(ref, expires_at)` | Issuer authority | Fails while paused, if the issuer is inactive, if `expires_at` is not in the future, or on duplicate ref. The registry authority cannot issue on an issuer's behalf |
| `revoke_credential` | Issuer authority or registry authority | Irreversible. Fails if already revoked or if the credential belongs to a different issuer. Works while paused or suspended |

Pausing and suspension never block revocation or further suspension, so the safe direction is always available.

## Errors

`NotUpgradeAuthority`, `Unauthorized`, `RegistryPaused`, `IssuerInactive`, `StatusUnchanged`, `ExpiryInPast`, `CredentialAlreadyRevoked`, `CredentialIssuerMismatch`, `InvalidAuthority`.

## Events

`RegistryInitialized`, `RegistryAuthorityUpdated`, `RegistryPausedChanged`, `IssuerRegistered`, `IssuerStatusChanged`, `CredentialRegistered`, `CredentialRevoked`. None carry personal data.

## Verifier reading rules

To trust a credential, a verifier reads `IssuerRecord` and `CredentialStatus` and requires all of:

- the issuer account exists, and `active` is true;
- `issuer_signing_key` matches the key that signed the credential;
- the credential account exists, `status == 0`, and `expires_at` is in the future;
- the credential's `issuer_id` matches the issuer's.

A missing account, an unreadable account or an RPC failure means "not verified". It must never be treated as valid.

## Known limitations

- Authority transfer is single-step. Passing a wrong (non-zero) pubkey locks the registry out. A two-step propose/accept handover would remove that risk.
- Registry and issuer authorities are single keys, with no multisig or governance (deferred in TD §11).
- The program has not had a security review (TD Phase 6).

## Running the tests

```
make anchor-test
```

This runs through WSL against a local `solana-test-validator`; see `contracts/credential-registry/scripts/anchor-wsl.sh`.
