# Glossary

Shared vocabulary for this project. Where this file and `td_init_project.md` disagree, the TD wins. For account layouts and instruction rules, see `solana_registry.md`.

## Who is who

| Term | What it is | In this project |
|---|---|---|
| **Registry** | Not a person. The on-chain list of trusted issuers and credential statuses. | The Anchor program in `contracts/credential-registry` |
| **Registry authority** | The administrator of the registry. Decides which issuers are trusted. | One Solana key, `RegistryConfig.authority`. In practice whoever runs the trust framework (a consortium operator or platform owner). |
| **Issuer** | An organization that performs KYC and vouches for users, such as a bank or KYC provider. | An `IssuerRecord`, identified by `issuer_id`, either active or suspended |
| **Issuer signing key** | The Ed25519 key an issuer signs credentials with. Used only by verifiers, off-chain. | `IssuerRecord.issuer_signing_key`. The program never uses it. |
| **Issuer authority** | The Solana key an issuer uses to write to the registry (register and revoke its own credentials). | `IssuerRecord.authority`. Kept separate from the signing key (TD §4.2). |
| **Upgrade authority** | The key that deployed the program and can upgrade it. Solana tracks this, not our code. | The only key that may call `initialize_registry`. |
| **User (subject)** | The person who holds a credential. | Never on-chain |
| **Verifier** | An application that checks a credential and reads the registry. | The Go verification service and the demo dApp |

The registry authority decides who counts as a trusted issuer. An issuer decides which credentials it has issued. In the MVP one party may play both roles (TD §5.5), but the program keeps them as separate keys with separate permissions.

## Things that get created

| Term | What it is |
|---|---|
| **Credential** | The signed statement about a user (for example "KYC verified"). Lives off-chain, in the user's wallet. Signed by the issuer. |
| **`credential_ref`** | A random, opaque 32-byte ID for one credential. It is the only credential identifier on-chain, and it must never be derived from personal data. |
| **Credential status** | The on-chain record for one `credential_ref`: issuer, active/revoked, and expiry. Contains no personal data. |
| **Revoked** | Permanently deactivated by the issuer authority or registry authority. Irreversible. Re-verification means issuing a new credential. |
| **Suspended** | An issuer switched to inactive by the registry authority. It cannot register new credentials, but its existing ones are not revoked automatically. Reversible. |
| **Paused** | The whole registry blocks new issuers and new credentials. Suspension and revocation keep working. |

## The three setup instructions

They run in dependency order, and each needs the one before it.

| Instruction | Called by | Creates | Meaning |
|---|---|---|---|
| `initialize_registry` | Upgrade authority, once | `RegistryConfig` | Opens the registry and names who runs it. Done once after deploying. |
| `register_issuer` | Registry authority | `IssuerRecord` | Adds an organization to the trusted list, with the key allowed to write on its behalf. Repeatable. |
| `register_credential` | Issuer authority | `CredentialStatus` | Logs one issued credential (random ref plus expiry) so it can be checked or revoked later. Once per credential. |

Analogy: this is like a certificate authority system. `initialize_registry` sets up the trust framework, `register_issuer` adds an authority to the trusted list, and `register_credential` is that authority logging one certificate it issued.

## Other terms

| Term | Meaning |
|---|---|
| **PDA (Program Derived Address)** | A deterministic account address derived from fixed seeds plus the program ID, so anyone can compute where a record lives. |
| **Fail closed** | If trust state can't be established (missing account, RPC outage), the credential is treated as not verified, never as valid. |
| **Trust layer** | Solana's role here. It records who is trusted and what is revoked. It does not verify identities and does not replace signature checks. |
