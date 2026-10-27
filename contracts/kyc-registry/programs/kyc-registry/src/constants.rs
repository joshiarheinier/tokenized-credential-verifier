use anchor_lang::prelude::*;

/// PDA seeds. Each is followed by a fixed-size 32-byte identifier where applicable,
/// so seed concatenation is never ambiguous.
#[constant]
pub const REGISTRY_CONFIG_SEED: &[u8] = b"registry_config";
#[constant]
pub const ISSUER_SEED: &[u8] = b"issuer";
#[constant]
pub const CREDENTIAL_SEED: &[u8] = b"credential";

/// Account layout version written into `RegistryConfig.version`.
#[constant]
pub const REGISTRY_VERSION: u8 = 1;

/// `CredentialStatus.status` values. Expiry is derived from `expires_at`, not stored here.
#[constant]
pub const CREDENTIAL_ACTIVE: u8 = 0;
#[constant]
pub const CREDENTIAL_REVOKED: u8 = 1;
