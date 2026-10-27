use anchor_lang::prelude::*;

/// Singleton registry configuration. PDA seeds: `["registry_config"]`.
#[account]
#[derive(InitSpace)]
pub struct RegistryConfig {
    pub authority: Pubkey,
    pub paused: bool,
    pub version: u8,
    pub bump: u8,
}

/// A trusted issuer. PDA seeds: `["issuer", issuer_id]`.
#[account]
#[derive(InitSpace)]
pub struct IssuerRecord {
    pub issuer_id: [u8; 32],
    /// Ed25519 key the issuer signs credentials with (verified off-chain only).
    pub issuer_signing_key: Pubkey,
    /// Solana key allowed to register/revoke this issuer's credentials.
    /// Deliberately separate from `issuer_signing_key` (TD section 4.2).
    pub authority: Pubkey,
    pub active: bool,
    pub created_at: i64,
    pub bump: u8,
}

/// On-chain status of one credential. PDA seeds: `["credential", credential_ref]`.
/// `credential_ref` is a random opaque id, never derived from personal data.
#[account]
#[derive(InitSpace)]
pub struct CredentialStatus {
    pub credential_ref: [u8; 32],
    pub issuer_id: [u8; 32],
    /// `CREDENTIAL_ACTIVE` or `CREDENTIAL_REVOKED`.
    pub status: u8,
    pub expires_at: i64,
    pub bump: u8,
}
