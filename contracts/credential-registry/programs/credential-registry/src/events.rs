use anchor_lang::prelude::*;

/// Events never carry personal information or credential contents.
#[event]
pub struct RegistryInitialized {
    pub authority: Pubkey,
}

#[event]
pub struct RegistryAuthorityUpdated {
    pub old_authority: Pubkey,
    pub new_authority: Pubkey,
}

#[event]
pub struct RegistryPausedChanged {
    pub paused: bool,
}

#[event]
pub struct IssuerRegistered {
    pub issuer_id: [u8; 32],
    pub authority: Pubkey,
    pub issuer_signing_key: Pubkey,
}

#[event]
pub struct IssuerStatusChanged {
    pub issuer_id: [u8; 32],
    pub active: bool,
}

#[event]
pub struct CredentialRegistered {
    pub credential_ref: [u8; 32],
    pub issuer_id: [u8; 32],
    pub expires_at: i64,
}

#[event]
pub struct CredentialRevoked {
    pub credential_ref: [u8; 32],
    pub issuer_id: [u8; 32],
    pub revoked_by: Pubkey,
}
