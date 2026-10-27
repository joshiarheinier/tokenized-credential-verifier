use anchor_lang::prelude::*;

#[error_code]
pub enum ErrorCode {
    #[msg("Signer is not the program upgrade authority")]
    NotUpgradeAuthority,
    #[msg("Signer is not authorized for this action")]
    Unauthorized,
    #[msg("Registry is paused")]
    RegistryPaused,
    #[msg("Issuer is not active")]
    IssuerInactive,
    #[msg("Issuer already has the requested status")]
    StatusUnchanged,
    #[msg("Credential expiry must be in the future")]
    ExpiryInPast,
    #[msg("Credential is already revoked")]
    CredentialAlreadyRevoked,
    #[msg("Credential does not belong to this issuer")]
    CredentialIssuerMismatch,
    #[msg("Authority must not be the default (all-zero) pubkey")]
    InvalidAuthority,
}
