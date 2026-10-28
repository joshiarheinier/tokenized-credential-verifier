use anchor_lang::prelude::*;

use crate::{
    constants::*,
    error::ErrorCode,
    events::CredentialRevoked,
    state::{CredentialStatus, IssuerRecord, RegistryConfig},
};

#[derive(Accounts)]
pub struct RevokeCredential<'info> {
    /// Either the credential's issuer authority or the registry authority.
    pub authority: Signer<'info>,
    #[account(seeds = [REGISTRY_CONFIG_SEED], bump = registry_config.bump)]
    pub registry_config: Account<'info, RegistryConfig>,
    #[account(
        seeds = [ISSUER_SEED, issuer_record.issuer_id.as_ref()],
        bump = issuer_record.bump,
    )]
    pub issuer_record: Account<'info, IssuerRecord>,
    #[account(
        mut,
        seeds = [CREDENTIAL_SEED, credential_status.credential_ref.as_ref()],
        bump = credential_status.bump,
        constraint = credential_status.issuer_id == issuer_record.issuer_id
            @ ErrorCode::CredentialIssuerMismatch,
    )]
    pub credential_status: Account<'info, CredentialStatus>,
}

/// Works while paused or while the issuer is suspended: revocation is always safe.
pub fn handle_revoke_credential(ctx: Context<RevokeCredential>) -> Result<()> {
    let signer = ctx.accounts.authority.key();
    require!(
        signer == ctx.accounts.issuer_record.authority
            || signer == ctx.accounts.registry_config.authority,
        ErrorCode::Unauthorized
    );

    let status = &mut ctx.accounts.credential_status;
    require!(
        status.status == CREDENTIAL_ACTIVE,
        ErrorCode::CredentialAlreadyRevoked
    );
    status.status = CREDENTIAL_REVOKED;

    emit!(CredentialRevoked {
        credential_ref: status.credential_ref,
        issuer_id: status.issuer_id,
        revoked_by: signer,
    });
    Ok(())
}
