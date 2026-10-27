use anchor_lang::prelude::*;

use crate::{
    constants::*,
    error::ErrorCode,
    events::CredentialRegistered,
    state::{CredentialStatus, IssuerRecord, RegistryConfig},
};

#[derive(Accounts)]
#[instruction(credential_ref: [u8; 32])]
pub struct RegisterCredential<'info> {
    /// The issuer authority; pays for the status account.
    #[account(mut)]
    pub authority: Signer<'info>,
    #[account(seeds = [REGISTRY_CONFIG_SEED], bump = registry_config.bump)]
    pub registry_config: Account<'info, RegistryConfig>,
    #[account(
        seeds = [ISSUER_SEED, issuer_record.issuer_id.as_ref()],
        bump = issuer_record.bump,
        has_one = authority @ ErrorCode::Unauthorized,
    )]
    pub issuer_record: Account<'info, IssuerRecord>,
    #[account(
        init,
        payer = authority,
        space = 8 + CredentialStatus::INIT_SPACE,
        seeds = [CREDENTIAL_SEED, credential_ref.as_ref()],
        bump
    )]
    pub credential_status: Account<'info, CredentialStatus>,
    pub system_program: Program<'info, System>,
}

pub fn handle_register_credential(
    ctx: Context<RegisterCredential>,
    credential_ref: [u8; 32],
    expires_at: i64,
) -> Result<()> {
    require!(!ctx.accounts.registry_config.paused, ErrorCode::RegistryPaused);
    require!(ctx.accounts.issuer_record.active, ErrorCode::IssuerInactive);
    require!(
        expires_at > Clock::get()?.unix_timestamp,
        ErrorCode::ExpiryInPast
    );

    let issuer_id = ctx.accounts.issuer_record.issuer_id;
    let status = &mut ctx.accounts.credential_status;
    status.credential_ref = credential_ref;
    status.issuer_id = issuer_id;
    status.status = CREDENTIAL_ACTIVE;
    status.expires_at = expires_at;
    status.bump = ctx.bumps.credential_status;

    emit!(CredentialRegistered {
        credential_ref,
        issuer_id,
        expires_at,
    });
    Ok(())
}
