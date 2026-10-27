use anchor_lang::prelude::*;

use crate::{
    constants::*,
    error::ErrorCode,
    events::IssuerRegistered,
    state::{IssuerRecord, RegistryConfig},
};

#[derive(Accounts)]
#[instruction(issuer_id: [u8; 32])]
pub struct RegisterIssuer<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,
    #[account(
        seeds = [REGISTRY_CONFIG_SEED],
        bump = registry_config.bump,
        has_one = authority @ ErrorCode::Unauthorized,
    )]
    pub registry_config: Account<'info, RegistryConfig>,
    #[account(
        init,
        payer = authority,
        space = 8 + IssuerRecord::INIT_SPACE,
        seeds = [ISSUER_SEED, issuer_id.as_ref()],
        bump
    )]
    pub issuer_record: Account<'info, IssuerRecord>,
    pub system_program: Program<'info, System>,
}

pub fn handle_register_issuer(
    ctx: Context<RegisterIssuer>,
    issuer_id: [u8; 32],
    issuer_signing_key: Pubkey,
    issuer_authority: Pubkey,
) -> Result<()> {
    require!(!ctx.accounts.registry_config.paused, ErrorCode::RegistryPaused);
    require_keys_neq!(issuer_authority, Pubkey::default(), ErrorCode::InvalidAuthority);

    let issuer = &mut ctx.accounts.issuer_record;
    issuer.issuer_id = issuer_id;
    issuer.issuer_signing_key = issuer_signing_key;
    issuer.authority = issuer_authority;
    issuer.active = true;
    issuer.created_at = Clock::get()?.unix_timestamp;
    issuer.bump = ctx.bumps.issuer_record;

    emit!(IssuerRegistered {
        issuer_id,
        authority: issuer_authority,
        issuer_signing_key,
    });
    Ok(())
}
