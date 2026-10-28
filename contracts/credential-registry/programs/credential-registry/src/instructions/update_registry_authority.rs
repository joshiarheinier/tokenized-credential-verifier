use anchor_lang::prelude::*;

use crate::{
    constants::*,
    error::ErrorCode,
    events::RegistryAuthorityUpdated,
    state::RegistryConfig,
};

#[derive(Accounts)]
pub struct UpdateRegistryAuthority<'info> {
    pub authority: Signer<'info>,
    #[account(
        mut,
        seeds = [REGISTRY_CONFIG_SEED],
        bump = registry_config.bump,
        has_one = authority @ ErrorCode::Unauthorized,
    )]
    pub registry_config: Account<'info, RegistryConfig>,
}

pub fn handle_update_registry_authority(
    ctx: Context<UpdateRegistryAuthority>,
    new_authority: Pubkey,
) -> Result<()> {
    require_keys_neq!(new_authority, Pubkey::default(), ErrorCode::InvalidAuthority);

    let config = &mut ctx.accounts.registry_config;
    let old_authority = config.authority;
    config.authority = new_authority;

    emit!(RegistryAuthorityUpdated {
        old_authority,
        new_authority,
    });
    Ok(())
}
