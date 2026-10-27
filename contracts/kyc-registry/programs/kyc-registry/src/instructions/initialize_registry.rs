use anchor_lang::prelude::*;

use crate::{
    constants::*, error::ErrorCode, events::RegistryInitialized, program::KycRegistry,
    state::RegistryConfig,
};

#[derive(Accounts)]
pub struct InitializeRegistry<'info> {
    /// Pays for the account and becomes the registry authority. Must be the
    /// program upgrade authority so nobody can front-run initialization after deploy.
    #[account(
        mut,
        address = program_data.upgrade_authority_address.ok_or(ErrorCode::NotUpgradeAuthority)?
            @ ErrorCode::NotUpgradeAuthority,
    )]
    pub authority: Signer<'info>,
    #[account(
        init,
        payer = authority,
        space = 8 + RegistryConfig::INIT_SPACE,
        seeds = [REGISTRY_CONFIG_SEED],
        bump
    )]
    pub registry_config: Account<'info, RegistryConfig>,
    #[account(constraint = program.programdata_address()? == Some(program_data.key()))]
    pub program: Program<'info, KycRegistry>,
    pub program_data: Account<'info, ProgramData>,
    pub system_program: Program<'info, System>,
}

pub fn handle_initialize_registry(ctx: Context<InitializeRegistry>) -> Result<()> {
    let config = &mut ctx.accounts.registry_config;
    config.authority = ctx.accounts.authority.key();
    config.paused = false;
    config.version = REGISTRY_VERSION;
    config.bump = ctx.bumps.registry_config;

    emit!(RegistryInitialized {
        authority: config.authority,
    });
    Ok(())
}
