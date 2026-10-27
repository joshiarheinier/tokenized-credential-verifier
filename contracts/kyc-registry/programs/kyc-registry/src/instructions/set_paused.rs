use anchor_lang::prelude::*;

use crate::{
    constants::*,
    error::ErrorCode,
    events::RegistryPausedChanged,
    state::RegistryConfig,
};

#[derive(Accounts)]
pub struct SetPaused<'info> {
    pub authority: Signer<'info>,
    #[account(
        mut,
        seeds = [REGISTRY_CONFIG_SEED],
        bump = registry_config.bump,
        has_one = authority @ ErrorCode::Unauthorized,
    )]
    pub registry_config: Account<'info, RegistryConfig>,
}

/// Pausing blocks new issuers and new credentials only; suspension and revocation keep working.
pub fn handle_set_paused(ctx: Context<SetPaused>, paused: bool) -> Result<()> {
    ctx.accounts.registry_config.paused = paused;
    emit!(RegistryPausedChanged { paused });
    Ok(())
}
