use anchor_lang::prelude::*;

use crate::{
    constants::*,
    error::ErrorCode,
    events::IssuerStatusChanged,
    state::{IssuerRecord, RegistryConfig},
};

#[derive(Accounts)]
pub struct SetIssuerStatus<'info> {
    pub authority: Signer<'info>,
    #[account(
        seeds = [REGISTRY_CONFIG_SEED],
        bump = registry_config.bump,
        has_one = authority @ ErrorCode::Unauthorized,
    )]
    pub registry_config: Account<'info, RegistryConfig>,
    #[account(
        mut,
        seeds = [ISSUER_SEED, issuer_record.issuer_id.as_ref()],
        bump = issuer_record.bump,
    )]
    pub issuer_record: Account<'info, IssuerRecord>,
}

/// Works while the registry is paused: suspending an issuer is always safe.
pub fn handle_set_issuer_status(ctx: Context<SetIssuerStatus>, active: bool) -> Result<()> {
    let issuer = &mut ctx.accounts.issuer_record;
    require!(issuer.active != active, ErrorCode::StatusUnchanged);
    issuer.active = active;

    emit!(IssuerStatusChanged {
        issuer_id: issuer.issuer_id,
        active,
    });
    Ok(())
}
