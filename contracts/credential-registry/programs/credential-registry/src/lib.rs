pub mod constants;
pub mod error;
pub mod events;
pub mod instructions;
pub mod state;

use anchor_lang::prelude::*;

pub use constants::*;
pub use instructions::*;
pub use state::*;

declare_id!("6NY7DBX4GQTq25E8pcrxUw4wDtGAC3EX1QVwD8jUDUMy");

#[program]
pub mod credential_registry {
    use super::*;

    pub fn initialize_registry(ctx: Context<InitializeRegistry>) -> Result<()> {
        instructions::initialize_registry::handle_initialize_registry(ctx)
    }

    pub fn update_registry_authority(
        ctx: Context<UpdateRegistryAuthority>,
        new_authority: Pubkey,
    ) -> Result<()> {
        instructions::update_registry_authority::handle_update_registry_authority(
            ctx,
            new_authority,
        )
    }

    pub fn set_paused(ctx: Context<SetPaused>, paused: bool) -> Result<()> {
        instructions::set_paused::handle_set_paused(ctx, paused)
    }

    pub fn register_issuer(
        ctx: Context<RegisterIssuer>,
        issuer_id: [u8; 32],
        issuer_signing_key: Pubkey,
        issuer_authority: Pubkey,
    ) -> Result<()> {
        instructions::register_issuer::handle_register_issuer(
            ctx,
            issuer_id,
            issuer_signing_key,
            issuer_authority,
        )
    }

    pub fn set_issuer_status(ctx: Context<SetIssuerStatus>, active: bool) -> Result<()> {
        instructions::set_issuer_status::handle_set_issuer_status(ctx, active)
    }

    pub fn register_credential(
        ctx: Context<RegisterCredential>,
        credential_ref: [u8; 32],
        expires_at: i64,
    ) -> Result<()> {
        instructions::register_credential::handle_register_credential(
            ctx,
            credential_ref,
            expires_at,
        )
    }

    pub fn revoke_credential(ctx: Context<RevokeCredential>) -> Result<()> {
        instructions::revoke_credential::handle_revoke_credential(ctx)
    }
}
