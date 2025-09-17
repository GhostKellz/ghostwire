/// Policy management command handlers

use anyhow::Result;
use crate::client::GwctlClient;
use crate::commands::PolicyCommands;
use crate::output;
use crate::Cli;

pub async fn handle_command(_client: &GwctlClient, _command: &PolicyCommands, cli: &Cli) -> Result<()> {
    println!("{}", output::info("Policy commands not yet implemented", !cli.quiet));
    Ok(())
}