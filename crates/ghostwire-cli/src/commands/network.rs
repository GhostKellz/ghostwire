/// Network management command handlers

use anyhow::Result;
use crate::client::GwctlClient;
use crate::commands::NetworkCommands;
use crate::output;
use crate::Cli;

pub async fn handle_command(_client: &GwctlClient, _command: &NetworkCommands, cli: &Cli) -> Result<()> {
    println!("{}", output::info("Network commands not yet implemented", !cli.quiet));
    Ok(())
}