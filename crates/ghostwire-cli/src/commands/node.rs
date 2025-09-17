/// Node management command handlers

use anyhow::Result;
use crate::client::GwctlClient;
use crate::commands::NodeCommands;
use crate::output::{self, OutputConfig, OutputFormat};
use crate::Cli;

pub async fn handle_command(client: &GwctlClient, command: &NodeCommands, cli: &Cli) -> Result<()> {
    let output_config = OutputConfig {
        format: cli.output,
        color: !cli.quiet,
        timestamps: false,
    };

    match command {
        NodeCommands::List { .. } => {
            let nodes = client.list_nodes().await?;

            match output_config.format {
                OutputFormat::Table => {
                    if nodes.is_empty() {
                        println!("{}", output::info("No nodes found", output_config.color));
                        return Ok(());
                    }

                    let node_infos: Vec<output::NodeInfo> = nodes.iter().map(|node| {
                        output::NodeInfo {
                            id: node.id.clone(),
                            name: node.name.clone(),
                            ip: node.ip.clone(),
                            status: if node.online { "Online".to_string() } else { "Offline".to_string() },
                            last_seen: node.last_seen.clone().unwrap_or_else(|| "Never".to_string()),
                            version: node.version.clone().unwrap_or_else(|| "Unknown".to_string()),
                        }
                    }).collect();

                    output::display_list(&node_infos, &output_config)?;
                }
                OutputFormat::Json => {
                    println!("{}", serde_json::to_string_pretty(&nodes)?);
                }
                OutputFormat::Yaml => {
                    println!("{}", serde_yaml::to_string(&nodes)?);
                }
                OutputFormat::Compact => {
                    for node in &nodes {
                        println!("{} {} {} {}", node.id, node.name, node.ip, if node.online { "online" } else { "offline" });
                    }
                }
            }
        }
        _ => {
            println!("{}", output::info("Node command not yet implemented", output_config.color));
        }
    }

    Ok(())
}