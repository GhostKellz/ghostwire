/// DERP relay management command handlers

use anyhow::Result;
use crate::client::GwctlClient;
use crate::commands::DerpCommands;
use crate::output::{self, OutputConfig, OutputFormat};
use crate::Cli;

pub async fn handle_command(client: &GwctlClient, command: &DerpCommands, cli: &Cli) -> Result<()> {
    let output_config = OutputConfig {
        format: cli.output,
        color: !cli.quiet,
        timestamps: false,
    };

    match command {
        DerpCommands::List { region } => {
            let relays = client.list_derp_relays(region.as_deref()).await?;

            match output_config.format {
                OutputFormat::Table => {
                    if relays.is_empty() {
                        println!("{}", output::info("No DERP relays found", output_config.color));
                        return Ok(());
                    }

                    let relay_infos: Vec<output::DerpRelayInfo> = relays.iter().map(|relay| {
                        output::DerpRelayInfo {
                            id: relay.id.clone(),
                            region: relay.region.clone(),
                            hostname: relay.hostname.clone(),
                            ipv4: relay.ipv4.clone().unwrap_or_else(|| "N/A".to_string()),
                            ipv6: relay.ipv6.clone().unwrap_or_else(|| "N/A".to_string()),
                            port: relay.port.to_string(),
                            status: if relay.healthy { "Healthy".to_string() } else { "Unhealthy".to_string() },
                            latency: relay.latency.map(|l| format!("{}ms", l)).unwrap_or_else(|| "Unknown".to_string()),
                        }
                    }).collect();

                    output::display_list(&relay_infos, &output_config)?;
                }
                OutputFormat::Json => {
                    println!("{}", serde_json::to_string_pretty(&relays)?);
                }
                OutputFormat::Yaml => {
                    println!("{}", serde_yaml::to_string(&relays)?);
                }
                OutputFormat::Compact => {
                    for relay in &relays {
                        println!("{} {} {} {}", relay.id, relay.region, relay.hostname, if relay.healthy { "healthy" } else { "unhealthy" });
                    }
                }
            }
        }
        DerpCommands::Status { relay_id } => {
            let status = client.get_derp_status(relay_id).await?;

            match output_config.format {
                OutputFormat::Table => {
                    let status_data = vec![
                        ("Relay ID".to_string(), status.id),
                        ("Region".to_string(), status.region),
                        ("Hostname".to_string(), status.hostname),
                        ("Status".to_string(), if status.healthy { "Healthy".to_string() } else { "Unhealthy".to_string() }),
                        ("Connected Clients".to_string(), status.connected_clients.to_string()),
                        ("Uptime".to_string(), status.uptime.unwrap_or_else(|| "Unknown".to_string())),
                        ("Last Health Check".to_string(), status.last_health_check.unwrap_or_else(|| "Never".to_string())),
                    ];

                    let table = output::create_kv_table(&status_data, output_config.color);
                    println!("{}", table);
                }
                OutputFormat::Json => {
                    println!("{}", serde_json::to_string_pretty(&status)?);
                }
                OutputFormat::Yaml => {
                    println!("{}", serde_yaml::to_string(&status)?);
                }
                OutputFormat::Compact => {
                    println!("{} {} {}", status.id, status.connected_clients, if status.healthy { "healthy" } else { "unhealthy" });
                }
            }
        }
        _ => {
            println!("{}", output::info("DERP command not yet implemented", output_config.color));
        }
    }

    Ok(())
}