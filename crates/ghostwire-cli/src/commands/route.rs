/// Route management command handlers

use anyhow::Result;
use crate::client::GwctlClient;
use crate::commands::RouteCommands;
use crate::output::{self, OutputConfig, OutputFormat};
use crate::utils::{validate_ip_or_cidr, confirm_operation};
use crate::Cli;

pub async fn handle_command(client: &GwctlClient, command: &RouteCommands, cli: &Cli) -> Result<()> {
    let output_config = OutputConfig {
        format: cli.output,
        color: !cli.quiet,
        timestamps: false,
    };

    match command {
        RouteCommands::List { node_id, network } => {
            let routes = client.list_routes(node_id.as_deref(), network.as_deref()).await?;

            match output_config.format {
                OutputFormat::Table => {
                    if routes.is_empty() {
                        println!("{}", output::info("No routes found", output_config.color));
                        return Ok(());
                    }

                    let route_infos: Vec<output::RouteInfo> = routes.iter().map(|route| {
                        output::RouteInfo {
                            id: route.id.clone(),
                            destination: route.destination.clone(),
                            node: route.node.clone(),
                            metric: route.metric.unwrap_or(0).to_string(),
                            enabled: route.enabled.to_string(),
                            advertised: route.advertised.to_string(),
                            created: route.created_at.clone(),
                        }
                    }).collect();

                    output::display_list(&route_infos, &output_config)?;
                }
                OutputFormat::Json => {
                    println!("{}", serde_json::to_string_pretty(&routes)?);
                }
                OutputFormat::Yaml => {
                    println!("{}", serde_yaml::to_string(&routes)?);
                }
                OutputFormat::Compact => {
                    for route in &routes {
                        println!("{} {} {} {}", route.id, route.destination, route.node, route.enabled);
                    }
                }
            }
        }
        RouteCommands::Add { destination, node_id, metric, advertise } => {
            validate_ip_or_cidr(destination)?;

            let route = client.create_route(destination, node_id, *metric, *advertise).await?;

            match output_config.format {
                OutputFormat::Table => {
                    println!("{}", output::success("Route created successfully", output_config.color));

                    let route_data = vec![
                        ("Route ID".to_string(), route.id),
                        ("Destination".to_string(), route.destination),
                        ("Node".to_string(), route.node),
                        ("Metric".to_string(), route.metric.unwrap_or(0).to_string()),
                        ("Enabled".to_string(), route.enabled.to_string()),
                        ("Advertised".to_string(), route.advertised.to_string()),
                        ("Created".to_string(), route.created_at),
                    ];

                    let table = output::create_kv_table(&route_data, output_config.color);
                    println!("{}", table);
                }
                OutputFormat::Json => {
                    println!("{}", serde_json::to_string_pretty(&route)?);
                }
                OutputFormat::Yaml => {
                    println!("{}", serde_yaml::to_string(&route)?);
                }
                OutputFormat::Compact => {
                    println!("{} {} {}", route.id, route.destination, route.node);
                }
            }
        }
        RouteCommands::Delete { route_id, force } => {
            let message = format!("Are you sure you want to delete route '{}'? This may affect network connectivity.", route_id);
            if !confirm_operation(&message, *force)? {
                println!("{}", output::info("Operation cancelled", output_config.color));
                return Ok(());
            }

            client.delete_route(route_id).await?;
            println!("{}", output::success("Route deleted successfully", output_config.color));
        }
        RouteCommands::Enable { route_id } => {
            let route = client.update_route(route_id, Some(true), None, None).await?;

            match output_config.format {
                OutputFormat::Table => {
                    println!("{}", output::success("Route enabled successfully", output_config.color));

                    let route_data = vec![
                        ("Route ID".to_string(), route.id),
                        ("Destination".to_string(), route.destination),
                        ("Node".to_string(), route.node),
                        ("Enabled".to_string(), route.enabled.to_string()),
                    ];

                    let table = output::create_kv_table(&route_data, output_config.color);
                    println!("{}", table);
                }
                OutputFormat::Json => {
                    println!("{}", serde_json::to_string_pretty(&route)?);
                }
                OutputFormat::Yaml => {
                    println!("{}", serde_yaml::to_string(&route)?);
                }
                OutputFormat::Compact => {
                    println!("{} enabled", route.id);
                }
            }
        }
        RouteCommands::Disable { route_id } => {
            let route = client.update_route(route_id, Some(false), None, None).await?;

            match output_config.format {
                OutputFormat::Table => {
                    println!("{}", output::success("Route disabled successfully", output_config.color));

                    let route_data = vec![
                        ("Route ID".to_string(), route.id),
                        ("Destination".to_string(), route.destination),
                        ("Node".to_string(), route.node),
                        ("Enabled".to_string(), route.enabled.to_string()),
                    ];

                    let table = output::create_kv_table(&route_data, output_config.color);
                    println!("{}", table);
                }
                OutputFormat::Json => {
                    println!("{}", serde_json::to_string_pretty(&route)?);
                }
                OutputFormat::Yaml => {
                    println!("{}", serde_yaml::to_string(&route)?);
                }
                OutputFormat::Compact => {
                    println!("{} disabled", route.id);
                }
            }
        }
        RouteCommands::Show { route_id } => {
            let route = client.get_route(route_id).await?;

            match output_config.format {
                OutputFormat::Table => {
                    let route_data = vec![
                        ("Route ID".to_string(), route.id),
                        ("Destination".to_string(), route.destination),
                        ("Node".to_string(), route.node),
                        ("Metric".to_string(), route.metric.unwrap_or(0).to_string()),
                        ("Enabled".to_string(), route.enabled.to_string()),
                        ("Advertised".to_string(), route.advertised.to_string()),
                        ("Created".to_string(), route.created_at),
                        ("Updated".to_string(), route.updated_at.unwrap_or_else(|| "N/A".to_string())),
                    ];

                    let table = output::create_kv_table(&route_data, output_config.color);
                    println!("{}", table);
                }
                OutputFormat::Json => {
                    println!("{}", serde_json::to_string_pretty(&route)?);
                }
                OutputFormat::Yaml => {
                    println!("{}", serde_yaml::to_string(&route)?);
                }
                OutputFormat::Compact => {
                    println!("{} {} {} {}", route.id, route.destination, route.node, route.enabled);
                }
            }
        }
        _ => {
            println!("{}", output::info("Route command not yet implemented", output_config.color));
        }
    }

    Ok(())
}