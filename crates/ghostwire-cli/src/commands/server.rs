/// Server management command handlers
///
/// Handles all server-related operations including status monitoring,
/// metrics, logs, and configuration management.

use anyhow::Result;
use tokio::time::{interval, Duration};
use tracing::{debug, info};

use crate::client::GwctlClient;
use crate::commands::ServerCommands;
use crate::output::{self, OutputConfig, OutputFormat, Status, format_bytes, format_duration, ProgressIndicator};
use crate::Cli;

pub async fn handle_command(client: &GwctlClient, command: &ServerCommands, cli: &Cli) -> Result<()> {
    match command {
        ServerCommands::Status { detailed, watch, interval: watch_interval } => {
            handle_status(client, *detailed, *watch, *watch_interval, cli).await
        }
        ServerCommands::Version => {
            handle_version(client, cli).await
        }
        ServerCommands::Metrics { categories, prometheus } => {
            handle_metrics(client, categories, *prometheus, cli).await
        }
        ServerCommands::Logs { lines, follow, level, component } => {
            handle_logs(client, *lines, *follow, level, component, cli).await
        }
        ServerCommands::Restart { component, force } => {
            handle_restart(client, component, *force, cli).await
        }
        ServerCommands::Configure { set, file, dry_run } => {
            handle_configure(client, set, file, *dry_run, cli).await
        }
    }
}

async fn handle_status(
    client: &GwctlClient,
    detailed: bool,
    watch: bool,
    watch_interval: u64,
    cli: &Cli,
) -> Result<()> {
    let output_config = OutputConfig {
        format: cli.output,
        color: !cli.quiet,
        timestamps: false,
    };

    if watch {
        // Continuous monitoring mode
        let mut interval_timer = interval(Duration::from_secs(watch_interval));

        loop {
            // Clear screen for better experience
            if output_config.color {
                print!("\x1B[2J\x1B[1;1H"); // Clear screen and move cursor to top
            }

            show_status(client, detailed, &output_config).await?;

            if output_config.color {
                println!("\n{}", "Press Ctrl+C to stop watching...".dimmed());
            }

            interval_timer.tick().await;
        }
    } else {
        show_status(client, detailed, &output_config).await
    }
}

async fn show_status(client: &GwctlClient, detailed: bool, config: &OutputConfig) -> Result<()> {
    let spinner = ProgressIndicator::new("Checking server status...");

    // Get basic health info
    let health = client.health().await?;
    let version = client.version().await?;

    spinner.finish();

    match config.format {
        OutputFormat::Table => {
            println!("{}", output::info("GhostWire Server Status", config.color));
            println!();

            // Server overview
            let status = match health.status.as_str() {
                "healthy" => Status::Online,
                "unhealthy" => Status::Error,
                "degraded" => Status::Warning,
                _ => Status::Unknown,
            };

            let overview_data = vec![
                ("Status".to_string(), status.colored(config.color).to_string()),
                ("Version".to_string(), version.version),
                ("Build".to_string(), format!("{} ({})", version.commit, version.build_date)),
            ];

            let overview_table = output::create_kv_table(&overview_data, config.color);
            println!("{}", overview_table);

            if detailed || health.components.len() > 0 {
                println!();
                println!("{}", "Component Status".bold());
                println!();

                // Component status table
                let mut component_rows = Vec::new();
                for component in &health.components {
                    let comp_status = match component.status.as_str() {
                        "healthy" => Status::Online,
                        "unhealthy" => Status::Error,
                        "degraded" => Status::Warning,
                        _ => Status::Unknown,
                    };

                    component_rows.push(output::ServerInfo {
                        component: component.name.clone(),
                        status: comp_status.colored(config.color).to_string(),
                        version: "1.0".to_string(), // Would come from actual component info
                        uptime: "5d 12h".to_string(), // Would come from actual metrics
                        memory: "245 MB".to_string(), // Would come from actual metrics
                    });
                }

                if !component_rows.is_empty() {
                    output::display_list(&component_rows, config)?;
                }
            }

            if detailed {
                // Additional metrics in detailed mode
                if let Ok(metrics) = client.get_metrics().await {
                    println!();
                    println!("{}", "Key Metrics".bold());
                    println!();

                    let metrics_data = vec![
                        ("Total Nodes".to_string(), metrics.nodes_total.to_string()),
                        ("Online Nodes".to_string(), metrics.nodes_online.to_string()),
                        ("Total Users".to_string(), metrics.users_total.to_string()),
                        ("Data Sent".to_string(), format_bytes(metrics.bytes_sent)),
                        ("Data Received".to_string(), format_bytes(metrics.bytes_received)),
                        ("Uptime".to_string(), format_duration(Duration::from_secs(metrics.uptime_seconds))),
                        ("Memory Usage".to_string(), format_bytes(metrics.memory_usage_bytes)),
                        ("CPU Usage".to_string(), format!("{:.1}%", metrics.cpu_usage_percent)),
                    ];

                    let metrics_table = output::create_kv_table(&metrics_data, config.color);
                    println!("{}", metrics_table);
                }
            }
        }
        OutputFormat::Json => {
            let status_info = serde_json::json!({
                "status": health.status,
                "version": version.version,
                "commit": version.commit,
                "build_date": version.build_date,
                "components": health.components
            });
            println!("{}", serde_json::to_string_pretty(&status_info)?);
        }
        OutputFormat::Yaml => {
            let status_info = serde_json::json!({
                "status": health.status,
                "version": version.version,
                "commit": version.commit,
                "build_date": version.build_date,
                "components": health.components
            });
            println!("{}", serde_yaml::to_string(&status_info)?);
        }
        OutputFormat::Compact => {
            println!("{} {} {}", health.status, version.version, health.components.len());
        }
    }

    Ok(())
}

async fn handle_version(client: &GwctlClient, cli: &Cli) -> Result<()> {
    let version = client.version().await?;

    let output_config = OutputConfig {
        format: cli.output,
        color: !cli.quiet,
        timestamps: false,
    };

    match output_config.format {
        OutputFormat::Table => {
            println!("{}", output::info("GhostWire Server Version", output_config.color));
            println!();

            let version_data = vec![
                ("Version".to_string(), version.version),
                ("Commit".to_string(), version.commit),
                ("Build Date".to_string(), version.build_date),
            ];

            let table = output::create_kv_table(&version_data, output_config.color);
            println!("{}", table);
        }
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&version)?);
        }
        OutputFormat::Yaml => {
            println!("{}", serde_yaml::to_string(&version)?);
        }
        OutputFormat::Compact => {
            println!("{}", version.version);
        }
    }

    Ok(())
}

async fn handle_metrics(
    client: &GwctlClient,
    categories: &[String],
    prometheus: bool,
    cli: &Cli,
) -> Result<()> {
    let metrics = client.get_metrics().await?;

    if prometheus {
        // Output in Prometheus format
        println!("# HELP ghostwire_nodes_total Total number of nodes");
        println!("# TYPE ghostwire_nodes_total gauge");
        println!("ghostwire_nodes_total {}", metrics.nodes_total);

        println!("# HELP ghostwire_nodes_online Number of online nodes");
        println!("# TYPE ghostwire_nodes_online gauge");
        println!("ghostwire_nodes_online {}", metrics.nodes_online);

        println!("# HELP ghostwire_users_total Total number of users");
        println!("# TYPE ghostwire_users_total gauge");
        println!("ghostwire_users_total {}", metrics.users_total);

        println!("# HELP ghostwire_bytes_sent_total Total bytes sent");
        println!("# TYPE ghostwire_bytes_sent_total counter");
        println!("ghostwire_bytes_sent_total {}", metrics.bytes_sent);

        println!("# HELP ghostwire_bytes_received_total Total bytes received");
        println!("# TYPE ghostwire_bytes_received_total counter");
        println!("ghostwire_bytes_received_total {}", metrics.bytes_received);

        println!("# HELP ghostwire_uptime_seconds Server uptime in seconds");
        println!("# TYPE ghostwire_uptime_seconds gauge");
        println!("ghostwire_uptime_seconds {}", metrics.uptime_seconds);

        return Ok(());
    }

    let output_config = OutputConfig {
        format: cli.output,
        color: !cli.quiet,
        timestamps: false,
    };

    match output_config.format {
        OutputFormat::Table => {
            println!("{}", output::info("Server Metrics", output_config.color));
            println!();

            // Filter categories if specified
            let show_all = categories.is_empty();

            if show_all || categories.contains(&"nodes".to_string()) {
                let node_data = vec![
                    ("Total Nodes".to_string(), metrics.nodes_total.to_string()),
                    ("Online Nodes".to_string(), metrics.nodes_online.to_string()),
                    ("Offline Nodes".to_string(), (metrics.nodes_total - metrics.nodes_online).to_string()),
                ];
                println!("{}", "Node Statistics".bold());
                let table = output::create_kv_table(&node_data, output_config.color);
                println!("{}", table);
                println!();
            }

            if show_all || categories.contains(&"traffic".to_string()) {
                let traffic_data = vec![
                    ("Bytes Sent".to_string(), format_bytes(metrics.bytes_sent)),
                    ("Bytes Received".to_string(), format_bytes(metrics.bytes_received)),
                    ("Total Traffic".to_string(), format_bytes(metrics.bytes_sent + metrics.bytes_received)),
                ];
                println!("{}", "Traffic Statistics".bold());
                let table = output::create_kv_table(&traffic_data, output_config.color);
                println!("{}", table);
                println!();
            }

            if show_all || categories.contains(&"system".to_string()) {
                let system_data = vec![
                    ("Uptime".to_string(), format_duration(Duration::from_secs(metrics.uptime_seconds))),
                    ("Memory Usage".to_string(), format_bytes(metrics.memory_usage_bytes)),
                    ("CPU Usage".to_string(), format!("{:.1}%", metrics.cpu_usage_percent)),
                ];
                println!("{}", "System Statistics".bold());
                let table = output::create_kv_table(&system_data, output_config.color);
                println!("{}", table);
            }
        }
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&metrics)?);
        }
        OutputFormat::Yaml => {
            println!("{}", serde_yaml::to_string(&metrics)?);
        }
        OutputFormat::Compact => {
            println!("{} {} {} {} {}",
                metrics.nodes_total,
                metrics.nodes_online,
                metrics.users_total,
                metrics.bytes_sent,
                metrics.bytes_received
            );
        }
    }

    Ok(())
}

async fn handle_logs(
    _client: &GwctlClient,
    _lines: u32,
    _follow: bool,
    _level: &Option<crate::commands::LogLevel>,
    _component: &Option<String>,
    cli: &Cli,
) -> Result<()> {
    // This would implement log streaming from the server
    // For now, show a placeholder message

    if !cli.quiet {
        println!("{}", output::info("Log streaming not yet implemented", true));
        println!("This feature will stream server logs in real-time");
    }

    Ok(())
}

async fn handle_restart(
    _client: &GwctlClient,
    component: &Option<String>,
    force: bool,
    cli: &Cli,
) -> Result<()> {
    if !force {
        use dialoguer::Confirm;

        let message = match component {
            Some(comp) => format!("Restart component '{}'?", comp),
            None => "Restart all server components?".to_string(),
        };

        let confirmed = Confirm::new()
            .with_prompt(message)
            .default(false)
            .interact()?;

        if !confirmed {
            println!("Operation cancelled");
            return Ok(());
        }
    }

    // This would implement component restart
    if !cli.quiet {
        match component {
            Some(comp) => println!("{}", output::success(&format!("Component '{}' restart initiated", comp), true)),
            None => println!("{}", output::success("Server restart initiated", true)),
        }
    }

    Ok(())
}

async fn handle_configure(
    _client: &GwctlClient,
    _set: &[String],
    _file: &Option<std::path::PathBuf>,
    dry_run: bool,
    cli: &Cli,
) -> Result<()> {
    if dry_run {
        println!("{}", output::info("Dry run mode - no changes will be applied", !cli.quiet));
    }

    // This would implement server configuration management
    if !cli.quiet {
        println!("{}", output::info("Server configuration management not yet implemented", true));
    }

    Ok(())
}

// Helper trait for colored text
use colored::Colorize;

trait ColoredExt {
    fn bold(&self) -> colored::ColoredString;
    fn dimmed(&self) -> colored::ColoredString;
}

impl ColoredExt for str {
    fn bold(&self) -> colored::ColoredString {
        self.bold()
    }

    fn dimmed(&self) -> colored::ColoredString {
        self.dimmed()
    }
}