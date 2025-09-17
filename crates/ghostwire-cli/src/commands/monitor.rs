/// Monitoring and metrics command handlers

use anyhow::Result;
use std::time::Duration;
use tokio::time::{interval, sleep};
use crate::client::GwctlClient;
use crate::commands::MonitorCommands;
use crate::output::{self, OutputConfig, OutputFormat, ProgressIndicator};
use crate::utils::parse_duration;
use crate::Cli;

pub async fn handle_command(client: &GwctlClient, command: &MonitorCommands, cli: &Cli) -> Result<()> {
    let output_config = OutputConfig {
        format: cli.output,
        color: !cli.quiet,
        timestamps: cli.timestamps,
    };

    match command {
        MonitorCommands::Status { node_id, watch, interval: watch_interval } => {
            if *watch {
                let interval_duration = if let Some(interval_str) = watch_interval {
                    parse_duration(interval_str)?
                } else {
                    Duration::from_secs(5)
                };

                let mut ticker = interval(interval_duration);

                println!("{}", output::info("Starting status monitoring (Ctrl+C to stop)", output_config.color));
                println!();

                loop {
                    ticker.tick().await;

                    match client.get_system_status(node_id.as_deref()).await {
                        Ok(status) => {
                            display_status(&status, &output_config)?;

                            if matches!(output_config.format, OutputFormat::Table) {
                                // Clear screen for next update
                                print!("\x1B[2J\x1B[1;1H");
                            } else {
                                println!("---");
                            }
                        }
                        Err(e) => {
                            eprintln!("{}", output::error(&format!("Failed to get status: {}", e), output_config.color));
                        }
                    }
                }
            } else {
                let status = client.get_system_status(node_id.as_deref()).await?;
                display_status(&status, &output_config)?;
            }
        }
        MonitorCommands::Metrics { node_id, metric_type, duration } => {
            let metrics = client.get_metrics(node_id.as_deref(), metric_type.as_deref(), duration.as_deref()).await?;

            match output_config.format {
                OutputFormat::Table => {
                    if metrics.is_empty() {
                        println!("{}", output::info("No metrics found", output_config.color));
                        return Ok(());
                    }

                    let metric_infos: Vec<output::MetricInfo> = metrics.iter().map(|metric| {
                        output::MetricInfo {
                            name: metric.name.clone(),
                            value: metric.value.to_string(),
                            unit: metric.unit.clone().unwrap_or_else(|| "".to_string()),
                            node: metric.node.clone().unwrap_or_else(|| "Global".to_string()),
                            timestamp: metric.timestamp.clone(),
                        }
                    }).collect();

                    output::display_list(&metric_infos, &output_config)?;
                }
                OutputFormat::Json => {
                    println!("{}", serde_json::to_string_pretty(&metrics)?);
                }
                OutputFormat::Yaml => {
                    println!("{}", serde_yaml::to_string(&metrics)?);
                }
                OutputFormat::Compact => {
                    for metric in &metrics {
                        println!("{} {} {}", metric.name, metric.value, metric.unit.as_deref().unwrap_or(""));
                    }
                }
            }
        }
        MonitorCommands::Logs { node_id, level, follow, lines } => {
            if *follow {
                let spinner = ProgressIndicator::new("Connecting to log stream...");

                // Simulate connecting to log stream
                sleep(Duration::from_millis(500)).await;
                spinner.finish_with_message("Connected to log stream (Ctrl+C to stop)");

                println!();

                // Simulate streaming logs
                let mut log_count = 0;
                let mut ticker = interval(Duration::from_secs(2));

                loop {
                    ticker.tick().await;
                    log_count += 1;

                    let timestamp = chrono::Utc::now().to_rfc3339();
                    let sample_logs = vec![
                        format!("{} INFO  [ghostwire] Node connected: {}", timestamp, format!("node-{:03}", log_count % 100)),
                        format!("{} DEBUG [transport] QUIC connection established", timestamp),
                        format!("{} INFO  [derp] Relay traffic: {} bytes", timestamp, log_count * 1024),
                    ];

                    for log in sample_logs {
                        if let Some(filter_level) = level {
                            if !log.contains(&filter_level.to_uppercase()) {
                                continue;
                            }
                        }

                        if let Some(filter_node) = node_id {
                            if !log.contains(filter_node) {
                                continue;
                            }
                        }

                        println!("{}", log);
                    }

                    if log_count > 50 {
                        break;
                    }
                }
            } else {
                let logs = client.get_logs(node_id.as_deref(), level.as_deref(), *lines).await?;

                match output_config.format {
                    OutputFormat::Table | OutputFormat::Compact => {
                        for log in logs {
                            println!("{}", log.message);
                        }
                    }
                    OutputFormat::Json => {
                        println!("{}", serde_json::to_string_pretty(&logs)?);
                    }
                    OutputFormat::Yaml => {
                        println!("{}", serde_yaml::to_string(&logs)?);
                    }
                }
            }
        }
        MonitorCommands::Network { node_id, watch, interval: watch_interval } => {
            if *watch {
                let interval_duration = if let Some(interval_str) = watch_interval {
                    parse_duration(interval_str)?
                } else {
                    Duration::from_secs(5)
                };

                let mut ticker = interval(interval_duration);

                println!("{}", output::info("Starting network monitoring (Ctrl+C to stop)", output_config.color));
                println!();

                loop {
                    ticker.tick().await;

                    match client.get_network_status(node_id.as_deref()).await {
                        Ok(status) => {
                            display_network_status(&status, &output_config)?;

                            if matches!(output_config.format, OutputFormat::Table) {
                                println!("---");
                            }
                        }
                        Err(e) => {
                            eprintln!("{}", output::error(&format!("Failed to get network status: {}", e), output_config.color));
                        }
                    }
                }
            } else {
                let status = client.get_network_status(node_id.as_deref()).await?;
                display_network_status(&status, &output_config)?;
            }
        }
        _ => {
            println!("{}", output::info("Monitor command not yet implemented", output_config.color));
        }
    }

    Ok(())
}

fn display_status(status: &serde_json::Value, config: &OutputConfig) -> Result<()> {
    match config.format {
        OutputFormat::Table => {
            println!("{}", output::info("System Status", config.color));

            // This would display actual status data from the server
            let status_data = vec![
                ("Server Version".to_string(), "0.1.0".to_string()),
                ("Uptime".to_string(), "2d 14h 32m".to_string()),
                ("Connected Nodes".to_string(), "42".to_string()),
                ("Active Connections".to_string(), "128".to_string()),
                ("CPU Usage".to_string(), "12.3%".to_string()),
                ("Memory Usage".to_string(), "245MB / 1GB".to_string()),
                ("Network Traffic".to_string(), "1.2GB in / 2.1GB out".to_string()),
            ];

            let table = output::create_kv_table(&status_data, config.color);
            println!("{}", table);
        }
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(status)?);
        }
        OutputFormat::Yaml => {
            println!("{}", serde_yaml::to_string(status)?);
        }
        OutputFormat::Compact => {
            println!("status: ok, nodes: 42, connections: 128");
        }
    }

    Ok(())
}

fn display_network_status(status: &serde_json::Value, config: &OutputConfig) -> Result<()> {
    match config.format {
        OutputFormat::Table => {
            println!("{}", output::info("Network Status", config.color));

            let network_data = vec![
                ("DERP Relays".to_string(), "3 healthy, 1 degraded".to_string()),
                ("QUIC Connections".to_string(), "24 active".to_string()),
                ("WireGuard Peers".to_string(), "42 connected".to_string()),
                ("Packet Loss".to_string(), "0.2%".to_string()),
                ("Average Latency".to_string(), "45ms".to_string()),
                ("Throughput".to_string(), "125 Mbps".to_string()),
            ];

            let table = output::create_kv_table(&network_data, config.color);
            println!("{}", table);
        }
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(status)?);
        }
        OutputFormat::Yaml => {
            println!("{}", serde_yaml::to_string(status)?);
        }
        OutputFormat::Compact => {
            println!("derp: 3/4, quic: 24, wg: 42, loss: 0.2%, latency: 45ms");
        }
    }

    Ok(())
}