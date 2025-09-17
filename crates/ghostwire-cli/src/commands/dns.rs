/// DNS management command handlers

use anyhow::Result;
use crate::client::GwctlClient;
use crate::commands::DnsCommands;
use crate::output::{self, OutputConfig, OutputFormat};
use crate::Cli;

pub async fn handle_command(client: &GwctlClient, command: &DnsCommands, cli: &Cli) -> Result<()> {
    let output_config = OutputConfig {
        format: cli.output,
        color: !cli.quiet,
        timestamps: false,
    };

    match command {
        DnsCommands::Records { domain, record_type } => {
            let records = client.list_dns_records(domain.as_deref(), record_type.as_deref()).await?;

            match output_config.format {
                OutputFormat::Table => {
                    if records.is_empty() {
                        println!("{}", output::info("No DNS records found", output_config.color));
                        return Ok(());
                    }

                    let record_infos: Vec<output::DnsRecordInfo> = records.iter().map(|record| {
                        output::DnsRecordInfo {
                            name: record.name.clone(),
                            record_type: record.record_type.clone(),
                            value: record.value.clone(),
                            ttl: record.ttl.to_string(),
                            node: record.node.clone().unwrap_or_else(|| "Global".to_string()),
                        }
                    }).collect();

                    output::display_list(&record_infos, &output_config)?;
                }
                OutputFormat::Json => {
                    println!("{}", serde_json::to_string_pretty(&records)?);
                }
                OutputFormat::Yaml => {
                    println!("{}", serde_yaml::to_string(&records)?);
                }
                OutputFormat::Compact => {
                    for record in &records {
                        println!("{} {} {}", record.name, record.record_type, record.value);
                    }
                }
            }
        }
        DnsCommands::Add { name, record_type, value, ttl, node } => {
            let record = client.create_dns_record(name, record_type, value, *ttl, node.as_deref()).await?;

            match output_config.format {
                OutputFormat::Table => {
                    println!("{}", output::success("DNS record created successfully", output_config.color));

                    let record_data = vec![
                        ("Name".to_string(), record.name),
                        ("Type".to_string(), record.record_type),
                        ("Value".to_string(), record.value),
                        ("TTL".to_string(), record.ttl.to_string()),
                        ("Node".to_string(), record.node.unwrap_or_else(|| "Global".to_string())),
                    ];

                    let table = output::create_kv_table(&record_data, output_config.color);
                    println!("{}", table);
                }
                OutputFormat::Json => {
                    println!("{}", serde_json::to_string_pretty(&record)?);
                }
                OutputFormat::Yaml => {
                    println!("{}", serde_yaml::to_string(&record)?);
                }
                OutputFormat::Compact => {
                    println!("{} {} {}", record.name, record.record_type, record.value);
                }
            }
        }
        DnsCommands::Remove { name, record_type } => {
            client.delete_dns_record(name, record_type.as_deref()).await?;
            println!("{}", output::success("DNS record deleted successfully", output_config.color));
        }
        DnsCommands::Status => {
            let status = client.get_dns_status().await?;

            match output_config.format {
                OutputFormat::Table => {
                    let status_data = vec![
                        ("MagicDNS Enabled".to_string(), status.enabled.to_string()),
                        ("Base Domain".to_string(), status.base_domain.unwrap_or_else(|| "N/A".to_string())),
                        ("Total Records".to_string(), status.total_records.to_string()),
                        ("Search Domains".to_string(), status.search_domains.join(", ")),
                        ("Nameservers".to_string(), status.nameservers.join(", ")),
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
                    println!("{} {}", status.enabled, status.total_records);
                }
            }
        }
        _ => {
            println!("{}", output::info("DNS command not yet implemented", output_config.color));
        }
    }

    Ok(())
}