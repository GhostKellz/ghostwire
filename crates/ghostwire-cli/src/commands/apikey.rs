/// API key management command handlers

use anyhow::Result;
use crate::client::GwctlClient;
use crate::commands::ApiKeyCommands;
use crate::output::{self, OutputConfig, OutputFormat};
use crate::utils::{parse_duration, format_timestamp_relative, confirm_operation};
use crate::Cli;

pub async fn handle_command(client: &GwctlClient, command: &ApiKeyCommands, cli: &Cli) -> Result<()> {
    let output_config = OutputConfig {
        format: cli.output,
        color: !cli.quiet,
        timestamps: false,
    };

    match command {
        ApiKeyCommands::List { user_id, active } => {
            let keys = client.list_api_keys(user_id.as_deref(), *active).await?;

            match output_config.format {
                OutputFormat::Table => {
                    if keys.is_empty() {
                        println!("{}", output::info("No API keys found", output_config.color));
                        return Ok(());
                    }

                    let key_infos: Vec<output::ApiKeyInfo> = keys.iter().map(|key| {
                        output::ApiKeyInfo {
                            id: key.id.clone(),
                            name: key.name.clone(),
                            user: key.user.clone(),
                            scopes: key.scopes.join(", "),
                            created: format_timestamp_relative(&key.created_at),
                            expires: key.expires_at.as_ref().map(format_timestamp_relative).unwrap_or_else(|| "Never".to_string()),
                            last_used: key.last_used.as_ref().map(format_timestamp_relative).unwrap_or_else(|| "Never".to_string()),
                            active: key.active.to_string(),
                        }
                    }).collect();

                    output::display_list(&key_infos, &output_config)?;
                }
                OutputFormat::Json => {
                    println!("{}", serde_json::to_string_pretty(&keys)?);
                }
                OutputFormat::Yaml => {
                    println!("{}", serde_yaml::to_string(&keys)?);
                }
                OutputFormat::Compact => {
                    for key in &keys {
                        println!("{} {} {} {}", key.id, key.name, key.user, key.active);
                    }
                }
            }
        }
        ApiKeyCommands::Create { name, scopes, expires_in, user_id } => {
            let expiry = if let Some(duration_str) = expires_in {
                Some(parse_duration(duration_str)?)
            } else {
                None
            };

            let key = client.create_api_key(name, scopes, expiry, user_id.as_deref()).await?;

            match output_config.format {
                OutputFormat::Table => {
                    println!("{}", output::success("API key created successfully", output_config.color));
                    println!();
                    println!("{}", output::warning("Store this key securely - it will not be shown again!", output_config.color));
                    println!();

                    let key_data = vec![
                        ("Key ID".to_string(), key.id),
                        ("Name".to_string(), key.name),
                        ("Token".to_string(), key.token),
                        ("User".to_string(), key.user),
                        ("Scopes".to_string(), key.scopes.join(", ")),
                        ("Created".to_string(), key.created_at),
                        ("Expires".to_string(), key.expires_at.unwrap_or_else(|| "Never".to_string())),
                    ];

                    let table = output::create_kv_table(&key_data, output_config.color);
                    println!("{}", table);
                }
                OutputFormat::Json => {
                    println!("{}", serde_json::to_string_pretty(&key)?);
                }
                OutputFormat::Yaml => {
                    println!("{}", serde_yaml::to_string(&key)?);
                }
                OutputFormat::Compact => {
                    println!("{}", key.token);
                }
            }
        }
        ApiKeyCommands::Delete { key_id, force } => {
            let message = format!("Are you sure you want to delete API key '{}'? This action cannot be undone.", key_id);
            if !confirm_operation(&message, *force)? {
                println!("{}", output::info("Operation cancelled", output_config.color));
                return Ok(());
            }

            client.delete_api_key(key_id).await?;
            println!("{}", output::success("API key deleted successfully", output_config.color));
        }
        ApiKeyCommands::Update { key_id, name, scopes, active } => {
            let key = client.update_api_key(key_id, name.as_deref(), scopes.as_deref(), *active).await?;

            match output_config.format {
                OutputFormat::Table => {
                    println!("{}", output::success("API key updated successfully", output_config.color));

                    let key_data = vec![
                        ("Key ID".to_string(), key.id),
                        ("Name".to_string(), key.name),
                        ("User".to_string(), key.user),
                        ("Scopes".to_string(), key.scopes.join(", ")),
                        ("Active".to_string(), key.active.to_string()),
                        ("Updated".to_string(), key.updated_at.unwrap_or_else(|| "N/A".to_string())),
                    ];

                    let table = output::create_kv_table(&key_data, output_config.color);
                    println!("{}", table);
                }
                OutputFormat::Json => {
                    println!("{}", serde_json::to_string_pretty(&key)?);
                }
                OutputFormat::Yaml => {
                    println!("{}", serde_yaml::to_string(&key)?);
                }
                OutputFormat::Compact => {
                    println!("{} {} {}", key.id, key.name, key.active);
                }
            }
        }
        ApiKeyCommands::Show { key_id } => {
            let key = client.get_api_key(key_id).await?;

            match output_config.format {
                OutputFormat::Table => {
                    let key_data = vec![
                        ("Key ID".to_string(), key.id),
                        ("Name".to_string(), key.name),
                        ("User".to_string(), key.user),
                        ("Scopes".to_string(), key.scopes.join(", ")),
                        ("Active".to_string(), key.active.to_string()),
                        ("Created".to_string(), key.created_at),
                        ("Expires".to_string(), key.expires_at.unwrap_or_else(|| "Never".to_string())),
                        ("Last Used".to_string(), key.last_used.unwrap_or_else(|| "Never".to_string())),
                        ("Usage Count".to_string(), key.usage_count.unwrap_or(0).to_string()),
                    ];

                    let table = output::create_kv_table(&key_data, output_config.color);
                    println!("{}", table);
                }
                OutputFormat::Json => {
                    println!("{}", serde_json::to_string_pretty(&key)?);
                }
                OutputFormat::Yaml => {
                    println!("{}", serde_yaml::to_string(&key)?);
                }
                OutputFormat::Compact => {
                    println!("{} {} {} {}", key.id, key.name, key.user, key.active);
                }
            }
        }
        _ => {
            println!("{}", output::info("API key command not yet implemented", output_config.color));
        }
    }

    Ok(())
}