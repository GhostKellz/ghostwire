/// User management command handlers

use anyhow::Result;
use crate::client::GwctlClient;
use crate::commands::UserCommands;
use crate::output::{self, OutputConfig, OutputFormat};
use crate::utils::{validate_username, validate_email, confirm_operation};
use crate::Cli;

pub async fn handle_command(client: &GwctlClient, command: &UserCommands, cli: &Cli) -> Result<()> {
    let output_config = OutputConfig {
        format: cli.output,
        color: !cli.quiet,
        timestamps: false,
    };

    match command {
        UserCommands::List { role, active } => {
            let users = client.list_users(role.as_deref(), *active).await?;

            match output_config.format {
                OutputFormat::Table => {
                    if users.is_empty() {
                        println!("{}", output::info("No users found", output_config.color));
                        return Ok(());
                    }

                    let user_infos: Vec<output::UserInfo> = users.iter().map(|user| {
                        output::UserInfo {
                            id: user.id.clone(),
                            username: user.username.clone(),
                            email: user.email.clone().unwrap_or_else(|| "N/A".to_string()),
                            role: user.role.clone(),
                            active: user.active.to_string(),
                            created_at: user.created_at.clone(),
                            last_login: user.last_login.clone().unwrap_or_else(|| "Never".to_string()),
                        }
                    }).collect();

                    output::display_list(&user_infos, &output_config)?;
                }
                OutputFormat::Json => {
                    println!("{}", serde_json::to_string_pretty(&users)?);
                }
                OutputFormat::Yaml => {
                    println!("{}", serde_yaml::to_string(&users)?);
                }
                OutputFormat::Compact => {
                    for user in &users {
                        println!("{} {} {} {}", user.id, user.username, user.role, user.active);
                    }
                }
            }
        }
        UserCommands::Create { username, email, role, password } => {
            validate_username(username)?;
            if let Some(e) = email {
                validate_email(e)?;
            }

            let user = client.create_user(username, email.as_deref(), role, password.as_deref()).await?;

            match output_config.format {
                OutputFormat::Table => {
                    println!("{}", output::success("User created successfully", output_config.color));

                    let user_data = vec![
                        ("User ID".to_string(), user.id),
                        ("Username".to_string(), user.username),
                        ("Email".to_string(), user.email.unwrap_or_else(|| "N/A".to_string())),
                        ("Role".to_string(), user.role),
                        ("Active".to_string(), user.active.to_string()),
                        ("Created".to_string(), user.created_at),
                    ];

                    let table = output::create_kv_table(&user_data, output_config.color);
                    println!("{}", table);
                }
                OutputFormat::Json => {
                    println!("{}", serde_json::to_string_pretty(&user)?);
                }
                OutputFormat::Yaml => {
                    println!("{}", serde_yaml::to_string(&user)?);
                }
                OutputFormat::Compact => {
                    println!("{} {} {}", user.id, user.username, user.role);
                }
            }
        }
        UserCommands::Delete { user_id, force } => {
            let message = format!("Are you sure you want to delete user '{}'? This action cannot be undone.", user_id);
            if !confirm_operation(&message, *force)? {
                println!("{}", output::info("Operation cancelled", output_config.color));
                return Ok(());
            }

            client.delete_user(user_id).await?;
            println!("{}", output::success("User deleted successfully", output_config.color));
        }
        UserCommands::Update { user_id, email, role, active } => {
            if let Some(e) = email {
                validate_email(e)?;
            }

            let user = client.update_user(user_id, email.as_deref(), role.as_deref(), *active).await?;

            match output_config.format {
                OutputFormat::Table => {
                    println!("{}", output::success("User updated successfully", output_config.color));

                    let user_data = vec![
                        ("User ID".to_string(), user.id),
                        ("Username".to_string(), user.username),
                        ("Email".to_string(), user.email.unwrap_or_else(|| "N/A".to_string())),
                        ("Role".to_string(), user.role),
                        ("Active".to_string(), user.active.to_string()),
                        ("Updated".to_string(), user.updated_at.unwrap_or_else(|| "N/A".to_string())),
                    ];

                    let table = output::create_kv_table(&user_data, output_config.color);
                    println!("{}", table);
                }
                OutputFormat::Json => {
                    println!("{}", serde_json::to_string_pretty(&user)?);
                }
                OutputFormat::Yaml => {
                    println!("{}", serde_yaml::to_string(&user)?);
                }
                OutputFormat::Compact => {
                    println!("{} {} {}", user.id, user.username, user.role);
                }
            }
        }
        UserCommands::Show { user_id } => {
            let user = client.get_user(user_id).await?;

            match output_config.format {
                OutputFormat::Table => {
                    let user_data = vec![
                        ("User ID".to_string(), user.id),
                        ("Username".to_string(), user.username),
                        ("Email".to_string(), user.email.unwrap_or_else(|| "N/A".to_string())),
                        ("Role".to_string(), user.role),
                        ("Active".to_string(), user.active.to_string()),
                        ("Created".to_string(), user.created_at),
                        ("Last Login".to_string(), user.last_login.unwrap_or_else(|| "Never".to_string())),
                        ("Total Nodes".to_string(), user.node_count.unwrap_or(0).to_string()),
                    ];

                    let table = output::create_kv_table(&user_data, output_config.color);
                    println!("{}", table);
                }
                OutputFormat::Json => {
                    println!("{}", serde_json::to_string_pretty(&user)?);
                }
                OutputFormat::Yaml => {
                    println!("{}", serde_yaml::to_string(&user)?);
                }
                OutputFormat::Compact => {
                    println!("{} {} {} {}", user.id, user.username, user.role, user.active);
                }
            }
        }
        _ => {
            println!("{}", output::info("User command not yet implemented", output_config.color));
        }
    }

    Ok(())
}