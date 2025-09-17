/// Authentication command handlers
///
/// Handles login, logout, and authentication status operations.

use anyhow::Result;
use dialoguer::{Input, Password, Confirm};
use std::time::Duration;
use tokio::time::{interval, timeout};
use tracing::{debug, info};

use crate::client::GwctlClient;
use crate::commands::AuthCommands;
use crate::config::GwctlConfig;
use crate::output::{self, OutputConfig, OutputFormat, ProgressIndicator};
use crate::Cli;

pub async fn handle_command(client: &GwctlClient, command: &AuthCommands, cli: &Cli) -> Result<()> {
    match command {
        AuthCommands::Login { username, oauth, api_key } => {
            handle_login(client, username, *oauth, api_key, cli).await
        }
        AuthCommands::Logout => {
            handle_logout(client, cli).await
        }
        AuthCommands::Status => {
            handle_status(client, cli).await
        }
        AuthCommands::Refresh => {
            handle_refresh(client, cli).await
        }
    }
}

async fn handle_login(
    client: &GwctlClient,
    username: &Option<String>,
    oauth: bool,
    api_key: &Option<String>,
    cli: &Cli,
) -> Result<()> {
    let output_config = OutputConfig {
        format: cli.output,
        color: !cli.quiet,
        timestamps: false,
    };

    if let Some(key) = api_key {
        // API key authentication
        return handle_api_key_auth(key, &output_config).await;
    }

    if oauth {
        // OAuth device flow
        return handle_oauth_login(client, &output_config).await;
    }

    // Username/password authentication
    handle_password_login(client, username, &output_config).await
}

async fn handle_password_login(
    client: &GwctlClient,
    username: &Option<String>,
    config: &OutputConfig,
) -> Result<()> {
    let username = match username {
        Some(u) => u.clone(),
        None => {
            Input::<String>::new()
                .with_prompt("Username")
                .interact_text()?
        }
    };

    let password = Password::new()
        .with_prompt("Password")
        .interact()?;

    let spinner = ProgressIndicator::new("Authenticating...");

    match client.authenticate(&username, &password).await {
        Ok(auth_response) => {
            spinner.finish_with_message("Authentication successful");

            // Store token in configuration
            let mut gwctl_config = GwctlConfig::load(None).await.unwrap_or_default();
            gwctl_config.auth.token = Some(auth_response.token);
            gwctl_config.save(None).await?;

            match config.format {
                OutputFormat::Table => {
                    println!("{}", output::success("Successfully logged in", config.color));
                    println!();

                    let user_data = vec![
                        ("User ID".to_string(), auth_response.user.id),
                        ("Username".to_string(), auth_response.user.username),
                        ("Email".to_string(), auth_response.user.email.unwrap_or_else(|| "N/A".to_string())),
                        ("Role".to_string(), auth_response.user.role),
                        ("Token Expires".to_string(), auth_response.expires_at),
                    ];

                    let table = output::create_kv_table(&user_data, config.color);
                    println!("{}", table);
                }
                OutputFormat::Json => {
                    println!("{}", serde_json::to_string_pretty(&auth_response)?);
                }
                OutputFormat::Yaml => {
                    println!("{}", serde_yaml::to_string(&auth_response)?);
                }
                OutputFormat::Compact => {
                    println!("{} {}", auth_response.user.username, auth_response.user.role);
                }
            }
        }
        Err(e) => {
            spinner.finish();
            return Err(anyhow::anyhow!("Authentication failed: {}", e));
        }
    }

    Ok(())
}

async fn handle_oauth_login(client: &GwctlClient, config: &OutputConfig) -> Result<()> {
    let spinner = ProgressIndicator::new("Starting OAuth device flow...");

    // Initialize device flow
    let device_response = client.oauth_device_init().await?;
    spinner.finish();

    match config.format {
        OutputFormat::Table => {
            println!("{}", output::info("OAuth Device Flow Authentication", config.color));
            println!();
            println!("1. Open this URL in your browser:");
            println!("   {}", device_response.verification_uri.bold());
            println!();
            println!("2. Enter this code:");
            println!("   {}", device_response.user_code.bold());
            println!();

            if let Some(complete_uri) = &device_response.verification_uri_complete {
                println!("Or open this direct link:");
                println!("   {}", complete_uri);
                println!();
            }

            // Generate QR code if possible
            if let Ok(qr) = qrcode::QrCode::new(&device_response.verification_uri) {
                use qrcode::render::unicode;
                let image = qr.render::<unicode::Dense1x2>()
                    .dark_color(unicode::Dense1x2::Light)
                    .light_color(unicode::Dense1x2::Dark)
                    .build();
                println!("QR Code:");
                println!("{}", image);
                println!();
            }
        }
        _ => {
            // For non-table formats, just output the essential info
            println!("URL: {}", device_response.verification_uri);
            println!("Code: {}", device_response.user_code);
        }
    }

    // Poll for completion
    let poll_spinner = ProgressIndicator::new("Waiting for authentication...");
    let mut poll_interval = interval(Duration::from_secs(device_response.interval));
    let auth_timeout = Duration::from_secs(device_response.expires_in);

    let auth_result = timeout(auth_timeout, async {
        loop {
            poll_interval.tick().await;

            match client.oauth_device_poll(&device_response.device_code).await {
                Ok(auth_response) => {
                    poll_spinner.finish_with_message("Authentication successful");

                    // Store token
                    let mut gwctl_config = GwctlConfig::load(None).await.unwrap_or_default();
                    gwctl_config.auth.token = Some(auth_response.token);
                    gwctl_config.save(None).await?;

                    return Ok(auth_response);
                }
                Err(_) => {
                    // Continue polling (most errors are expected during polling)
                    continue;
                }
            }
        }
    }).await;

    match auth_result {
        Ok(Ok(auth_response)) => {
            println!("{}", output::success("Successfully logged in via OAuth", config.color));

            if matches!(config.format, OutputFormat::Table) {
                let user_data = vec![
                    ("User ID".to_string(), auth_response.user.id),
                    ("Username".to_string(), auth_response.user.username),
                    ("Email".to_string(), auth_response.user.email.unwrap_or_else(|| "N/A".to_string())),
                    ("Role".to_string(), auth_response.user.role),
                ];

                let table = output::create_kv_table(&user_data, config.color);
                println!("{}", table);
            }

            Ok(())
        }
        Ok(Err(e)) => Err(e),
        Err(_) => {
            poll_spinner.finish();
            Err(anyhow::anyhow!("Authentication timeout"))
        }
    }
}

async fn handle_api_key_auth(api_key: &str, config: &OutputConfig) -> Result<()> {
    // Store API key in configuration
    let mut gwctl_config = GwctlConfig::load(None).await.unwrap_or_default();
    gwctl_config.auth.token = Some(api_key.to_string());
    gwctl_config.auth.method = "api-key".to_string();
    gwctl_config.save(None).await?;

    println!("{}", output::success("API key configured successfully", config.color));
    println!("{}", output::info("Run 'gwctl auth status' to verify authentication", config.color));

    Ok(())
}

async fn handle_logout(_client: &GwctlClient, cli: &Cli) -> Result<()> {
    let output_config = OutputConfig {
        format: cli.output,
        color: !cli.quiet,
        timestamps: false,
    };

    // Clear stored authentication
    let mut config = GwctlConfig::load(None).await.unwrap_or_default();
    config.auth.token = None;
    config.save(None).await?;

    // Also clear from keyring if applicable
    if let Ok(keyring) = keyring::Entry::new("gwctl", "auth_token") {
        let _ = keyring.delete_password(); // Ignore errors
    }

    println!("{}", output::success("Successfully logged out", output_config.color));

    Ok(())
}

async fn handle_status(client: &GwctlClient, cli: &Cli) -> Result<()> {
    let output_config = OutputConfig {
        format: cli.output,
        color: !cli.quiet,
        timestamps: false,
    };

    let config = GwctlConfig::load(None).await.unwrap_or_default();

    if config.auth.token.is_none() {
        match output_config.format {
            OutputFormat::Table => {
                println!("{}", output::warning("Not authenticated", output_config.color));
                println!("{}", output::info("Run 'gwctl auth login' to authenticate", output_config.color));
            }
            OutputFormat::Json => {
                let status = serde_json::json!({
                    "authenticated": false,
                    "method": null,
                    "user": null
                });
                println!("{}", serde_json::to_string_pretty(&status)?);
            }
            OutputFormat::Yaml => {
                let status = serde_json::json!({
                    "authenticated": false,
                    "method": null,
                    "user": null
                });
                println!("{}", serde_yaml::to_string(&status)?);
            }
            OutputFormat::Compact => {
                println!("false");
            }
        }
        return Ok(());
    }

    // Validate token with server
    match client.validate_token().await {
        Ok(validation) => {
            match output_config.format {
                OutputFormat::Table => {
                    println!("{}", output::success("Authenticated", output_config.color));
                    println!();

                    let mut auth_data = vec![
                        ("Method".to_string(), config.auth.method),
                        ("Valid".to_string(), validation.valid.to_string()),
                    ];

                    if let Some(user) = &validation.user {
                        auth_data.extend(vec![
                            ("User ID".to_string(), user.id.clone()),
                            ("Username".to_string(), user.username.clone()),
                            ("Email".to_string(), user.email.clone().unwrap_or_else(|| "N/A".to_string())),
                            ("Role".to_string(), user.role.clone()),
                        ]);
                    }

                    if let Some(expires_at) = &validation.expires_at {
                        auth_data.push(("Expires".to_string(), expires_at.clone()));
                    }

                    let table = output::create_kv_table(&auth_data, output_config.color);
                    println!("{}", table);
                }
                OutputFormat::Json => {
                    let status = serde_json::json!({
                        "authenticated": true,
                        "method": config.auth.method,
                        "valid": validation.valid,
                        "user": validation.user,
                        "expires_at": validation.expires_at
                    });
                    println!("{}", serde_json::to_string_pretty(&status)?);
                }
                OutputFormat::Yaml => {
                    let status = serde_json::json!({
                        "authenticated": true,
                        "method": config.auth.method,
                        "valid": validation.valid,
                        "user": validation.user,
                        "expires_at": validation.expires_at
                    });
                    println!("{}", serde_yaml::to_string(&status)?);
                }
                OutputFormat::Compact => {
                    println!("true {}", validation.valid);
                }
            }
        }
        Err(e) => {
            match output_config.format {
                OutputFormat::Table => {
                    println!("{}", output::error(&format!("Authentication invalid: {}", e), output_config.color));
                    println!("{}", output::info("Run 'gwctl auth login' to re-authenticate", output_config.color));
                }
                _ => {
                    let status = serde_json::json!({
                        "authenticated": false,
                        "error": e.to_string()
                    });
                    match output_config.format {
                        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&status)?),
                        OutputFormat::Yaml => println!("{}", serde_yaml::to_string(&status)?),
                        OutputFormat::Compact => println!("false"),
                        _ => {}
                    }
                }
            }
        }
    }

    Ok(())
}

async fn handle_refresh(client: &GwctlClient, cli: &Cli) -> Result<()> {
    let output_config = OutputConfig {
        format: cli.output,
        color: !cli.quiet,
        timestamps: false,
    };

    // For now, just validate the current token
    // In a real implementation, this would refresh OAuth tokens
    match client.validate_token().await {
        Ok(validation) => {
            if validation.valid {
                println!("{}", output::success("Authentication token is still valid", output_config.color));
            } else {
                println!("{}", output::warning("Authentication token is invalid", output_config.color));
                println!("{}", output::info("Run 'gwctl auth login' to re-authenticate", output_config.color));
            }
        }
        Err(e) => {
            return Err(anyhow::anyhow!("Failed to validate token: {}", e));
        }
    }

    Ok(())
}

// Helper trait for colored text
use colored::Colorize;

trait ColoredExt {
    fn bold(&self) -> colored::ColoredString;
}

impl ColoredExt for str {
    fn bold(&self) -> colored::ColoredString {
        self.bold()
    }
}