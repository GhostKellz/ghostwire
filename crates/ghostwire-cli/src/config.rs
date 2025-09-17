/// Configuration management for gwctl
///
/// Handles loading, saving, and managing gwctl configuration including
/// server connections, authentication, and output preferences.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tokio::fs;
use tracing::{debug, info};

use crate::output::OutputFormat;

/// Complete gwctl configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GwctlConfig {
    /// Server connection configuration
    pub server: ServerConfig,

    /// Authentication configuration
    pub auth: AuthConfig,

    /// Output formatting configuration
    pub output: OutputConfig,
}

impl Default for GwctlConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig::default(),
            auth: AuthConfig::default(),
            output: OutputConfig::default(),
        }
    }
}

impl GwctlConfig {
    /// Load configuration from file or create default
    pub async fn load(config_path: Option<&Path>) -> Result<Self> {
        let path = match config_path {
            Some(p) => p.to_path_buf(),
            None => Self::default_config_path()?,
        };

        if path.exists() {
            debug!("Loading configuration from {}", path.display());
            let content = fs::read_to_string(&path).await
                .with_context(|| format!("Failed to read config file: {}", path.display()))?;

            let config: GwctlConfig = if path.extension().and_then(|s| s.to_str()) == Some("toml") {
                toml::from_str(&content)?
            } else {
                serde_yaml::from_str(&content)?
            };

            debug!("Configuration loaded successfully");
            Ok(config)
        } else {
            info!("No configuration file found, using defaults");
            Ok(Self::default())
        }
    }

    /// Save configuration to file
    pub async fn save(&self, config_path: Option<&Path>) -> Result<()> {
        let path = match config_path {
            Some(p) => p.to_path_buf(),
            None => Self::default_config_path()?,
        };

        // Create parent directory if it doesn't exist
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).await
                .with_context(|| format!("Failed to create config directory: {}", parent.display()))?;
        }

        let content = if path.extension().and_then(|s| s.to_str()) == Some("toml") {
            toml::to_string_pretty(self)?
        } else {
            serde_yaml::to_string(self)?
        };

        fs::write(&path, content).await
            .with_context(|| format!("Failed to write config file: {}", path.display()))?;

        info!("Configuration saved to {}", path.display());
        Ok(())
    }

    /// Get default configuration file path
    pub fn default_config_path() -> Result<PathBuf> {
        let config_dir = directories::ProjectDirs::from("com", "ghostwire", "gwctl")
            .context("Failed to determine config directory")?
            .config_dir()
            .to_path_buf();

        Ok(config_dir.join("config.yaml"))
    }

    /// Get credentials storage path
    pub fn credentials_path() -> Result<PathBuf> {
        let config_dir = directories::ProjectDirs::from("com", "ghostwire", "gwctl")
            .context("Failed to determine config directory")?
            .config_dir()
            .to_path_buf();

        Ok(config_dir.join("credentials.json"))
    }
}

/// Server connection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Server URL
    pub url: String,

    /// Enable TLS verification
    pub verify_tls: bool,

    /// Connection timeout in seconds
    pub timeout_seconds: u64,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            url: "https://ghostwire.example.com".to_string(),
            verify_tls: true,
            timeout_seconds: 30,
        }
    }
}

/// Authentication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    /// Enable authentication
    pub enabled: bool,

    /// Authentication method
    pub method: String,

    /// Stored authentication token
    pub token: Option<String>,

    /// Store token persistently
    pub store_token: bool,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            method: "oauth".to_string(),
            token: None,
            store_token: true,
        }
    }
}

/// Output formatting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputConfig {
    /// Default output format
    pub format: OutputFormat,

    /// Enable color output
    pub color: bool,

    /// Show timestamps in output
    pub timestamps: bool,
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            format: OutputFormat::Table,
            color: true,
            timestamps: false,
        }
    }
}

/// Initialize configuration with interactive prompts
pub async fn init_config() -> Result<()> {
    use dialoguer::{Confirm, Input, Select};

    println!("🔧 Initializing gwctl configuration");
    println!();

    // Get server URL
    let server_url: String = Input::new()
        .with_prompt("GhostWire server URL")
        .default("https://ghostwire.example.com".to_string())
        .interact_text()?;

    // Get authentication preference
    let auth_enabled = Confirm::new()
        .with_prompt("Enable authentication")
        .default(true)
        .interact()?;

    let auth_method = if auth_enabled {
        let methods = vec!["oauth", "api-key", "certificate"];
        let selection = Select::new()
            .with_prompt("Authentication method")
            .items(&methods)
            .default(0)
            .interact()?;
        methods[selection].to_string()
    } else {
        "none".to_string()
    };

    // Get output format preference
    let formats = vec!["table", "json", "yaml"];
    let format_selection = Select::new()
        .with_prompt("Default output format")
        .items(&formats)
        .default(0)
        .interact()?;

    let output_format = match formats[format_selection] {
        "table" => OutputFormat::Table,
        "json" => OutputFormat::Json,
        "yaml" => OutputFormat::Yaml,
        _ => OutputFormat::Table,
    };

    // Create configuration
    let config = GwctlConfig {
        server: ServerConfig {
            url: server_url,
            verify_tls: true,
            timeout_seconds: 30,
        },
        auth: AuthConfig {
            enabled: auth_enabled,
            method: auth_method,
            token: None,
            store_token: true,
        },
        output: OutputConfig {
            format: output_format,
            color: true,
            timestamps: false,
        },
    };

    // Save configuration
    config.save(None).await?;

    println!();
    println!("✅ Configuration initialized successfully");
    println!("📁 Config saved to: {}", GwctlConfig::default_config_path()?.display());

    if config.auth.enabled && config.auth.method != "none" {
        println!("🔐 Run 'gwctl auth login' to authenticate");
    }

    Ok(())
}

/// Configuration management commands
use clap::Subcommand;

#[derive(Subcommand)]
pub enum ConfigCommands {
    /// Initialize configuration with interactive prompts
    Init {
        /// Force initialization even if config exists
        #[arg(long)]
        force: bool,
    },

    /// Show current configuration
    Show {
        /// Show configuration file path
        #[arg(long)]
        path: bool,

        /// Show sensitive values (tokens, etc.)
        #[arg(long)]
        show_secrets: bool,
    },

    /// Edit configuration file
    Edit {
        /// Editor to use (defaults to $EDITOR)
        #[arg(long)]
        editor: Option<String>,
    },

    /// Validate configuration file
    Validate {
        /// Configuration file to validate
        #[arg(long)]
        file: Option<PathBuf>,
    },

    /// Reset configuration to defaults
    Reset {
        /// Skip confirmation prompt
        #[arg(long, short)]
        yes: bool,
    },

    /// Set configuration value
    Set {
        /// Configuration key (e.g., server.url)
        key: String,

        /// Configuration value
        value: String,
    },

    /// Get configuration value
    Get {
        /// Configuration key (e.g., server.url)
        key: String,
    },

    /// Export configuration to file
    Export {
        /// Output file path
        #[arg(long, short)]
        output: PathBuf,

        /// Output format
        #[arg(long, value_enum, default_value = "yaml")]
        format: ExportFormat,

        /// Include sensitive values
        #[arg(long)]
        include_secrets: bool,
    },

    /// Import configuration from file
    Import {
        /// Input file path
        file: PathBuf,

        /// Merge with existing config instead of replacing
        #[arg(long)]
        merge: bool,
    },
}

#[derive(clap::ValueEnum, Clone)]
pub enum ExportFormat {
    Yaml,
    Json,
    Toml,
}

pub async fn handle_command(
    _client: &crate::client::GwctlClient,
    command: &ConfigCommands,
    _cli: &crate::Cli,
) -> Result<()> {
    match command {
        ConfigCommands::Init { force } => {
            let config_path = GwctlConfig::default_config_path()?;
            if config_path.exists() && !force {
                anyhow::bail!("Configuration already exists. Use --force to overwrite.");
            }
            init_config().await
        }

        ConfigCommands::Show { path, show_secrets } => {
            if *path {
                println!("{}", GwctlConfig::default_config_path()?.display());
                return Ok(());
            }

            let config = GwctlConfig::load(None).await?;
            let mut config_to_show = config.clone();

            if !show_secrets {
                config_to_show.auth.token = config_to_show.auth.token.map(|_| "***".to_string());
            }

            let output = serde_yaml::to_string(&config_to_show)?;
            println!("{}", output);
            Ok(())
        }

        ConfigCommands::Edit { editor } => {
            let config_path = GwctlConfig::default_config_path()?;
            let editor_cmd = editor.clone()
                .or_else(|| std::env::var("EDITOR").ok())
                .unwrap_or_else(|| "vi".to_string());

            let status = std::process::Command::new(&editor_cmd)
                .arg(&config_path)
                .status()?;

            if !status.success() {
                anyhow::bail!("Editor exited with non-zero status");
            }

            Ok(())
        }

        ConfigCommands::Validate { file } => {
            let path = file.as_deref();
            match GwctlConfig::load(path).await {
                Ok(_) => {
                    println!("✅ Configuration is valid");
                    Ok(())
                }
                Err(e) => {
                    println!("❌ Configuration is invalid: {}", e);
                    std::process::exit(1);
                }
            }
        }

        ConfigCommands::Reset { yes } => {
            if !yes {
                use dialoguer::Confirm;
                let confirmed = Confirm::new()
                    .with_prompt("Reset configuration to defaults?")
                    .default(false)
                    .interact()?;

                if !confirmed {
                    println!("Operation cancelled");
                    return Ok(());
                }
            }

            let config = GwctlConfig::default();
            config.save(None).await?;
            println!("✅ Configuration reset to defaults");
            Ok(())
        }

        ConfigCommands::Set { key, value } => {
            let mut config = GwctlConfig::load(None).await?;

            // Simple key-value setting (would need more sophisticated implementation)
            match key.as_str() {
                "server.url" => config.server.url = value.clone(),
                "auth.enabled" => config.auth.enabled = value.parse()?,
                "auth.method" => config.auth.method = value.clone(),
                "output.format" => {
                    config.output.format = match value.as_str() {
                        "table" => OutputFormat::Table,
                        "json" => OutputFormat::Json,
                        "yaml" => OutputFormat::Yaml,
                        _ => anyhow::bail!("Invalid output format: {}", value),
                    };
                }
                _ => anyhow::bail!("Unknown configuration key: {}", key),
            }

            config.save(None).await?;
            println!("✅ Configuration updated: {} = {}", key, value);
            Ok(())
        }

        ConfigCommands::Get { key } => {
            let config = GwctlConfig::load(None).await?;

            let value = match key.as_str() {
                "server.url" => config.server.url,
                "auth.enabled" => config.auth.enabled.to_string(),
                "auth.method" => config.auth.method,
                "output.format" => format!("{:?}", config.output.format).to_lowercase(),
                _ => anyhow::bail!("Unknown configuration key: {}", key),
            };

            println!("{}", value);
            Ok(())
        }

        ConfigCommands::Export { output, format, include_secrets } => {
            let config = GwctlConfig::load(None).await?;
            let mut config_to_export = config.clone();

            if !include_secrets {
                config_to_export.auth.token = None;
            }

            let content = match format {
                ExportFormat::Yaml => serde_yaml::to_string(&config_to_export)?,
                ExportFormat::Json => serde_json::to_string_pretty(&config_to_export)?,
                ExportFormat::Toml => toml::to_string_pretty(&config_to_export)?,
            };

            fs::write(output, content).await?;
            println!("✅ Configuration exported to {}", output.display());
            Ok(())
        }

        ConfigCommands::Import { file, merge } => {
            let content = fs::read_to_string(file).await?;
            let imported_config: GwctlConfig = if file.extension().and_then(|s| s.to_str()) == Some("toml") {
                toml::from_str(&content)?
            } else if file.extension().and_then(|s| s.to_str()) == Some("json") {
                serde_json::from_str(&content)?
            } else {
                serde_yaml::from_str(&content)?
            };

            let final_config = if *merge {
                // Simple merge - would need more sophisticated implementation
                let mut existing = GwctlConfig::load(None).await.unwrap_or_default();
                existing.server = imported_config.server;
                existing.auth.enabled = imported_config.auth.enabled;
                existing.auth.method = imported_config.auth.method;
                existing.output = imported_config.output;
                existing
            } else {
                imported_config
            };

            final_config.save(None).await?;
            println!("✅ Configuration imported from {}", file.display());
            Ok(())
        }
    }
}