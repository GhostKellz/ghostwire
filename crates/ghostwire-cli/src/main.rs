/// GhostWire Control CLI (gwctl)
///
/// Unified command-line interface for managing the entire GhostWire mesh VPN system.
/// Provides comprehensive control over servers, clients, networks, and policies.

use clap::{Parser, Subcommand, ValueEnum};
use anyhow::{Context, Result};
use std::path::PathBuf;
use tracing::{info, warn, error, debug};

mod config;
mod client;
mod commands;
mod output;
mod utils;

use client::GwctlClient;
use commands::*;
use config::GwctlConfig;
use output::OutputFormat;

/// GhostWire Control CLI - Unified mesh VPN management
#[derive(Parser)]
#[command(name = "gwctl")]
#[command(about = "GhostWire mesh VPN control CLI")]
#[command(version)]
#[command(long_about = r#"
GwCtl is the unified command-line interface for managing GhostWire mesh VPN networks.

It provides comprehensive control over:
- Server infrastructure and coordination
- Client nodes and connectivity
- Network policies and access control
- DERP relays and routing
- DNS and service discovery
- Authentication and authorization
- Monitoring and observability

Examples:
  gwctl server status                    # Check server health
  gwctl node list                        # List all nodes
  gwctl net create corporate             # Create new network
  gwctl policy apply --file policy.json # Apply ACL policy
  gwctl auth login                       # Authenticate with server
  gwctl derp list --region us-east       # List DERP servers
"#)]
struct Cli {
    /// Configuration file path
    #[arg(long, short, global = true)]
    config: Option<PathBuf>,

    /// Server URL override
    #[arg(long, global = true, env = "GHOSTWIRE_SERVER")]
    server: Option<String>,

    /// API token override
    #[arg(long, global = true, env = "GHOSTWIRE_TOKEN")]
    token: Option<String>,

    /// Output format
    #[arg(long, short, global = true, default_value = "table")]
    output: OutputFormat,

    /// Enable verbose logging
    #[arg(long, short, global = true)]
    verbose: bool,

    /// Enable quiet mode (errors only)
    #[arg(long, short, global = true)]
    quiet: bool,

    /// Skip TLS verification (development only)
    #[arg(long, global = true)]
    insecure: bool,

    /// Timeout in seconds
    #[arg(long, global = true, default_value = "30")]
    timeout: u64,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Server management commands
    #[command(alias = "srv")]
    Server {
        #[command(subcommand)]
        command: ServerCommands,
    },

    /// Node management commands
    #[command(alias = "nodes")]
    Node {
        #[command(subcommand)]
        command: NodeCommands,
    },

    /// Network management commands
    #[command(alias = "net")]
    Network {
        #[command(subcommand)]
        command: NetworkCommands,
    },

    /// Policy management commands
    #[command(alias = "pol")]
    Policy {
        #[command(subcommand)]
        command: PolicyCommands,
    },

    /// Authentication commands
    Auth {
        #[command(subcommand)]
        command: AuthCommands,
    },

    /// DERP relay commands
    Derp {
        #[command(subcommand)]
        command: DerpCommands,
    },

    /// DNS management commands
    Dns {
        #[command(subcommand)]
        command: DnsCommands,
    },

    /// User management commands
    User {
        #[command(subcommand)]
        command: UserCommands,
    },

    /// API key management commands
    ApiKey {
        #[command(subcommand)]
        command: ApiKeyCommands,
    },

    /// Route management commands
    Route {
        #[command(subcommand)]
        command: RouteCommands,
    },

    /// Monitoring and metrics commands
    Monitor {
        #[command(subcommand)]
        command: MonitorCommands,
    },


    /// Debug and troubleshooting commands
    Debug {
        #[command(subcommand)]
        command: DebugCommands,
    },

    /// Generate shell completions
    Completion {
        /// Shell to generate completions for
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },

    /// Update gwctl to latest version
    Update {
        /// Force update even if same version
        #[arg(long)]
        force: bool,

        /// Check for updates without installing
        #[arg(long)]
        check: bool,
    },

    /// Interactive setup wizard
    Setup {
        /// Skip confirmation prompts
        #[arg(long, short)]
        yes: bool,

        /// Setup mode
        #[arg(value_enum, default_value = "client")]
        mode: SetupMode,
    },
}

#[derive(ValueEnum, Clone)]
enum SetupMode {
    /// Setup as client
    Client,
    /// Setup as server
    Server,
    /// Setup development environment
    Dev,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    init_logging(&cli)?;

    // Handle special commands that don't need server connection
    match &cli.command {
        Commands::Completion { shell } => {
            return handle_completion(*shell);
        }
        Commands::Setup { mode, yes } => {
            return setup::run_setup(*mode, *yes).await;
        }
        _ => {}
    }

    // Load configuration
    let config = GwctlConfig::load(cli.config.as_deref()).await
        .context("Failed to load configuration")?;

    // Apply CLI overrides
    let config = apply_cli_overrides(config, &cli);

    // Initialize client
    let client = GwctlClient::new(config).await
        .context("Failed to initialize client")?;

    // Execute command
    let result = execute_command(&client, &cli.command, &cli).await;

    // Handle result and exit
    match result {
        Ok(_) => {
            debug!("Command completed successfully");
            Ok(())
        }
        Err(e) => {
            error!("Command failed: {}", e);
            std::process::exit(1);
        }
    }
}

fn init_logging(cli: &Cli) -> Result<()> {
    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

    let level = if cli.quiet {
        "error"
    } else if cli.verbose {
        "debug"
    } else {
        "info"
    };

    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(level));

    tracing_subscriber::registry()
        .with(env_filter)
        .with(tracing_subscriber::fmt::layer()
            .with_target(false)
            .with_level(true)
            .compact())
        .init();

    Ok(())
}

fn apply_cli_overrides(mut config: GwctlConfig, cli: &Cli) -> GwctlConfig {
    if let Some(server) = &cli.server {
        config.server.url = server.clone();
    }
    if let Some(token) = &cli.token {
        config.auth.token = Some(token.clone());
    }
    if cli.insecure {
        config.server.verify_tls = false;
    }
    config.server.timeout_seconds = cli.timeout;
    config.output.format = cli.output;
    config
}

async fn execute_command(client: &GwctlClient, command: &Commands, cli: &Cli) -> Result<()> {
    match command {
        Commands::Server { command } => {
            server::handle_command(client, command, cli).await
        }
        Commands::Node { command } => {
            node::handle_command(client, command, cli).await
        }
        Commands::Network { command } => {
            network::handle_command(client, command, cli).await
        }
        Commands::Policy { command } => {
            policy::handle_command(client, command, cli).await
        }
        Commands::Auth { command } => {
            auth::handle_command(client, command, cli).await
        }
        Commands::Derp { command } => {
            derp::handle_command(client, command, cli).await
        }
        Commands::Dns { command } => {
            dns::handle_command(client, command, cli).await
        }
        Commands::User { command } => {
            user::handle_command(client, command, cli).await
        }
        Commands::ApiKey { command } => {
            apikey::handle_command(client, command, cli).await
        }
        Commands::Route { command } => {
            route::handle_command(client, command, cli).await
        }
        Commands::Monitor { command } => {
            monitor::handle_command(client, command, cli).await
        }
        Commands::Debug { command } => {
            debug::handle_command(client, command, cli).await
        }
        Commands::Update { force, check } => {
            update::handle_update(*force, *check).await
        }
        Commands::Completion { .. } | Commands::Setup { .. } => {
            // These are handled earlier
            Ok(())
        }
    }
}

fn handle_completion(shell: clap_complete::Shell) -> Result<()> {
    use clap_complete::{generate, Generator};
    use std::io;

    fn print_completions<G: Generator>(gen: G, cmd: &mut clap::Command) {
        generate(gen, cmd, cmd.get_name().to_string(), &mut io::stdout());
    }

    let mut cmd = Cli::command();
    print_completions(shell, &mut cmd);
    Ok(())
}

// Module for setup wizard
mod setup {
    use super::*;
    use dialoguer::{Confirm, Input, Select};
    use std::fs;

    pub async fn run_setup(mode: SetupMode, yes: bool) -> Result<()> {
        println!("🚀 GhostWire Setup Wizard");
        println!();

        match mode {
            SetupMode::Client => setup_client(yes).await,
            SetupMode::Server => setup_server(yes).await,
            SetupMode::Dev => setup_development(yes).await,
        }
    }

    async fn setup_client(yes: bool) -> Result<()> {
        println!("Setting up GhostWire client...");

        let server_url = if yes {
            "https://ghostwire.example.com".to_string()
        } else {
            Input::<String>::new()
                .with_prompt("GhostWire server URL")
                .default("https://ghostwire.example.com".to_string())
                .interact_text()?
        };

        let use_auth = if yes {
            true
        } else {
            Confirm::new()
                .with_prompt("Enable authentication?")
                .default(true)
                .interact()?
        };

        // Create basic client config
        let config = GwctlConfig {
            server: config::ServerConfig {
                url: server_url,
                verify_tls: true,
                timeout_seconds: 30,
            },
            auth: config::AuthConfig {
                enabled: use_auth,
                method: if use_auth { "oauth".to_string() } else { "none".to_string() },
                token: None,
                store_token: true,
            },
            output: config::OutputConfig {
                format: OutputFormat::Table,
                color: true,
                timestamps: false,
            },
        };

        // Save config
        config.save(None).await?;

        println!("✅ Client configuration saved");
        println!("📝 Run 'gwctl auth login' to authenticate");

        Ok(())
    }

    async fn setup_server(yes: bool) -> Result<()> {
        println!("Setting up GhostWire server...");

        // This would guide through server setup
        println!("🔧 Server setup not yet implemented");
        println!("📖 Please refer to the server documentation");

        Ok(())
    }

    async fn setup_development(yes: bool) -> Result<()> {
        println!("Setting up GhostWire development environment...");

        // This would set up local development environment
        println!("🔧 Development setup not yet implemented");
        println!("📖 Please refer to the development documentation");

        Ok(())
    }
}

// Module for update functionality
mod update {
    use super::*;

    pub async fn handle_update(force: bool, check: bool) -> Result<()> {
        if check {
            check_for_updates().await
        } else {
            perform_update(force).await
        }
    }

    async fn check_for_updates() -> Result<()> {
        println!("🔍 Checking for updates...");

        // This would check GitHub releases or update server
        println!("ℹ️  You are running the latest version of gwctl");

        Ok(())
    }

    async fn perform_update(force: bool) -> Result<()> {
        println!("⬇️  Downloading latest version...");

        // This would download and install the latest version
        println!("🔧 Update functionality not yet implemented");
        println!("📝 Please download the latest release manually");

        Ok(())
    }
}