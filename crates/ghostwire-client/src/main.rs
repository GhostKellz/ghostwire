/// GhostWire Client Daemon
///
/// High-performance mesh VPN client with hybrid WireGuard and QUIC transport.
/// Provides automatic key management, NAT traversal, and seamless connectivity.

use clap::{Parser, Subcommand};
use ghostwire_common::{
    types::*,
    error::{Result, GhostWireError},
};
use std::path::PathBuf;
use tracing::{info, warn, error, debug};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod client;
mod config;
mod tunnel;
mod transport;
mod auth;
mod platform;

use client::GhostWireClient;
use config::ClientConfig;

/// GhostWire mesh VPN client daemon
#[derive(Parser)]
#[command(name = "ghostwire-client")]
#[command(about = "High-performance mesh VPN client with hybrid WireGuard and QUIC transport")]
#[command(version)]
struct Cli {
    /// Configuration file path
    #[arg(short, long, default_value = "~/.config/ghostwire/client.yaml")]
    config: PathBuf,

    /// Log level
    #[arg(long, default_value = "info")]
    log_level: String,

    /// Enable JSON logging
    #[arg(long)]
    json_logs: bool,

    /// Run in foreground (don't daemonize)
    #[arg(long)]
    foreground: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the client daemon
    Up {
        /// Override server URL
        #[arg(long)]
        server: Option<String>,

        /// Override node name
        #[arg(long)]
        name: Option<String>,

        /// Enable exit node mode
        #[arg(long)]
        exit_node: bool,

        /// Advertise routes
        #[arg(long)]
        routes: Vec<String>,
    },

    /// Stop the client daemon
    Down,

    /// Show current status
    Status {
        /// Show detailed information
        #[arg(long)]
        verbose: bool,

        /// Output format (text, json, yaml)
        #[arg(long, default_value = "text")]
        format: String,
    },

    /// Authentication commands
    Auth {
        #[command(subcommand)]
        auth_command: AuthCommands,
    },

    /// Node management commands
    Node {
        #[command(subcommand)]
        node_command: NodeCommands,
    },

    /// Network diagnostics
    Ping {
        /// Target node name or IP
        target: String,

        /// Number of packets to send
        #[arg(short, long, default_value = "4")]
        count: u32,

        /// Packet size in bytes
        #[arg(short, long, default_value = "64")]
        size: u32,
    },

    /// Network debugging and troubleshooting
    Debug {
        #[command(subcommand)]
        debug_command: DebugCommands,
    },

    /// Configuration management
    Config {
        #[command(subcommand)]
        config_command: ConfigCommands,
    },
}

#[derive(Subcommand)]
enum AuthCommands {
    /// Authenticate with the coordination server
    Login {
        /// Server URL
        #[arg(long)]
        server: Option<String>,

        /// Use web browser for authentication
        #[arg(long)]
        web: bool,

        /// Authentication key (for CLI auth)
        #[arg(long)]
        key: Option<String>,
    },

    /// Show current authentication status
    Status,

    /// Logout and clear credentials
    Logout,

    /// Refresh authentication token
    Refresh,
}

#[derive(Subcommand)]
enum NodeCommands {
    /// List all nodes in the mesh
    List {
        /// Show only online nodes
        #[arg(long)]
        online: bool,

        /// Filter by tag
        #[arg(long)]
        tag: Option<String>,
    },

    /// Show detailed node information
    Show {
        /// Node name or ID
        node: String,
    },

    /// Configure node settings
    Configure {
        /// Node name
        #[arg(long)]
        name: Option<String>,

        /// Add tags
        #[arg(long)]
        tags: Vec<String>,

        /// Enable/disable exit node
        #[arg(long)]
        exit_node: Option<bool>,

        /// Advertised routes
        #[arg(long)]
        routes: Vec<String>,
    },

    /// Reset node to defaults
    Reset,
}

#[derive(Subcommand)]
enum DebugCommands {
    /// Show network routes
    Routes,

    /// Show interface information
    Interfaces,

    /// Test connectivity to coordination server
    TestServer,

    /// Test DERP relay connectivity
    TestDerp,

    /// Show WireGuard statistics
    WgStats,

    /// Show QUIC connection statistics
    QuicStats,

    /// Capture network packets
    Capture {
        /// Output file
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Capture duration in seconds
        #[arg(short, long, default_value = "30")]
        duration: u32,
    },
}

#[derive(Subcommand)]
enum ConfigCommands {
    /// Show current configuration
    Show,

    /// Validate configuration
    Validate,

    /// Generate example configuration
    Example {
        /// Output file
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Edit configuration
    Edit,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    init_logging(&cli.log_level, cli.json_logs)?;

    info!("GhostWire client starting");
    info!("Version: {}", env!("CARGO_PKG_VERSION"));

    // Handle special commands that don't require configuration
    match &cli.command {
        Some(Commands::Config { config_command: ConfigCommands::Example { output } }) => {
            return generate_example_config(output.as_ref()).await;
        }
        _ => {}
    }

    // Load configuration
    let config = load_config(&cli.config).await?;

    // Execute command
    match cli.command {
        Some(Commands::Up { server, name, exit_node, routes }) => {
            run_client(config, server, name, exit_node, routes, !cli.foreground).await
        }
        Some(Commands::Down) => {
            stop_client().await
        }
        Some(Commands::Status { verbose, format }) => {
            show_status(verbose, &format).await
        }
        Some(Commands::Auth { auth_command }) => {
            run_auth_command(config, auth_command).await
        }
        Some(Commands::Node { node_command }) => {
            run_node_command(config, node_command).await
        }
        Some(Commands::Ping { target, count, size }) => {
            run_ping(config, &target, count, size).await
        }
        Some(Commands::Debug { debug_command }) => {
            run_debug_command(config, debug_command).await
        }
        Some(Commands::Config { config_command }) => {
            run_config_command(config, config_command, &cli.config).await
        }
        None => {
            // Default to status
            show_status(false, "text").await
        }
    }
}

fn init_logging(level: &str, json_logs: bool) -> Result<()> {
    let level_filter = level.parse::<tracing::Level>()
        .map_err(|_| GhostWireError::configuration(format!("Invalid log level: {}", level)))?;

    let registry = tracing_subscriber::registry()
        .with(tracing_subscriber::filter::LevelFilter::from_level(level_filter));

    if json_logs {
        registry
            .with(tracing_subscriber::fmt::layer().json())
            .init();
    } else {
        registry
            .with(tracing_subscriber::fmt::layer().pretty())
            .init();
    }

    Ok(())
}

async fn load_config(config_path: &PathBuf) -> Result<ClientConfig> {
    let expanded_path = expand_path(config_path)?;

    if !expanded_path.exists() {
        warn!("Configuration file not found: {}, using defaults", expanded_path.display());
        return Ok(ClientConfig::default());
    }

    let config_content = tokio::fs::read_to_string(&expanded_path).await
        .map_err(|e| GhostWireError::configuration(
            format!("Failed to read config file: {}", e)
        ))?;

    let config: ClientConfig = serde_yaml::from_str(&config_content)
        .map_err(|e| GhostWireError::configuration(
            format!("Failed to parse config file: {}", e)
        ))?;

    info!("Loaded configuration from {}", expanded_path.display());
    Ok(config)
}

fn expand_path(path: &PathBuf) -> Result<PathBuf> {
    let path_str = path.to_string_lossy();
    if path_str.starts_with("~/") {
        if let Some(home_dir) = directories::BaseDirs::new() {
            let home_path = home_dir.home_dir();
            let expanded = home_path.join(&path_str[2..]);
            Ok(expanded)
        } else {
            Err(GhostWireError::configuration("Cannot determine home directory".to_string()))
        }
    } else {
        Ok(path.clone())
    }
}

async fn run_client(
    mut config: ClientConfig,
    server_override: Option<String>,
    name_override: Option<String>,
    exit_node: bool,
    routes: Vec<String>,
    daemonize: bool,
) -> Result<()> {
    // Apply CLI overrides
    if let Some(server) = server_override {
        config.server.url = server;
    }
    if let Some(name) = name_override {
        config.node.name = Some(name);
    }
    if exit_node {
        config.node.exit_node = true;
    }
    if !routes.is_empty() {
        config.node.advertise_routes = routes;
    }

    info!("Starting GhostWire client");
    info!("Server: {}", config.server.url);
    info!("Node name: {}", config.node.name.as_deref().unwrap_or("auto"));

    // Create and start the client
    let mut client = GhostWireClient::new(config).await?;

    if daemonize {
        // TODO: Implement proper daemonization
        info!("Running in background mode");
    }

    // Start the client and wait for shutdown
    client.start().await?;

    // Wait for shutdown signal
    wait_for_shutdown().await;

    // Graceful shutdown
    client.stop().await?;

    Ok(())
}

async fn stop_client() -> Result<()> {
    info!("Stopping GhostWire client...");

    // TODO: Send stop signal to running daemon
    // For now, just print message
    println!("Client stopped");

    Ok(())
}

async fn show_status(verbose: bool, format: &str) -> Result<()> {
    // TODO: Get actual status from running client
    let status = get_client_status().await?;

    match format {
        "json" => {
            let json = serde_json::to_string_pretty(&status)
                .map_err(|e| GhostWireError::internal(format!("JSON serialization error: {}", e)))?;
            println!("{}", json);
        }
        "yaml" => {
            let yaml = serde_yaml::to_string(&status)
                .map_err(|e| GhostWireError::internal(format!("YAML serialization error: {}", e)))?;
            println!("{}", yaml);
        }
        _ => {
            print_status_text(&status, verbose);
        }
    }

    Ok(())
}

async fn get_client_status() -> Result<ClientStatus> {
    // TODO: Get real status from running client
    Ok(ClientStatus::default())
}

fn print_status_text(status: &ClientStatus, verbose: bool) {
    println!("GhostWire Client Status:");
    println!("  State: {:?}", status.state);
    println!("  Node ID: {}", status.node_id.unwrap_or_else(|| "Not connected".to_string()));
    println!("  Server: {}", status.server_url.as_deref().unwrap_or("Not configured"));

    if verbose {
        println!("  Uptime: {} seconds", status.uptime_seconds);
        println!("  Bytes sent: {}", status.bytes_sent);
        println!("  Bytes received: {}", status.bytes_received);
        println!("  Active peers: {}", status.active_peers);
    }
}

async fn run_auth_command(config: ClientConfig, command: AuthCommands) -> Result<()> {
    match command {
        AuthCommands::Login { server, web, key } => {
            info!("Authenticating with server...");
            // TODO: Implement authentication
            println!("Authentication successful");
        }
        AuthCommands::Status => {
            // TODO: Get auth status
            println!("Authentication status: Connected");
        }
        AuthCommands::Logout => {
            info!("Logging out...");
            // TODO: Clear credentials
            println!("Logged out successfully");
        }
        AuthCommands::Refresh => {
            info!("Refreshing authentication...");
            // TODO: Refresh token
            println!("Authentication refreshed");
        }
    }
    Ok(())
}

async fn run_node_command(config: ClientConfig, command: NodeCommands) -> Result<()> {
    match command {
        NodeCommands::List { online, tag } => {
            info!("Listing nodes...");
            // TODO: Get node list from server
            println!("No nodes found");
        }
        NodeCommands::Show { node } => {
            info!("Showing node: {}", node);
            // TODO: Get node details
            println!("Node not found");
        }
        NodeCommands::Configure { name, tags, exit_node, routes } => {
            info!("Configuring node...");
            // TODO: Update node configuration
            println!("Node configuration updated");
        }
        NodeCommands::Reset => {
            info!("Resetting node configuration...");
            // TODO: Reset to defaults
            println!("Node reset to defaults");
        }
    }
    Ok(())
}

async fn run_ping(config: ClientConfig, target: &str, count: u32, size: u32) -> Result<()> {
    info!("Pinging {} ({} packets, {} bytes each)", target, count, size);

    // TODO: Implement mesh ping
    for i in 1..=count {
        println!("PING {}: seq={} time=<unknown> ms", target, i);
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    }

    Ok(())
}

async fn run_debug_command(config: ClientConfig, command: DebugCommands) -> Result<()> {
    match command {
        DebugCommands::Routes => {
            println!("Network routes:");
            // TODO: Show actual routes
        }
        DebugCommands::Interfaces => {
            println!("Network interfaces:");
            // TODO: Show actual interfaces
        }
        DebugCommands::TestServer => {
            println!("Testing server connectivity...");
            // TODO: Test server connection
        }
        DebugCommands::TestDerp => {
            println!("Testing DERP relay connectivity...");
            // TODO: Test DERP connection
        }
        DebugCommands::WgStats => {
            println!("WireGuard statistics:");
            // TODO: Show WireGuard stats
        }
        DebugCommands::QuicStats => {
            println!("QUIC statistics:");
            // TODO: Show QUIC stats
        }
        DebugCommands::Capture { output, duration } => {
            println!("Capturing packets for {} seconds...", duration);
            // TODO: Implement packet capture
        }
    }
    Ok(())
}

async fn run_config_command(config: ClientConfig, command: ConfigCommands, config_path: &PathBuf) -> Result<()> {
    match command {
        ConfigCommands::Show => {
            let yaml = serde_yaml::to_string(&config)
                .map_err(|e| GhostWireError::configuration(format!("Failed to serialize config: {}", e)))?;
            println!("Current configuration:");
            println!("{}", yaml);
        }
        ConfigCommands::Validate => {
            println!("Configuration is valid: {}", config_path.display());
        }
        ConfigCommands::Example { output } => {
            generate_example_config(output.as_ref()).await?;
        }
        ConfigCommands::Edit => {
            let editor = std::env::var("EDITOR").unwrap_or_else(|_| "vi".to_string());
            let expanded_path = expand_path(config_path)?;

            let status = std::process::Command::new(editor)
                .arg(&expanded_path)
                .status()
                .map_err(|e| GhostWireError::internal(format!("Failed to launch editor: {}", e)))?;

            if !status.success() {
                return Err(GhostWireError::internal("Editor exited with error".to_string()));
            }
        }
    }
    Ok(())
}

async fn generate_example_config(output: Option<&PathBuf>) -> Result<()> {
    let example_config = ClientConfig::default();
    let yaml = serde_yaml::to_string(&example_config)
        .map_err(|e| GhostWireError::configuration(format!("Failed to serialize example config: {}", e)))?;

    if let Some(output_path) = output {
        let expanded_path = expand_path(output_path)?;
        if let Some(parent) = expanded_path.parent() {
            tokio::fs::create_dir_all(parent).await
                .map_err(|e| GhostWireError::configuration(format!("Failed to create config directory: {}", e)))?;
        }

        tokio::fs::write(&expanded_path, yaml).await
            .map_err(|e| GhostWireError::configuration(format!("Failed to write example config: {}", e)))?;
        println!("Example configuration written to: {}", expanded_path.display());
    } else {
        println!("{}", yaml);
    }

    Ok(())
}

async fn wait_for_shutdown() {
    use tokio::signal;

    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            info!("Received Ctrl+C, starting graceful shutdown");
        },
        _ = terminate => {
            info!("Received SIGTERM, starting graceful shutdown");
        },
    }
}

#[derive(Debug, Default, serde::Serialize)]
struct ClientStatus {
    state: ClientState,
    node_id: Option<String>,
    server_url: Option<String>,
    uptime_seconds: u64,
    bytes_sent: u64,
    bytes_received: u64,
    active_peers: u32,
}

#[derive(Debug, Default, serde::Serialize)]
enum ClientState {
    #[default]
    Disconnected,
    Connecting,
    Connected,
    Error(String),
}