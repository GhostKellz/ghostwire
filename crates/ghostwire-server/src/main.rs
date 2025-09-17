use clap::{Parser, Subcommand};
use ghostwire_common::error::Result;
use std::path::PathBuf;
use tracing::{info, warn, error};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod server;
mod database;
mod coordinator;
mod auth;
mod api;
mod policy;
mod netmap;
mod derp;
mod dns;

use server::{GhostWireServer, ServerConfig};
use database::DatabaseManager;

/// GhostWire coordination server - self-hosted Tailscale alternative
#[derive(Parser)]
#[command(name = "ghostwire-server")]
#[command(about = "A high-performance mesh VPN coordination server")]
#[command(version)]
struct Cli {
    /// Configuration file path
    #[arg(short, long, default_value = "/etc/ghostwire/server.yaml")]
    config: PathBuf,

    /// Log level
    #[arg(long, default_value = "info")]
    log_level: String,

    /// Enable JSON logging
    #[arg(long)]
    json_logs: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the coordination server
    Serve {
        /// Override listen address
        #[arg(long)]
        listen: Option<String>,

        /// Override database path
        #[arg(long)]
        database: Option<PathBuf>,

        /// Enable DERP relay on this server
        #[arg(long)]
        enable_derp: bool,

        /// DERP listen port
        #[arg(long, default_value = "3478")]
        derp_port: u16,
    },

    /// Database management commands
    Db {
        #[command(subcommand)]
        db_command: DbCommands,
    },

    /// User management commands
    Users {
        #[command(subcommand)]
        user_command: UserCommands,
    },

    /// Node management commands
    Nodes {
        #[command(subcommand)]
        node_command: NodeCommands,
    },

    /// Configuration validation and generation
    Config {
        #[command(subcommand)]
        config_command: ConfigCommands,
    },
}

#[derive(Subcommand)]
enum DbCommands {
    /// Initialize database schema
    Init,
    /// Run database migrations
    Migrate,
    /// Database status and statistics
    Status,
    /// Backup database
    Backup {
        /// Output file path
        output: PathBuf,
    },
    /// Restore database from backup
    Restore {
        /// Backup file path
        input: PathBuf,
    },
}

#[derive(Subcommand)]
enum UserCommands {
    /// List all users
    List,
    /// Create a new user
    Create {
        /// User name
        name: String,
        /// User email
        #[arg(long)]
        email: Option<String>,
    },
    /// Delete a user
    Delete {
        /// User name or ID
        user: String,
    },
    /// Show user details
    Show {
        /// User name or ID
        user: String,
    },
}

#[derive(Subcommand)]
enum NodeCommands {
    /// List all nodes
    List {
        /// Filter by user
        #[arg(long)]
        user: Option<String>,
        /// Include expired nodes
        #[arg(long)]
        include_expired: bool,
    },
    /// Show node details
    Show {
        /// Node ID or name
        node: String,
    },
    /// Delete/expire a node
    Delete {
        /// Node ID or name
        node: String,
    },
    /// Move node to different user
    Move {
        /// Node ID or name
        node: String,
        /// Target user
        user: String,
    },
}

#[derive(Subcommand)]
enum ConfigCommands {
    /// Validate configuration file
    Validate,
    /// Generate example configuration
    Example {
        /// Output file (stdout if not specified)
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Show current effective configuration
    Show,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    init_logging(&cli.log_level, cli.json_logs)?;

    info!("GhostWire coordination server starting");
    info!("Version: {}", env!("CARGO_PKG_VERSION"));

    // Load configuration
    let config = load_config(&cli.config).await?;

    match cli.command {
        Some(Commands::Serve { listen, database, enable_derp, derp_port }) => {
            run_server(config, listen, database, enable_derp, derp_port).await
        }
        Some(Commands::Db { db_command }) => {
            run_db_command(config, db_command).await
        }
        Some(Commands::Users { user_command }) => {
            run_user_command(config, user_command).await
        }
        Some(Commands::Nodes { node_command }) => {
            run_node_command(config, node_command).await
        }
        Some(Commands::Config { config_command }) => {
            run_config_command(config, config_command, &cli.config).await
        }
        None => {
            // Default to serve command
            run_server(config, None, None, false, 3478).await
        }
    }
}

fn init_logging(level: &str, json_logs: bool) -> Result<()> {
    let level_filter = level.parse::<tracing::Level>()
        .map_err(|_| ghostwire_common::error::GhostWireError::configuration(format!("Invalid log level: {}", level)))?;

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

async fn load_config(config_path: &PathBuf) -> Result<ServerConfig> {
    if !config_path.exists() {
        warn!("Configuration file not found: {}, using defaults", config_path.display());
        return Ok(ServerConfig::default());
    }

    let config_content = tokio::fs::read_to_string(config_path).await
        .map_err(|e| ghostwire_common::error::GhostWireError::configuration(
            format!("Failed to read config file: {}", e)
        ))?;

    let config: ServerConfig = serde_yaml::from_str(&config_content)
        .map_err(|e| ghostwire_common::error::GhostWireError::configuration(
            format!("Failed to parse config file: {}", e)
        ))?;

    info!("Loaded configuration from {}", config_path.display());
    Ok(config)
}

async fn run_server(
    mut config: ServerConfig,
    listen_override: Option<String>,
    database_override: Option<PathBuf>,
    enable_derp: bool,
    derp_port: u16,
) -> Result<()> {
    // Apply CLI overrides
    if let Some(listen) = listen_override {
        config.rest.listen_addr = listen.clone();
        config.grpc.listen_addr = listen;
    }
    if let Some(database) = database_override {
        config.database.url = format!("sqlite:{}", database.display());
    }
    if enable_derp {
        config.derp.enabled = true;
        config.derp.stun_port = derp_port;
    }

    info!("Starting GhostWire server: {}", config.instance.server_name);
    info!("Database: {}", config.database.url);

    if config.derp.enabled {
        info!("DERP relay enabled on port {}", config.derp.stun_port);
    }

    // Create and start the server
    let mut server = GhostWireServer::new(config).await?;
    server.start().await?;

    // Wait for shutdown signal
    wait_for_shutdown().await;

    // Graceful shutdown
    server.stop().await?;

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

async fn run_db_command(config: ServerConfig, command: DbCommands) -> Result<()> {
    use database::DatabaseManager;

    let db_manager = DatabaseManager::new(&config.database).await?;

    match command {
        DbCommands::Init => {
            info!("Initializing database schema...");
            db_manager.init_schema().await?;
            info!("Database initialized successfully");
        }
        DbCommands::Migrate => {
            info!("Running database migrations...");
            db_manager.migrate().await?;
            info!("Migrations completed successfully");
        }
        DbCommands::Status => {
            let status = db_manager.get_status().await?;
            println!("Database Status:");
            println!("  URL: {}", config.database.url);
            println!("  Schema Version: {}", status.schema_version);
            println!("  Users: {}", status.user_count);
            println!("  Nodes: {}", status.node_count);
            println!("  Routes: {}", status.route_count);
            println!("  Size: {} MB", status.size_mb);
        }
        DbCommands::Backup { output } => {
            info!("Creating database backup...");
            db_manager.backup(&output).await?;
            info!("Backup created: {}", output.display());
        }
        DbCommands::Restore { input } => {
            warn!("Restoring database from backup...");
            db_manager.restore(&input).await?;
            info!("Database restored from: {}", input.display());
        }
    }

    Ok(())
}

async fn run_user_command(config: ServerConfig, command: UserCommands) -> Result<()> {
    use database::DatabaseManager;

    let db_manager = DatabaseManager::new(&config.database).await?;

    match command {
        UserCommands::List => {
            let users = db_manager.list_users().await?;
            println!("Users ({}):", users.len());
            for user in users {
                println!("  {} - {} ({})", user.id, user.name,
                    user.email.as_deref().unwrap_or("no email"));
            }
        }
        UserCommands::Create { name, email } => {
            let user = db_manager.create_user(&name, email.as_deref()).await?;
            println!("Created user: {} ({})", user.name, user.id);
        }
        UserCommands::Delete { user } => {
            db_manager.delete_user(&user).await?;
            println!("Deleted user: {}", user);
        }
        UserCommands::Show { user } => {
            let user_info = db_manager.get_user(&user).await?;
            println!("User: {}", user_info.name);
            println!("  ID: {}", user_info.id);
            println!("  Email: {}", user_info.email.as_deref().unwrap_or("none"));
            println!("  Created: {:?}", user_info.created_at);

            let nodes = db_manager.get_user_nodes(&user_info.id).await?;
            println!("  Nodes ({}):", nodes.len());
            for node in nodes {
                println!("    {} - {}", node.name,
                    if node.online { "online" } else { "offline" });
            }
        }
    }

    Ok(())
}

async fn run_node_command(config: ServerConfig, command: NodeCommands) -> Result<()> {
    use database::DatabaseManager;

    let db_manager = DatabaseManager::new(&config.database).await?;

    match command {
        NodeCommands::List { user, include_expired } => {
            let nodes = if let Some(user_filter) = user {
                let user_info = db_manager.get_user(&user_filter).await?;
                db_manager.get_user_nodes(&user_info.id).await?
            } else {
                db_manager.list_nodes(include_expired).await?
            };

            println!("Nodes ({}):", nodes.len());
            for node in nodes {
                let status = if node.online { "online" }
                           else if node.is_expired() { "expired" }
                           else { "offline" };
                println!("  {} - {} - {} ({})",
                    node.name, node.ipv4, status, node.id);
            }
        }
        NodeCommands::Show { node } => {
            let node_info = db_manager.get_node(&node).await?;
            println!("Node: {}", node_info.name);
            println!("  ID: {}", node_info.id);
            println!("  IPv4: {}", node_info.ipv4);
            if let Some(ipv6) = node_info.ipv6 {
                println!("  IPv6: {}", ipv6);
            }
            println!("  Status: {}", if node_info.online { "online" } else { "offline" });
            println!("  Created: {:?}", node_info.created_at);
            println!("  Last Seen: {:?}", node_info.last_seen);

            if !node_info.routes.is_empty() {
                println!("  Routes:");
                for route in &node_info.routes {
                    println!("    {} - {}", route.prefix,
                        if route.enabled { "enabled" } else { "disabled" });
                }
            }
        }
        NodeCommands::Delete { node } => {
            db_manager.delete_node(&node).await?;
            println!("Deleted node: {}", node);
        }
        NodeCommands::Move { node, user } => {
            let user_info = db_manager.get_user(&user).await?;
            db_manager.move_node(&node, &user_info.id).await?;
            println!("Moved node {} to user {}", node, user);
        }
    }

    Ok(())
}

async fn run_config_command(
    config: ServerConfig,
    command: ConfigCommands,
    config_path: &PathBuf,
) -> Result<()> {
    match command {
        ConfigCommands::Validate => {
            // Config is already loaded and validated
            println!("Configuration file is valid: {}", config_path.display());
        }
        ConfigCommands::Example { output } => {
            let example_config = ServerConfig::default();
            let yaml = serde_yaml::to_string(&example_config)
                .map_err(|e| ghostwire_common::error::GhostWireError::configuration(
                    format!("Failed to serialize example config: {}", e)
                ))?;

            if let Some(output_path) = output {
                tokio::fs::write(&output_path, yaml).await
                    .map_err(|e| ghostwire_common::error::GhostWireError::configuration(
                        format!("Failed to write example config: {}", e)
                    ))?;
                println!("Example configuration written to: {}", output_path.display());
            } else {
                println!("{}", yaml);
            }
        }
        ConfigCommands::Show => {
            let yaml = serde_yaml::to_string(&config)
                .map_err(|e| ghostwire_common::error::GhostWireError::configuration(
                    format!("Failed to serialize config: {}", e)
                ))?;
            println!("Current configuration:");
            println!("{}", yaml);
        }
    }

    Ok(())
}