/// Command handlers for gwctl
///
/// This module contains all the command implementations for the various
/// gwctl subcommands, organized by functional area.

pub mod server;
pub mod node;
pub mod network;
pub mod policy;
pub mod auth;
pub mod derp;
pub mod dns;
pub mod user;
pub mod apikey;
pub mod route;
pub mod monitor;
pub mod debug;

use clap::Subcommand;

/// Server management commands
#[derive(Subcommand)]
pub enum ServerCommands {
    /// Show server status and health
    Status {
        /// Show detailed component status
        #[arg(long)]
        detailed: bool,

        /// Continuously monitor status
        #[arg(long, short)]
        watch: bool,

        /// Watch interval in seconds
        #[arg(long, default_value = "5")]
        interval: u64,
    },

    /// Show server version information
    Version,

    /// Show server metrics
    Metrics {
        /// Metric categories to show
        #[arg(long, value_delimiter = ',')]
        categories: Vec<String>,

        /// Show metrics in Prometheus format
        #[arg(long)]
        prometheus: bool,
    },

    /// Show server logs
    Logs {
        /// Number of log lines to show
        #[arg(long, short, default_value = "100")]
        lines: u32,

        /// Follow log output
        #[arg(long, short)]
        follow: bool,

        /// Filter logs by level
        #[arg(long, value_enum)]
        level: Option<LogLevel>,

        /// Filter logs by component
        #[arg(long)]
        component: Option<String>,
    },

    /// Restart server components
    Restart {
        /// Component to restart (all if not specified)
        component: Option<String>,

        /// Force restart without confirmation
        #[arg(long)]
        force: bool,
    },

    /// Update server configuration
    Configure {
        /// Configuration key to set
        #[arg(long)]
        set: Vec<String>,

        /// Configuration file to apply
        #[arg(long)]
        file: Option<std::path::PathBuf>,

        /// Dry run - show changes without applying
        #[arg(long)]
        dry_run: bool,
    },
}

/// Node management commands
#[derive(Subcommand)]
pub enum NodeCommands {
    /// List all nodes
    List {
        /// Filter by user
        #[arg(long)]
        user: Option<String>,

        /// Filter by status
        #[arg(long, value_enum)]
        status: Option<NodeStatus>,

        /// Show only online nodes
        #[arg(long)]
        online: bool,

        /// Show only offline nodes
        #[arg(long)]
        offline: bool,

        /// Sort by field
        #[arg(long, value_enum, default_value = "name")]
        sort: NodeSortField,
    },

    /// Show detailed node information
    Show {
        /// Node ID or name
        node: String,

        /// Show detailed network information
        #[arg(long)]
        detailed: bool,
    },

    /// Delete a node
    Delete {
        /// Node ID or name
        node: String,

        /// Force deletion without confirmation
        #[arg(long)]
        force: bool,
    },

    /// Rename a node
    Rename {
        /// Current node ID or name
        node: String,

        /// New name
        name: String,
    },

    /// Move node to different user
    Move {
        /// Node ID or name
        node: String,

        /// Target user
        user: String,
    },

    /// Tag operations
    Tag {
        #[command(subcommand)]
        action: TagCommands,
    },

    /// Generate pre-auth key for node registration
    PreAuth {
        /// User for the pre-auth key
        #[arg(long)]
        user: String,

        /// Make key reusable
        #[arg(long)]
        reusable: bool,

        /// Make node ephemeral
        #[arg(long)]
        ephemeral: bool,

        /// Key expiration in hours
        #[arg(long, default_value = "24")]
        expires: u32,

        /// Tags to apply to nodes using this key
        #[arg(long)]
        tags: Vec<String>,
    },

    /// Export node configuration
    Export {
        /// Node ID or name
        node: String,

        /// Export format
        #[arg(long, value_enum, default_value = "config")]
        format: ExportFormat,

        /// Output file (stdout if not specified)
        #[arg(long, short)]
        output: Option<std::path::PathBuf>,
    },
}

/// Network management commands
#[derive(Subcommand)]
pub enum NetworkCommands {
    /// Show network map
    Map {
        /// Show detailed peer connections
        #[arg(long)]
        detailed: bool,

        /// Focus on specific node
        #[arg(long)]
        focus: Option<String>,
    },

    /// Show routing table
    Routes {
        /// Filter by destination
        #[arg(long)]
        destination: Option<String>,

        /// Show exit node routes only
        #[arg(long)]
        exit_nodes: bool,
    },

    /// Connectivity testing
    Test {
        /// Source node (current if not specified)
        #[arg(long)]
        from: Option<String>,

        /// Target node or IP
        to: String,

        /// Test type
        #[arg(long, value_enum, default_value = "ping")]
        test_type: TestType,

        /// Number of test packets
        #[arg(long, short, default_value = "5")]
        count: u32,
    },

    /// Configure subnet routes
    Subnet {
        #[command(subcommand)]
        action: SubnetCommands,
    },

    /// Configure exit nodes
    ExitNode {
        #[command(subcommand)]
        action: ExitNodeCommands,
    },
}

/// Policy management commands
#[derive(Subcommand)]
pub enum PolicyCommands {
    /// Show current policy
    Show {
        /// Show in HuJSON format
        #[arg(long)]
        hujson: bool,

        /// Show effective policy for specific node
        #[arg(long)]
        node: Option<String>,
    },

    /// Apply policy from file
    Apply {
        /// Policy file
        file: std::path::PathBuf,

        /// Dry run - validate without applying
        #[arg(long)]
        dry_run: bool,
    },

    /// Validate policy file
    Validate {
        /// Policy file
        file: std::path::PathBuf,
    },

    /// Test policy rules
    Test {
        /// Source node or tag
        from: String,

        /// Destination node, tag, or IP
        to: String,

        /// Port (optional)
        #[arg(long)]
        port: Option<u16>,

        /// Protocol (optional)
        #[arg(long)]
        protocol: Option<String>,
    },

    /// Generate policy template
    Template {
        /// Template type
        #[arg(value_enum)]
        template_type: PolicyTemplate,

        /// Output file (stdout if not specified)
        #[arg(long, short)]
        output: Option<std::path::PathBuf>,
    },
}

/// Authentication commands
#[derive(Subcommand)]
pub enum AuthCommands {
    /// Login to server
    Login {
        /// Username (interactive if not provided)
        #[arg(long)]
        username: Option<String>,

        /// Use OAuth device flow
        #[arg(long)]
        oauth: bool,

        /// Use API key authentication
        #[arg(long)]
        api_key: Option<String>,
    },

    /// Logout from server
    Logout,

    /// Show current authentication status
    Status,

    /// Refresh authentication token
    Refresh,
}

/// DERP relay commands
#[derive(Subcommand)]
pub enum DerpCommands {
    /// List DERP servers
    List {
        /// Filter by region
        #[arg(long)]
        region: Option<String>,
    },

    /// Show DERP server status
    Status {
        /// Relay ID to check
        relay_id: String,
    },

    /// Test DERP connectivity
    Test {
        /// Specific server to test
        server: Option<String>,

        /// Test all servers in region
        #[arg(long)]
        region: Option<String>,
    },

    /// Show DERP statistics
    Stats {
        /// Specific server
        server: Option<String>,

        /// Show historical data
        #[arg(long)]
        history: bool,
    },
}

/// DNS management commands
#[derive(Subcommand)]
pub enum DnsCommands {
    /// List DNS records
    Records {
        /// Filter by domain
        #[arg(long)]
        domain: Option<String>,

        /// Filter by record type
        #[arg(long)]
        record_type: Option<String>,
    },

    /// Add DNS record
    Add {
        /// Record name
        name: String,

        /// Record type
        record_type: String,

        /// Record value
        value: String,

        /// TTL in seconds
        #[arg(long, default_value = "300")]
        ttl: u32,

        /// Associated node
        #[arg(long)]
        node: Option<String>,
    },

    /// Remove DNS record
    Remove {
        /// Record name
        name: String,

        /// Record type (optional)
        #[arg(long)]
        record_type: Option<String>,
    },

    /// Show DNS status
    Status,
}

/// User management commands
#[derive(Subcommand)]
pub enum UserCommands {
    /// List users
    List {
        /// Filter by role
        #[arg(long)]
        role: Option<String>,

        /// Show only active users
        #[arg(long)]
        active: Option<bool>,
    },

    /// Create new user
    Create {
        /// Username
        username: String,

        /// Email address
        #[arg(long)]
        email: Option<String>,

        /// User role
        #[arg(long, default_value = "user")]
        role: String,

        /// Initial password
        #[arg(long)]
        password: Option<String>,
    },

    /// Delete user
    Delete {
        /// User ID
        user_id: String,

        /// Force deletion without confirmation
        #[arg(long)]
        force: bool,
    },

    /// Show user details
    Show {
        /// User ID
        user_id: String,
    },

    /// Update user
    Update {
        /// User ID
        user_id: String,

        /// New email
        #[arg(long)]
        email: Option<String>,

        /// New role
        #[arg(long)]
        role: Option<String>,

        /// Active status
        #[arg(long)]
        active: Option<bool>,
    },
}

/// API key management commands
#[derive(Subcommand)]
pub enum ApiKeyCommands {
    /// List API keys
    List {
        /// Filter by user ID
        #[arg(long)]
        user_id: Option<String>,

        /// Show only active keys
        #[arg(long)]
        active: Option<bool>,
    },

    /// Create new API key
    Create {
        /// Key name
        name: String,

        /// Key scopes
        #[arg(long)]
        scopes: Vec<String>,

        /// Expiration duration (e.g., "30d", "1y")
        #[arg(long)]
        expires_in: Option<String>,

        /// User ID (admin only)
        #[arg(long)]
        user_id: Option<String>,
    },

    /// Delete API key
    Delete {
        /// Key ID
        key_id: String,

        /// Force deletion without confirmation
        #[arg(long)]
        force: bool,
    },

    /// Update API key
    Update {
        /// Key ID
        key_id: String,

        /// New name
        #[arg(long)]
        name: Option<String>,

        /// New scopes
        #[arg(long)]
        scopes: Option<Vec<String>>,

        /// Active status
        #[arg(long)]
        active: Option<bool>,
    },

    /// Show API key details
    Show {
        /// Key ID
        key_id: String,
    },
}

/// Route management commands
#[derive(Subcommand)]
pub enum RouteCommands {
    /// List routes
    List {
        /// Filter by node ID
        #[arg(long)]
        node_id: Option<String>,

        /// Filter by network
        #[arg(long)]
        network: Option<String>,
    },

    /// Add new route
    Add {
        /// Destination CIDR
        destination: String,

        /// Node ID
        node_id: String,

        /// Route metric
        #[arg(long)]
        metric: Option<u32>,

        /// Advertise route
        #[arg(long)]
        advertise: bool,
    },

    /// Delete route
    Delete {
        /// Route ID
        route_id: String,

        /// Force deletion without confirmation
        #[arg(long)]
        force: bool,
    },

    /// Enable route
    Enable {
        /// Route ID
        route_id: String,
    },

    /// Disable route
    Disable {
        /// Route ID
        route_id: String,
    },

    /// Show route details
    Show {
        /// Route ID
        route_id: String,
    },
}

/// Monitoring commands
#[derive(Subcommand)]
pub enum MonitorCommands {
    /// Monitor system status
    Status {
        /// Specific node ID
        #[arg(long)]
        node_id: Option<String>,

        /// Watch mode
        #[arg(long)]
        watch: bool,

        /// Watch interval
        #[arg(long)]
        interval: Option<String>,
    },

    /// Show metrics
    Metrics {
        /// Specific node ID
        #[arg(long)]
        node_id: Option<String>,

        /// Metric type filter
        #[arg(long)]
        metric_type: Option<String>,

        /// Duration filter
        #[arg(long)]
        duration: Option<String>,
    },

    /// Monitor logs
    Logs {
        /// Specific node ID
        #[arg(long)]
        node_id: Option<String>,

        /// Log level filter
        #[arg(long)]
        level: Option<String>,

        /// Follow logs
        #[arg(long)]
        follow: bool,

        /// Number of lines
        #[arg(long, default_value = "100")]
        lines: u32,
    },

    /// Monitor network status
    Network {
        /// Specific node ID
        #[arg(long)]
        node_id: Option<String>,

        /// Watch mode
        #[arg(long)]
        watch: bool,

        /// Watch interval
        #[arg(long)]
        interval: Option<String>,
    },
}

/// Debug commands
#[derive(Subcommand)]
pub enum DebugCommands {
    /// Ping target
    Ping {
        /// Target IP or hostname
        target: String,

        /// Number of pings
        #[arg(long, short)]
        count: Option<u32>,

        /// Timeout in milliseconds
        #[arg(long)]
        timeout: Option<u32>,
    },

    /// Trace route to target
    Trace {
        /// Target IP or hostname
        target: String,

        /// Maximum hops
        #[arg(long)]
        max_hops: Option<u32>,
    },

    /// Test connectivity
    Connectivity {
        /// Specific node ID
        #[arg(long)]
        node_id: Option<String>,
    },

    /// Export debug information
    Export {
        /// Specific node ID
        #[arg(long)]
        node_id: Option<String>,

        /// Output file
        #[arg(long, short)]
        output_file: Option<String>,
    },

    /// Run system diagnostics
    Doctor,
}

// Supporting enums and types

#[derive(clap::ValueEnum, Clone)]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

#[derive(clap::ValueEnum, Clone)]
pub enum NodeStatus {
    Online,
    Offline,
    Unknown,
}

#[derive(clap::ValueEnum, Clone)]
pub enum NodeSortField {
    Name,
    User,
    Ip,
    LastSeen,
    Status,
}

#[derive(clap::ValueEnum, Clone)]
pub enum ExportFormat {
    Config,
    Qr,
    Json,
}

#[derive(clap::ValueEnum, Clone)]
pub enum TestType {
    Ping,
    Traceroute,
    Speed,
}

#[derive(clap::ValueEnum, Clone)]
pub enum PolicyTemplate {
    Basic,
    Corporate,
    HomeOffice,
    ZeroTrust,
}

#[derive(clap::ValueEnum, Clone)]
pub enum TopologyFormat {
    Ascii,
    Graphviz,
    Json,
}

#[derive(clap::ValueEnum, Clone)]
pub enum MetricsFormat {
    Prometheus,
    Json,
    Csv,
}

// Subcommand types

#[derive(Subcommand)]
pub enum TagCommands {
    Add {
        node: String,
        tags: Vec<String>,
    },
    Remove {
        node: String,
        tags: Vec<String>,
    },
    List {
        node: String,
    },
}

#[derive(Subcommand)]
pub enum SubnetCommands {
    List,
    Add {
        node: String,
        cidr: String,
    },
    Remove {
        node: String,
        cidr: String,
    },
    Enable {
        route_id: String,
    },
    Disable {
        route_id: String,
    },
}

#[derive(Subcommand)]
pub enum ExitNodeCommands {
    List,
    Set {
        node: String,
    },
    Unset,
}