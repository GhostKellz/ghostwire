/// Client configuration management
///
/// Handles all configuration aspects of the GhostWire client including
/// server connection, node settings, transport configuration, and platform-specific options.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

/// Complete client configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    /// Server connection configuration
    pub server: ServerConfig,

    /// Node configuration
    pub node: NodeConfig,

    /// Transport configuration
    pub transport: TransportConfig,

    /// Authentication configuration
    pub auth: AuthConfig,

    /// Platform-specific configuration
    pub platform: PlatformConfig,

    /// Logging configuration
    pub logging: LoggingConfig,

    /// Tunnel configuration
    pub tunnel: TunnelConfig,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig::default(),
            node: NodeConfig::default(),
            transport: TransportConfig::default(),
            auth: AuthConfig::default(),
            platform: PlatformConfig::default(),
            logging: LoggingConfig::default(),
            tunnel: TunnelConfig::default(),
        }
    }
}

/// Server connection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Server URL
    pub url: String,

    /// gRPC port
    pub grpc_port: Option<u16>,

    /// REST API port
    pub rest_port: Option<u16>,

    /// Enable TLS verification
    pub verify_tls: bool,

    /// Custom CA certificate path
    pub ca_cert: Option<PathBuf>,

    /// Connection timeout (seconds)
    pub timeout_seconds: u64,

    /// Retry configuration
    pub retry: RetryConfig,

    /// Health check configuration
    pub health_check: HealthCheckConfig,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            url: "https://ghostwire.example.com".to_string(),
            grpc_port: Some(50051),
            rest_port: Some(8080),
            verify_tls: true,
            ca_cert: None,
            timeout_seconds: 30,
            retry: RetryConfig::default(),
            health_check: HealthCheckConfig::default(),
        }
    }
}

/// Retry configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryConfig {
    /// Maximum retry attempts
    pub max_attempts: u32,

    /// Initial retry delay (seconds)
    pub initial_delay_seconds: u64,

    /// Maximum retry delay (seconds)
    pub max_delay_seconds: u64,

    /// Exponential backoff multiplier
    pub backoff_multiplier: f64,

    /// Enable jitter
    pub jitter: bool,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 5,
            initial_delay_seconds: 1,
            max_delay_seconds: 300,
            backoff_multiplier: 2.0,
            jitter: true,
        }
    }
}

/// Health check configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckConfig {
    /// Enable health checks
    pub enabled: bool,

    /// Health check interval (seconds)
    pub interval_seconds: u64,

    /// Health check timeout (seconds)
    pub timeout_seconds: u64,

    /// Failure threshold
    pub failure_threshold: u32,

    /// Recovery threshold
    pub recovery_threshold: u32,
}

impl Default for HealthCheckConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_seconds: 30,
            timeout_seconds: 5,
            failure_threshold: 3,
            recovery_threshold: 2,
        }
    }
}

/// Node configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    /// Node name (auto-generated if None)
    pub name: Option<String>,

    /// Node tags
    pub tags: Vec<String>,

    /// Enable exit node functionality
    pub exit_node: bool,

    /// Routes to advertise
    pub advertise_routes: Vec<String>,

    /// Accept routes from other nodes
    pub accept_routes: bool,

    /// Accept DNS configuration
    pub accept_dns: bool,

    /// Enable subnet routing
    pub subnet_routing: bool,

    /// Enable SSH access
    pub ssh_enabled: bool,

    /// Custom attributes
    pub attributes: HashMap<String, String>,

    /// Auto-update configuration
    pub auto_update: AutoUpdateConfig,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            name: None,
            tags: vec![],
            exit_node: false,
            advertise_routes: vec![],
            accept_routes: true,
            accept_dns: true,
            subnet_routing: false,
            ssh_enabled: false,
            attributes: HashMap::new(),
            auto_update: AutoUpdateConfig::default(),
        }
    }
}

/// Auto-update configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoUpdateConfig {
    /// Enable automatic updates
    pub enabled: bool,

    /// Update channel (stable, beta, dev)
    pub channel: String,

    /// Check interval (hours)
    pub check_interval_hours: u64,

    /// Auto-restart after update
    pub auto_restart: bool,

    /// Backup before update
    pub backup_config: bool,
}

impl Default for AutoUpdateConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            channel: "stable".to_string(),
            check_interval_hours: 24,
            auto_restart: false,
            backup_config: true,
        }
    }
}

/// Transport configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportConfig {
    /// WireGuard configuration
    pub wireguard: WireGuardConfig,

    /// QUIC configuration
    pub quic: QuicConfig,

    /// DERP configuration
    pub derp: DerpConfig,

    /// NAT traversal configuration
    pub nat: NatConfig,

    /// Interface configuration
    pub interface: InterfaceConfig,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            wireguard: WireGuardConfig::default(),
            quic: QuicConfig::default(),
            derp: DerpConfig::default(),
            nat: NatConfig::default(),
            interface: InterfaceConfig::default(),
        }
    }
}

/// WireGuard configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireGuardConfig {
    /// Enable WireGuard transport
    pub enabled: bool,

    /// Use userspace implementation
    pub userspace: bool,

    /// Private key (auto-generated if None)
    pub private_key: Option<String>,

    /// Listen port
    pub listen_port: Option<u16>,

    /// MTU size
    pub mtu: u16,

    /// Keepalive interval (seconds)
    pub keepalive_seconds: Option<u64>,

    /// Enable post-quantum cryptography
    pub post_quantum: bool,
}

impl Default for WireGuardConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            userspace: false,
            private_key: None,
            listen_port: None,
            mtu: 1420,
            keepalive_seconds: Some(25),
            post_quantum: false,
        }
    }
}

/// QUIC configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuicConfig {
    /// Enable QUIC transport
    pub enabled: bool,

    /// QUIC bind port
    pub bind_port: Option<u16>,

    /// Maximum concurrent connections
    pub max_connections: u32,

    /// Connection idle timeout (seconds)
    pub idle_timeout_seconds: u64,

    /// Keep-alive interval (seconds)
    pub keepalive_seconds: u64,

    /// Maximum packet size
    pub max_packet_size: u16,

    /// Enable 0-RTT
    pub enable_0rtt: bool,

    /// Congestion control algorithm
    pub congestion_control: String,
}

impl Default for QuicConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            bind_port: None,
            max_connections: 100,
            idle_timeout_seconds: 60,
            keepalive_seconds: 25,
            max_packet_size: 1350,
            enable_0rtt: true,
            congestion_control: "bbr".to_string(),
        }
    }
}

/// DERP configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DerpConfig {
    /// Enable DERP fallback
    pub enabled: bool,

    /// Custom DERP servers
    pub custom_servers: Vec<DerpServerConfig>,

    /// Use built-in DERP servers
    pub use_builtin_servers: bool,

    /// DERP server selection strategy
    pub selection_strategy: String,

    /// Connection timeout (seconds)
    pub timeout_seconds: u64,

    /// Enable mesh forwarding
    pub mesh_forwarding: bool,
}

impl Default for DerpConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            custom_servers: vec![],
            use_builtin_servers: true,
            selection_strategy: "closest".to_string(),
            timeout_seconds: 30,
            mesh_forwarding: true,
        }
    }
}

/// DERP server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DerpServerConfig {
    /// Server name
    pub name: String,

    /// Server hostname
    pub hostname: String,

    /// HTTPS port
    pub https_port: u16,

    /// STUN port
    pub stun_port: u16,

    /// Server region
    pub region: String,

    /// Server priority
    pub priority: u8,
}

/// NAT traversal configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NatConfig {
    /// Enable STUN
    pub stun_enabled: bool,

    /// Custom STUN servers
    pub stun_servers: Vec<String>,

    /// Enable UPnP/NAT-PMP
    pub upnp_enabled: bool,

    /// Port mapping timeout (seconds)
    pub mapping_timeout_seconds: u64,

    /// Enable hole punching
    pub hole_punching: bool,

    /// Hole punching timeout (seconds)
    pub hole_punch_timeout_seconds: u64,
}

impl Default for NatConfig {
    fn default() -> Self {
        Self {
            stun_enabled: true,
            stun_servers: vec![
                "stun.l.google.com:19302".to_string(),
                "stun1.l.google.com:19302".to_string(),
            ],
            upnp_enabled: true,
            mapping_timeout_seconds: 300,
            hole_punching: true,
            hole_punch_timeout_seconds: 10,
        }
    }
}

/// Network interface configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceConfig {
    /// Interface name
    pub name: String,

    /// IPv4 configuration
    pub ipv4: Option<Ipv4Config>,

    /// IPv6 configuration
    pub ipv6: Option<Ipv6Config>,

    /// DNS configuration
    pub dns: DnsConfig,

    /// Routing configuration
    pub routing: RoutingConfig,

    /// Firewall configuration
    pub firewall: FirewallConfig,
}

impl Default for InterfaceConfig {
    fn default() -> Self {
        Self {
            name: "ghostwire0".to_string(),
            ipv4: Some(Ipv4Config::default()),
            ipv6: Some(Ipv6Config::default()),
            dns: DnsConfig::default(),
            routing: RoutingConfig::default(),
            firewall: FirewallConfig::default(),
        }
    }
}

/// IPv4 configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ipv4Config {
    /// Enable IPv4
    pub enabled: bool,

    /// Static IP address (auto-assigned if None)
    pub address: Option<String>,

    /// Subnet mask
    pub netmask: Option<String>,

    /// Default gateway
    pub gateway: Option<String>,
}

impl Default for Ipv4Config {
    fn default() -> Self {
        Self {
            enabled: true,
            address: None,
            netmask: None,
            gateway: None,
        }
    }
}

/// IPv6 configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ipv6Config {
    /// Enable IPv6
    pub enabled: bool,

    /// Static IP address (auto-assigned if None)
    pub address: Option<String>,

    /// Prefix length
    pub prefix_length: Option<u8>,

    /// Default gateway
    pub gateway: Option<String>,
}

impl Default for Ipv6Config {
    fn default() -> Self {
        Self {
            enabled: true,
            address: None,
            prefix_length: None,
            gateway: None,
        }
    }
}

/// DNS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsConfig {
    /// Enable MagicDNS
    pub magic_dns: bool,

    /// Custom DNS servers
    pub servers: Vec<String>,

    /// DNS search domains
    pub search_domains: Vec<String>,

    /// Override system DNS
    pub override_system_dns: bool,

    /// DNS timeout (seconds)
    pub timeout_seconds: u64,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            magic_dns: true,
            servers: vec![],
            search_domains: vec![],
            override_system_dns: false,
            timeout_seconds: 5,
        }
    }
}

/// Routing configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingConfig {
    /// Enable default route
    pub default_route: bool,

    /// Custom routes
    pub custom_routes: Vec<RouteConfig>,

    /// Route metric
    pub metric: Option<u32>,

    /// Enable route advertisements
    pub advertise_routes: bool,
}

impl Default for RoutingConfig {
    fn default() -> Self {
        Self {
            default_route: false,
            custom_routes: vec![],
            metric: None,
            advertise_routes: false,
        }
    }
}

/// Route configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteConfig {
    /// Destination network
    pub destination: String,

    /// Gateway
    pub gateway: Option<String>,

    /// Route metric
    pub metric: Option<u32>,

    /// Route description
    pub description: Option<String>,
}

/// Firewall configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallConfig {
    /// Enable built-in firewall
    pub enabled: bool,

    /// Default policy (allow, deny)
    pub default_policy: String,

    /// Firewall rules
    pub rules: Vec<FirewallRule>,

    /// Enable logging
    pub logging: bool,
}

impl Default for FirewallConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            default_policy: "allow".to_string(),
            rules: vec![],
            logging: false,
        }
    }
}

/// Firewall rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallRule {
    /// Rule action (allow, deny, log)
    pub action: String,

    /// Source address/network
    pub source: Option<String>,

    /// Destination address/network
    pub destination: Option<String>,

    /// Protocol (tcp, udp, icmp, any)
    pub protocol: Option<String>,

    /// Source port
    pub source_port: Option<u16>,

    /// Destination port
    pub destination_port: Option<u16>,

    /// Rule description
    pub description: Option<String>,
}

/// Authentication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    /// Authentication method (oauth, key, cert)
    pub method: String,

    /// OAuth configuration
    pub oauth: Option<OAuthConfig>,

    /// OIDC configuration
    pub oidc: Option<OidcConfig>,

    /// API key
    pub api_key: Option<String>,

    /// Certificate path
    pub cert_path: Option<PathBuf>,

    /// Private key path
    pub key_path: Option<PathBuf>,

    /// Token refresh configuration
    pub token_refresh: TokenRefreshConfig,

    /// Keyring configuration
    pub keyring: KeyringConfig,

    /// Server URL for authentication
    pub server_url: String,

    /// Machine name for registration
    pub machine_name: String,

    /// OAuth callback port
    pub oauth_port: u16,

    /// Store credentials in keyring
    pub store_credentials: bool,

    /// Auto refresh tokens
    pub auto_refresh: bool,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            method: "oauth".to_string(),
            oauth: Some(OAuthConfig::default()),
            oidc: None,
            api_key: None,
            cert_path: None,
            key_path: None,
            token_refresh: TokenRefreshConfig::default(),
            keyring: KeyringConfig::default(),
            server_url: "https://ghostwire.example.com".to_string(),
            machine_name: "ghostwire-client".to_string(),
            oauth_port: 8080,
            store_credentials: true,
            auto_refresh: true,
        }
    }
}

/// OIDC configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcConfig {
    /// OIDC issuer URL
    pub issuer_url: String,

    /// Client ID
    pub client_id: String,

    /// Client secret (optional for public clients)
    pub client_secret: Option<String>,

    /// OAuth scopes
    pub scopes: Vec<String>,

    /// Redirect URI
    pub redirect_uri: Option<String>,
}

impl Default for OidcConfig {
    fn default() -> Self {
        Self {
            issuer_url: "https://auth.ghostwire.example.com".to_string(),
            client_id: "ghostwire-client".to_string(),
            client_secret: None,
            scopes: vec!["openid".to_string(), "profile".to_string(), "email".to_string()],
            redirect_uri: None,
        }
    }
}

/// OAuth configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthConfig {
    /// OAuth provider
    pub provider: String,

    /// Client ID
    pub client_id: Option<String>,

    /// Redirect URL for web auth
    pub redirect_url: String,

    /// OAuth scopes
    pub scopes: Vec<String>,

    /// Device flow configuration
    pub device_flow: DeviceFlowConfig,
}

impl Default for OAuthConfig {
    fn default() -> Self {
        Self {
            provider: "auto".to_string(),
            client_id: None,
            redirect_url: "http://localhost:8080/auth/callback".to_string(),
            scopes: vec!["openid".to_string(), "profile".to_string()],
            device_flow: DeviceFlowConfig::default(),
        }
    }
}

/// Device flow configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceFlowConfig {
    /// Enable device flow
    pub enabled: bool,

    /// Polling interval (seconds)
    pub poll_interval_seconds: u64,

    /// Device code timeout (seconds)
    pub timeout_seconds: u64,
}

impl Default for DeviceFlowConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            poll_interval_seconds: 5,
            timeout_seconds: 600,
        }
    }
}

/// Token refresh configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenRefreshConfig {
    /// Enable automatic refresh
    pub auto_refresh: bool,

    /// Refresh threshold (seconds before expiry)
    pub refresh_threshold_seconds: u64,

    /// Maximum refresh attempts
    pub max_attempts: u32,
}

impl Default for TokenRefreshConfig {
    fn default() -> Self {
        Self {
            auto_refresh: true,
            refresh_threshold_seconds: 300,
            max_attempts: 3,
        }
    }
}

/// Keyring configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyringConfig {
    /// Enable keyring storage
    pub enabled: bool,

    /// Keyring service name
    pub service_name: String,

    /// Fallback to file storage
    pub fallback_to_file: bool,

    /// File storage path
    pub file_path: Option<PathBuf>,
}

impl Default for KeyringConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            service_name: "ghostwire-client".to_string(),
            fallback_to_file: true,
            file_path: None,
        }
    }
}

/// Platform-specific configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformConfig {
    /// Linux-specific configuration
    #[cfg(target_os = "linux")]
    pub linux: Option<LinuxConfig>,

    /// macOS-specific configuration
    #[cfg(target_os = "macos")]
    pub macos: Option<MacOSConfig>,

    /// Windows-specific configuration
    #[cfg(target_os = "windows")]
    pub windows: Option<WindowsConfig>,

    /// Service configuration
    pub service: ServiceConfig,
}

impl Default for PlatformConfig {
    fn default() -> Self {
        Self {
            #[cfg(target_os = "linux")]
            linux: Some(LinuxConfig::default()),
            #[cfg(target_os = "macos")]
            macos: Some(MacOSConfig::default()),
            #[cfg(target_os = "windows")]
            windows: Some(WindowsConfig::default()),
            service: ServiceConfig::default(),
        }
    }
}

/// Linux-specific configuration
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinuxConfig {
    /// Use netlink for routing
    pub use_netlink: bool,

    /// NetworkManager integration
    pub networkmanager: bool,

    /// systemd integration
    pub systemd: bool,

    /// Use kernel WireGuard
    pub kernel_wireguard: bool,

    /// eBPF acceleration
    pub ebpf_accel: bool,
}

#[cfg(target_os = "linux")]
impl Default for LinuxConfig {
    fn default() -> Self {
        Self {
            use_netlink: true,
            networkmanager: true,
            systemd: true,
            kernel_wireguard: true,
            ebpf_accel: false,
        }
    }
}

/// macOS-specific configuration
#[cfg(target_os = "macos")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacOSConfig {
    /// Use system configuration framework
    pub use_system_config: bool,

    /// Endpoint Security framework
    pub endpoint_security: bool,

    /// Launch agent configuration
    pub launch_agent: bool,

    /// Keychain integration
    pub keychain: bool,
}

#[cfg(target_os = "macos")]
impl Default for MacOSConfig {
    fn default() -> Self {
        Self {
            use_system_config: true,
            endpoint_security: false,
            launch_agent: true,
            keychain: true,
        }
    }
}

/// Windows-specific configuration
#[cfg(target_os = "windows")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowsConfig {
    /// Use WinTUN driver
    pub use_wintun: bool,

    /// Windows service configuration
    pub service: bool,

    /// Credential Manager integration
    pub credential_manager: bool,

    /// Windows Firewall integration
    pub firewall_integration: bool,
}

#[cfg(target_os = "windows")]
impl Default for WindowsConfig {
    fn default() -> Self {
        Self {
            use_wintun: true,
            service: true,
            credential_manager: true,
            firewall_integration: true,
        }
    }
}

/// Service configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceConfig {
    /// Run as system service
    pub enabled: bool,

    /// Service name
    pub name: String,

    /// Service description
    pub description: String,

    /// Service user
    pub user: Option<String>,

    /// Service group
    pub group: Option<String>,

    /// Working directory
    pub working_directory: Option<PathBuf>,

    /// Restart policy
    pub restart_policy: String,

    /// Environment variables
    pub environment: HashMap<String, String>,
}

impl Default for ServiceConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            name: "ghostwire-client".to_string(),
            description: "GhostWire mesh VPN client".to_string(),
            user: None,
            group: None,
            working_directory: None,
            restart_policy: "always".to_string(),
            environment: HashMap::new(),
        }
    }
}

/// Logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Log level
    pub level: String,

    /// Log format
    pub format: String,

    /// Enable structured logging
    pub structured: bool,

    /// Log file path
    pub file: Option<PathBuf>,

    /// Enable log rotation
    pub rotation: bool,

    /// Maximum log file size (MB)
    pub max_file_size_mb: u64,

    /// Number of log files to keep
    pub max_files: u32,

    /// Enable syslog
    pub syslog: bool,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            format: "text".to_string(),
            structured: false,
            file: None,
            rotation: false,
            max_file_size_mb: 100,
            max_files: 5,
            syslog: false,
        }
    }
}

/// Tunnel configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelConfig {
    /// Interface name
    pub interface_name: String,

    /// MTU size
    pub mtu: u16,

    /// Enable IPv4
    pub ipv4: bool,

    /// Enable IPv6
    pub ipv6: bool,

    /// Default routes
    pub default_routes: Vec<String>,

    /// DNS servers
    pub dns_servers: Vec<String>,

    /// Enable packet forwarding
    pub packet_forwarding: bool,

    /// Route table ID
    pub route_table_id: Option<u32>,
}

impl Default for TunnelConfig {
    fn default() -> Self {
        Self {
            interface_name: "gwire0".to_string(),
            mtu: 1420,
            ipv4: true,
            ipv6: true,
            default_routes: vec![],
            dns_servers: vec![],
            packet_forwarding: false,
            route_table_id: None,
        }
    }
}