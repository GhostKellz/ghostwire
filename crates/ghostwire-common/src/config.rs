use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

/// Server configuration - simplified and cleaner than Headscale
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub server: ServerSettings,
    pub database: DatabaseConfig,
    pub auth: AuthConfig,
    pub network: NetworkConfig,
    pub derp: DerpConfig,
    pub dns: DnsConfig,
    pub policy: PolicyConfig,
    pub observability: ObservabilityConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerSettings {
    /// Listen address for HTTP/gRPC API
    #[serde(default = "default_listen_addr")]
    pub listen_addr: String,

    /// TLS certificate path (optional, enables HTTPS)
    pub tls_cert_path: Option<PathBuf>,

    /// TLS private key path
    pub tls_key_path: Option<PathBuf>,

    /// Server base URL for client callbacks
    #[serde(default = "default_base_url")]
    pub base_url: String,

    /// Enable gRPC reflection for debugging
    #[serde(default)]
    pub grpc_reflection: bool,

    /// Request timeout
    #[serde(default = "default_request_timeout", with = "humantime_serde")]
    pub request_timeout: Duration,

    /// Maximum request size
    #[serde(default = "default_max_request_size")]
    pub max_request_size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    /// Database file path
    #[serde(default = "default_db_path")]
    pub path: PathBuf,

    /// Cache size for zqlite
    #[serde(default = "default_cache_size")]
    pub cache_size: String,

    /// Enable parallel writes
    #[serde(default = "default_parallel_writes")]
    pub parallel_writes: bool,

    /// Compression level (none, low, high)
    #[serde(default = "default_compression")]
    pub compression: CompressionLevel,

    /// Backup interval
    #[serde(default, with = "humantime_serde")]
    pub backup_interval: Option<Duration>,

    /// Backup retention (number of backups to keep)
    #[serde(default = "default_backup_retention")]
    pub backup_retention: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CompressionLevel {
    None,
    Low,
    High,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    /// Authentication method
    pub method: AuthMethod,

    /// OIDC configuration (if using OIDC)
    pub oidc: Option<OidcConfig>,

    /// Session timeout
    #[serde(default = "default_session_timeout", with = "humantime_serde")]
    pub session_timeout: Duration,

    /// Allow ephemeral nodes (auto-delete when offline)
    #[serde(default)]
    pub allow_ephemeral: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthMethod {
    /// CLI-based registration only
    Cli,
    /// OIDC/OAuth2 authentication
    Oidc,
    /// Both CLI and OIDC
    Hybrid,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcConfig {
    /// OIDC issuer URL
    pub issuer_url: String,

    /// Client ID
    pub client_id: String,

    /// Client secret
    pub client_secret: String,

    /// Additional scopes to request
    #[serde(default)]
    pub scopes: Vec<String>,

    /// Domain restriction (only allow users from these domains)
    pub allowed_domains: Option<Vec<String>>,

    /// User/group mapping
    #[serde(default)]
    pub group_mapping: HashMap<String, Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// IP prefix for the tailnet
    #[serde(default = "default_ip_prefix")]
    pub ip_prefix: String,

    /// IPv6 prefix (optional)
    pub ipv6_prefix: Option<String>,

    /// Default route advertisements
    #[serde(default)]
    pub advertise_routes: Vec<String>,

    /// Enable exit node functionality
    #[serde(default)]
    pub enable_exit_node: bool,

    /// Node expiry time
    #[serde(default = "default_node_expiry", with = "humantime_serde")]
    pub node_expiry: Duration,

    /// Keepalive interval
    #[serde(default = "default_keepalive", with = "humantime_serde")]
    pub keepalive_interval: Duration,

    /// Enable QUIC for direct connections
    #[serde(default = "default_enable_quic")]
    pub enable_quic: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DerpConfig {
    /// Enable embedded DERP server
    #[serde(default)]
    pub enabled: bool,

    /// DERP server listen port
    #[serde(default = "default_derp_port")]
    pub listen_port: u16,

    /// STUN server port
    #[serde(default = "default_stun_port")]
    pub stun_port: u16,

    /// Public IPv4 address (for DERP map)
    pub public_ipv4: Option<IpAddr>,

    /// Public IPv6 address (for DERP map)
    pub public_ipv6: Option<IpAddr>,

    /// Verify connecting clients
    #[serde(default = "default_verify_clients")]
    pub verify_clients: bool,

    /// External DERP servers to include
    #[serde(default)]
    pub external_derp_urls: Vec<String>,

    /// Custom DERP map
    pub custom_derp_map: Option<PathBuf>,

    /// Enable QUIC for DERP relay
    #[serde(default = "default_derp_quic")]
    pub enable_quic: bool,

    /// DERP mesh with other servers
    #[serde(default)]
    pub mesh_peers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsConfig {
    /// Enable MagicDNS
    #[serde(default = "default_magic_dns")]
    pub magic_dns: bool,

    /// Base domain for MagicDNS
    #[serde(default = "default_base_domain")]
    pub base_domain: String,

    /// Upstream DNS servers
    #[serde(default = "default_nameservers")]
    pub nameservers: Vec<IpAddr>,

    /// Search domains
    #[serde(default)]
    pub search_domains: Vec<String>,

    /// Extra DNS records
    #[serde(default)]
    pub extra_records: Vec<DnsRecord>,

    /// Path to dynamic DNS records file
    pub extra_records_path: Option<PathBuf>,

    /// Enable split-DNS
    #[serde(default)]
    pub split_dns: bool,

    /// DNS backends (CloudFlare, PowerDNS, etc.)
    #[serde(default)]
    pub backends: Vec<DnsBackend>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRecord {
    pub name: String,
    #[serde(rename = "type")]
    pub record_type: String,
    pub value: String,
    pub ttl: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsBackend {
    pub name: String,
    pub backend_type: String,
    pub config: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    /// Policy mode (file or database)
    #[serde(default = "default_policy_mode")]
    pub mode: PolicyMode,

    /// ACL policy file path
    pub policy_path: Option<PathBuf>,

    /// Enable policy enforcement
    #[serde(default = "default_enable_policy")]
    pub enable_acl: bool,

    /// Default action when no ACL matches
    #[serde(default = "default_acl_action")]
    pub default_action: AclAction,

    /// Allow localhost access
    #[serde(default = "default_allow_localhost")]
    pub allow_localhost: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicyMode {
    File,
    Database,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AclAction {
    Accept,
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservabilityConfig {
    /// Metrics configuration
    pub metrics: MetricsConfig,

    /// Logging configuration
    pub logging: LoggingConfig,

    /// Tracing configuration
    pub tracing: TracingConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsConfig {
    /// Enable Prometheus metrics
    #[serde(default = "default_enable_metrics")]
    pub enabled: bool,

    /// Metrics listen address
    #[serde(default = "default_metrics_addr")]
    pub listen_addr: String,

    /// Metrics path
    #[serde(default = "default_metrics_path")]
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Log level
    #[serde(default = "default_log_level")]
    pub level: String,

    /// Enable JSON logging
    #[serde(default)]
    pub json: bool,

    /// Log file path (optional)
    pub file: Option<PathBuf>,

    /// Log rotation size
    #[serde(default = "default_log_rotation_size")]
    pub rotation_size: String,

    /// Log retention days
    #[serde(default = "default_log_retention")]
    pub retention_days: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TracingConfig {
    /// Enable distributed tracing
    #[serde(default)]
    pub enabled: bool,

    /// Tracing endpoint (Jaeger, etc.)
    pub endpoint: Option<String>,

    /// Service name for tracing
    #[serde(default = "default_service_name")]
    pub service_name: String,

    /// Sampling rate (0.0 to 1.0)
    #[serde(default = "default_sampling_rate")]
    pub sampling_rate: f64,
}

// Default value functions
fn default_listen_addr() -> String { "0.0.0.0:8080".to_string() }
fn default_base_url() -> String { "http://localhost:8080".to_string() }
fn default_request_timeout() -> Duration { Duration::from_secs(30) }
fn default_max_request_size() -> usize { 64 * 1024 * 1024 } // 64MB

fn default_db_path() -> PathBuf { PathBuf::from("/var/lib/ghostwire/ghostwire.zqlite") }
fn default_cache_size() -> String { "256MB".to_string() }
fn default_parallel_writes() -> bool { true }
fn default_compression() -> CompressionLevel { CompressionLevel::High }
fn default_backup_retention() -> u32 { 7 }

fn default_session_timeout() -> Duration { Duration::from_secs(24 * 60 * 60) } // 24 hours

fn default_ip_prefix() -> String { "100.64.0.0/10".to_string() }
fn default_node_expiry() -> Duration { Duration::from_secs(180 * 24 * 60 * 60) } // 180 days
fn default_keepalive() -> Duration { Duration::from_secs(60) }
fn default_enable_quic() -> bool { true }

fn default_derp_port() -> u16 { 3478 }
fn default_stun_port() -> u16 { 3478 }
fn default_verify_clients() -> bool { true }
fn default_derp_quic() -> bool { true }

fn default_magic_dns() -> bool { true }
fn default_base_domain() -> String { "ghostwire.local".to_string() }
fn default_nameservers() -> Vec<IpAddr> {
    vec!["1.1.1.1".parse().unwrap(), "8.8.8.8".parse().unwrap()]
}

fn default_policy_mode() -> PolicyMode { PolicyMode::File }
fn default_enable_policy() -> bool { true }
fn default_acl_action() -> AclAction { AclAction::Deny }
fn default_allow_localhost() -> bool { true }

fn default_enable_metrics() -> bool { true }
fn default_metrics_addr() -> String { "0.0.0.0:9090".to_string() }
fn default_metrics_path() -> String { "/metrics".to_string() }

fn default_log_level() -> String { "info".to_string() }
fn default_log_rotation_size() -> String { "100MB".to_string() }
fn default_log_retention() -> u32 { 30 }

fn default_service_name() -> String { "ghostwire-server".to_string() }
fn default_sampling_rate() -> f64 { 0.1 }

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            server: ServerSettings {
                listen_addr: default_listen_addr(),
                tls_cert_path: None,
                tls_key_path: None,
                base_url: default_base_url(),
                grpc_reflection: false,
                request_timeout: default_request_timeout(),
                max_request_size: default_max_request_size(),
            },
            database: DatabaseConfig {
                path: default_db_path(),
                cache_size: default_cache_size(),
                parallel_writes: default_parallel_writes(),
                compression: default_compression(),
                backup_interval: None,
                backup_retention: default_backup_retention(),
            },
            auth: AuthConfig {
                method: AuthMethod::Cli,
                oidc: None,
                session_timeout: default_session_timeout(),
                allow_ephemeral: false,
            },
            network: NetworkConfig {
                ip_prefix: default_ip_prefix(),
                ipv6_prefix: None,
                advertise_routes: vec![],
                enable_exit_node: false,
                node_expiry: default_node_expiry(),
                keepalive_interval: default_keepalive(),
                enable_quic: default_enable_quic(),
            },
            derp: DerpConfig {
                enabled: false,
                listen_port: default_derp_port(),
                stun_port: default_stun_port(),
                public_ipv4: None,
                public_ipv6: None,
                verify_clients: default_verify_clients(),
                external_derp_urls: vec![],
                custom_derp_map: None,
                enable_quic: default_derp_quic(),
                mesh_peers: vec![],
            },
            dns: DnsConfig {
                magic_dns: default_magic_dns(),
                base_domain: default_base_domain(),
                nameservers: default_nameservers(),
                search_domains: vec![],
                extra_records: vec![],
                extra_records_path: None,
                split_dns: false,
                backends: vec![],
            },
            policy: PolicyConfig {
                mode: default_policy_mode(),
                policy_path: None,
                enable_acl: default_enable_policy(),
                default_action: default_acl_action(),
                allow_localhost: default_allow_localhost(),
            },
            observability: ObservabilityConfig {
                metrics: MetricsConfig {
                    enabled: default_enable_metrics(),
                    listen_addr: default_metrics_addr(),
                    path: default_metrics_path(),
                },
                logging: LoggingConfig {
                    level: default_log_level(),
                    json: false,
                    file: None,
                    rotation_size: default_log_rotation_size(),
                    retention_days: default_log_retention(),
                },
                tracing: TracingConfig {
                    enabled: false,
                    endpoint: None,
                    service_name: default_service_name(),
                    sampling_rate: default_sampling_rate(),
                },
            },
        }
    }
}

impl ServerConfig {
    /// Generate example configuration with detailed comments
    pub fn example() -> Self {
        Self {
            server: ServerSettings {
                listen_addr: "0.0.0.0:8080".to_string(),
                tls_cert_path: Some(PathBuf::from("/etc/ghostwire/tls.crt")),
                tls_key_path: Some(PathBuf::from("/etc/ghostwire/tls.key")),
                base_url: "https://ghostwire.example.com".to_string(),
                grpc_reflection: true,
                request_timeout: Duration::from_secs(30),
                max_request_size: 64 * 1024 * 1024,
            },
            database: DatabaseConfig {
                path: PathBuf::from("/var/lib/ghostwire/ghostwire.zqlite"),
                cache_size: "512MB".to_string(),
                parallel_writes: true,
                compression: CompressionLevel::High,
                backup_interval: Some(Duration::from_secs(6 * 60 * 60)), // 6 hours
                backup_retention: 14,
            },
            auth: AuthConfig {
                method: AuthMethod::Oidc,
                oidc: Some(OidcConfig {
                    issuer_url: "https://accounts.google.com".to_string(),
                    client_id: "your-client-id".to_string(),
                    client_secret: "your-client-secret".to_string(),
                    scopes: vec!["openid".to_string(), "profile".to_string(), "email".to_string()],
                    allowed_domains: Some(vec!["example.com".to_string()]),
                    group_mapping: HashMap::new(),
                }),
                session_timeout: Duration::from_secs(7 * 24 * 60 * 60), // 7 days
                allow_ephemeral: true,
            },
            network: NetworkConfig {
                ip_prefix: "100.64.0.0/10".to_string(),
                ipv6_prefix: Some("fd00:64::/48".to_string()),
                advertise_routes: vec!["10.0.0.0/8".to_string()],
                enable_exit_node: true,
                node_expiry: Duration::from_secs(180 * 24 * 60 * 60),
                keepalive_interval: Duration::from_secs(60),
                enable_quic: true,
            },
            derp: DerpConfig {
                enabled: true,
                listen_port: 3478,
                stun_port: 3478,
                public_ipv4: Some("203.0.113.1".parse().unwrap()),
                public_ipv6: Some("2001:db8::1".parse().unwrap()),
                verify_clients: true,
                external_derp_urls: vec![],
                custom_derp_map: Some(PathBuf::from("/etc/ghostwire/derp.yaml")),
                enable_quic: true,
                mesh_peers: vec!["derp2.example.com:3478".to_string()],
            },
            dns: DnsConfig {
                magic_dns: true,
                base_domain: "ghostwire.example.com".to_string(),
                nameservers: vec!["1.1.1.1".parse().unwrap(), "8.8.8.8".parse().unwrap()],
                search_domains: vec!["example.com".to_string()],
                extra_records: vec![
                    DnsRecord {
                        name: "grafana.ghostwire.example.com".to_string(),
                        record_type: "A".to_string(),
                        value: "100.64.0.10".to_string(),
                        ttl: Some(300),
                    }
                ],
                extra_records_path: Some(PathBuf::from("/etc/ghostwire/dns-records.json")),
                split_dns: true,
                backends: vec![
                    DnsBackend {
                        name: "cloudflare".to_string(),
                        backend_type: "cloudflare".to_string(),
                        config: [
                            ("api_token".to_string(), "your-cf-token".to_string()),
                            ("zone_id".to_string(), "your-zone-id".to_string()),
                        ].into_iter().collect(),
                    }
                ],
            },
            policy: PolicyConfig {
                mode: PolicyMode::File,
                policy_path: Some(PathBuf::from("/etc/ghostwire/policy.json")),
                enable_acl: true,
                default_action: AclAction::Deny,
                allow_localhost: true,
            },
            observability: ObservabilityConfig {
                metrics: MetricsConfig {
                    enabled: true,
                    listen_addr: "0.0.0.0:9090".to_string(),
                    path: "/metrics".to_string(),
                },
                logging: LoggingConfig {
                    level: "info".to_string(),
                    json: true,
                    file: Some(PathBuf::from("/var/log/ghostwire/server.log")),
                    rotation_size: "100MB".to_string(),
                    retention_days: 30,
                },
                tracing: TracingConfig {
                    enabled: true,
                    endpoint: Some("http://jaeger:14268/api/traces".to_string()),
                    service_name: "ghostwire-server".to_string(),
                    sampling_rate: 0.1,
                },
            },
        }
    }

    /// Validate configuration
    pub fn validate(&self) -> Result<(), String> {
        // Validate IP prefixes
        if let Err(e) = self.network.ip_prefix.parse::<ipnet::IpNet>() {
            return Err(format!("Invalid IP prefix: {}", e));
        }

        if let Some(ref ipv6_prefix) = self.network.ipv6_prefix {
            if let Err(e) = ipv6_prefix.parse::<ipnet::IpNet>() {
                return Err(format!("Invalid IPv6 prefix: {}", e));
            }
        }

        // Validate auth configuration
        if matches!(self.auth.method, AuthMethod::Oidc | AuthMethod::Hybrid) && self.auth.oidc.is_none() {
            return Err("OIDC configuration required when using OIDC auth method".to_string());
        }

        // Validate TLS configuration
        if self.server.tls_cert_path.is_some() != self.server.tls_key_path.is_some() {
            return Err("Both TLS certificate and key must be specified".to_string());
        }

        // Validate DERP configuration
        if self.derp.enabled && (self.derp.public_ipv4.is_none() && self.derp.public_ipv6.is_none()) {
            return Err("At least one public IP address required for DERP server".to_string());
        }

        Ok(())
    }
}