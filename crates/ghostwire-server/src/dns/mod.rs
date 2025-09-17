/// MagicDNS implementation with split-DNS and backends
///
/// Provides DNS resolution for the mesh network with automatic
/// node name resolution, split-DNS capabilities, and backend integration.

pub mod resolver;
pub mod server;
pub mod backends;
pub mod records;

pub use resolver::DnsResolver;
pub use server::DnsServer;
pub use backends::*;
pub use records::*;

use ghostwire_common::{
    types::*,
    error::{Result, GhostWireError},
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{SystemTime, Duration};
use trust_dns_server::proto::rr::{Name, RecordType};

/// DNS configuration
#[derive(Debug, Clone, Deserialize)]
pub struct DnsConfig {
    /// Enable MagicDNS
    pub enabled: bool,

    /// DNS listen address
    pub listen_addr: String,

    /// DNS listen port
    pub listen_port: u16,

    /// Base domain for the mesh
    pub base_domain: String,

    /// Upstream DNS servers
    pub upstream_servers: Vec<IpAddr>,

    /// Split DNS configuration
    pub split_dns: SplitDnsConfig,

    /// Backend configuration
    pub backends: BackendConfig,

    /// Cache configuration
    pub cache: CacheConfig,

    /// Security configuration
    pub security: DnsSecurityConfig,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            listen_addr: "0.0.0.0".to_string(),
            listen_port: 53,
            base_domain: "ghost".to_string(),
            upstream_servers: vec![
                IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),    // Cloudflare
                IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),    // Google
            ],
            split_dns: SplitDnsConfig::default(),
            backends: BackendConfig::default(),
            cache: CacheConfig::default(),
            security: DnsSecurityConfig::default(),
        }
    }
}

/// Split DNS configuration
#[derive(Debug, Clone, Deserialize)]
pub struct SplitDnsConfig {
    /// Enable split DNS
    pub enabled: bool,

    /// Internal domains (resolved locally)
    pub internal_domains: Vec<String>,

    /// External domains (forwarded to upstream)
    pub external_domains: Vec<String>,

    /// Override rules
    pub overrides: Vec<DnsOverride>,

    /// Default behavior for unknown domains
    pub default_behavior: DefaultBehavior,
}

impl Default for SplitDnsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            internal_domains: vec![
                "ghost".to_string(),
                "mesh.local".to_string(),
                "ghostwire.internal".to_string(),
            ],
            external_domains: vec![],
            overrides: vec![],
            default_behavior: DefaultBehavior::Forward,
        }
    }
}

/// DNS override rule
#[derive(Debug, Clone, Deserialize)]
pub struct DnsOverride {
    /// Domain pattern (supports wildcards)
    pub pattern: String,

    /// Override action
    pub action: OverrideAction,

    /// Target servers (for Forward action)
    pub servers: Option<Vec<IpAddr>>,

    /// Static record (for Static action)
    pub record: Option<StaticRecord>,
}

/// Override action
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OverrideAction {
    /// Block the domain
    Block,
    /// Forward to specific servers
    Forward,
    /// Return static record
    Static,
    /// Use internal resolution
    Internal,
}

/// Default behavior for unknown domains
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DefaultBehavior {
    /// Forward to upstream
    Forward,
    /// Block all unknown domains
    Block,
    /// Return NXDOMAIN
    Nxdomain,
}

/// Static DNS record
#[derive(Debug, Clone, Deserialize)]
pub struct StaticRecord {
    /// Record type
    pub record_type: String,
    /// Record value
    pub value: String,
    /// TTL in seconds
    pub ttl: u32,
}

/// Backend configuration
#[derive(Debug, Clone, Deserialize)]
pub struct BackendConfig {
    /// Coordinator backend
    pub coordinator: CoordinatorBackend,

    /// File backend
    pub file: Option<FileBackend>,

    /// External API backend
    pub external_api: Option<ExternalApiBackend>,

    /// Redis backend
    pub redis: Option<RedisBackend>,
}

impl Default for BackendConfig {
    fn default() -> Self {
        Self {
            coordinator: CoordinatorBackend::default(),
            file: None,
            external_api: None,
            redis: None,
        }
    }
}

/// Coordinator backend configuration
#[derive(Debug, Clone, Deserialize)]
pub struct CoordinatorBackend {
    /// Enable coordinator backend
    pub enabled: bool,

    /// Auto-generate node records
    pub auto_generate_nodes: bool,

    /// Node name format
    pub node_name_format: String,

    /// Include IPv6 records
    pub include_ipv6: bool,

    /// TTL for node records
    pub node_ttl: u32,
}

impl Default for CoordinatorBackend {
    fn default() -> Self {
        Self {
            enabled: true,
            auto_generate_nodes: true,
            node_name_format: "{name}.{user}.ghost".to_string(),
            include_ipv6: true,
            node_ttl: 300,
        }
    }
}

/// File backend configuration
#[derive(Debug, Clone, Deserialize)]
pub struct FileBackend {
    /// Enable file backend
    pub enabled: bool,

    /// Zone file path
    pub zone_file: String,

    /// Watch file for changes
    pub watch_changes: bool,

    /// Reload interval (seconds)
    pub reload_interval: u64,
}

/// External API backend configuration
#[derive(Debug, Clone, Deserialize)]
pub struct ExternalApiBackend {
    /// Enable external API backend
    pub enabled: bool,

    /// API endpoint URL
    pub endpoint: String,

    /// API key
    pub api_key: Option<String>,

    /// Request timeout (seconds)
    pub timeout: u64,

    /// Cache TTL (seconds)
    pub cache_ttl: u32,
}

/// Redis backend configuration
#[derive(Debug, Clone, Deserialize)]
pub struct RedisBackend {
    /// Enable Redis backend
    pub enabled: bool,

    /// Redis URL
    pub url: String,

    /// Key prefix
    pub key_prefix: String,

    /// Connection timeout (seconds)
    pub timeout: u64,
}

/// DNS cache configuration
#[derive(Debug, Clone, Deserialize)]
pub struct CacheConfig {
    /// Enable caching
    pub enabled: bool,

    /// Maximum cache entries
    pub max_entries: usize,

    /// Default TTL (seconds)
    pub default_ttl: u32,

    /// Minimum TTL (seconds)
    pub min_ttl: u32,

    /// Maximum TTL (seconds)
    pub max_ttl: u32,

    /// Negative cache TTL (seconds)
    pub negative_ttl: u32,

    /// Cache cleanup interval (seconds)
    pub cleanup_interval: u64,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_entries: 10000,
            default_ttl: 300,
            min_ttl: 30,
            max_ttl: 3600,
            negative_ttl: 60,
            cleanup_interval: 300,
        }
    }
}

/// DNS security configuration
#[derive(Debug, Clone, Deserialize)]
pub struct DnsSecurityConfig {
    /// Enable rate limiting
    pub rate_limiting: bool,

    /// Queries per IP per minute
    pub queries_per_ip_per_minute: u32,

    /// Enable query logging
    pub query_logging: bool,

    /// Block suspicious queries
    pub block_suspicious: bool,

    /// Allowed query types
    pub allowed_query_types: Vec<String>,

    /// Enable DNSSEC
    pub dnssec: bool,
}

impl Default for DnsSecurityConfig {
    fn default() -> Self {
        Self {
            rate_limiting: true,
            queries_per_ip_per_minute: 300,
            query_logging: true,
            block_suspicious: true,
            allowed_query_types: vec![
                "A".to_string(),
                "AAAA".to_string(),
                "CNAME".to_string(),
                "MX".to_string(),
                "TXT".to_string(),
                "SRV".to_string(),
                "PTR".to_string(),
            ],
            dnssec: false,
        }
    }
}

/// DNS query context
#[derive(Debug, Clone)]
pub struct DnsQueryContext {
    /// Client IP address
    pub client_ip: IpAddr,

    /// Query name
    pub query_name: Name,

    /// Query type
    pub query_type: RecordType,

    /// Query timestamp
    pub timestamp: SystemTime,

    /// Source interface
    pub interface: String,

    /// Query ID
    pub query_id: u16,
}

/// DNS response
#[derive(Debug, Clone)]
pub struct DnsResponse {
    /// Response records
    pub records: Vec<DnsRecord>,

    /// Authority records
    pub authority: Vec<DnsRecord>,

    /// Additional records
    pub additional: Vec<DnsRecord>,

    /// Response code
    pub response_code: ResponseCode,

    /// TTL for the response
    pub ttl: u32,

    /// Source backend
    pub source: ResponseSource,
}

/// Response code
#[derive(Debug, Clone, PartialEq)]
pub enum ResponseCode {
    NoError,
    FormErr,
    ServFail,
    NXDomain,
    NotImp,
    Refused,
}

/// Response source
#[derive(Debug, Clone)]
pub enum ResponseSource {
    Cache,
    Coordinator,
    File,
    ExternalApi,
    Redis,
    Upstream,
    Static,
}

/// DNS service statistics
#[derive(Debug, Clone, Serialize)]
pub struct DnsStats {
    /// Total queries received
    pub total_queries: u64,

    /// Queries by type
    pub queries_by_type: HashMap<String, u64>,

    /// Responses by source
    pub responses_by_source: HashMap<String, u64>,

    /// Cache hit rate
    pub cache_hit_rate: f64,

    /// Average response time (ms)
    pub average_response_time_ms: f64,

    /// Rate limited queries
    pub rate_limited_queries: u64,

    /// Blocked queries
    pub blocked_queries: u64,

    /// Upstream queries
    pub upstream_queries: u64,

    /// Cache statistics
    pub cache_stats: CacheStats,
}

/// Cache statistics
#[derive(Debug, Clone, Serialize)]
pub struct CacheStats {
    /// Current cache size
    pub current_size: usize,

    /// Cache hits
    pub cache_hits: u64,

    /// Cache misses
    pub cache_misses: u64,

    /// Cache evictions
    pub cache_evictions: u64,

    /// Memory usage (bytes)
    pub memory_usage: usize,
}

/// DNS service error types
#[derive(Debug, thiserror::Error)]
pub enum DnsError {
    #[error("Configuration error: {0}")]
    Configuration(String),

    #[error("Query error: {0}")]
    Query(String),

    #[error("Backend error: {0}")]
    Backend(String),

    #[error("Cache error: {0}")]
    Cache(String),

    #[error("Network error: {0}")]
    Network(String),

    #[error("Rate limit exceeded: {0}")]
    RateLimit(String),

    #[error("Security violation: {0}")]
    Security(String),
}

impl From<DnsError> for GhostWireError {
    fn from(err: DnsError) -> Self {
        match err {
            DnsError::Configuration(msg) => GhostWireError::configuration(msg),
            DnsError::Query(msg) => GhostWireError::protocol(msg),
            DnsError::Backend(msg) => GhostWireError::internal(msg),
            DnsError::Cache(msg) => GhostWireError::internal(msg),
            DnsError::Network(msg) => GhostWireError::network(msg),
            DnsError::RateLimit(msg) => GhostWireError::rate_limit(msg),
            DnsError::Security(msg) => GhostWireError::security(msg),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_config_default() {
        let config = DnsConfig::default();
        assert!(config.enabled);
        assert_eq!(config.listen_port, 53);
        assert_eq!(config.base_domain, "ghost");
        assert!(!config.upstream_servers.is_empty());
    }

    #[test]
    fn test_split_dns_config_default() {
        let config = SplitDnsConfig::default();
        assert!(config.enabled);
        assert!(config.internal_domains.contains(&"ghost".to_string()));
        assert!(matches!(config.default_behavior, DefaultBehavior::Forward));
    }

    #[test]
    fn test_cache_config_default() {
        let config = CacheConfig::default();
        assert!(config.enabled);
        assert_eq!(config.max_entries, 10000);
        assert_eq!(config.default_ttl, 300);
        assert!(config.min_ttl < config.max_ttl);
    }

    #[test]
    fn test_coordinator_backend_default() {
        let backend = CoordinatorBackend::default();
        assert!(backend.enabled);
        assert!(backend.auto_generate_nodes);
        assert_eq!(backend.node_name_format, "{name}.{user}.ghost");
        assert!(backend.include_ipv6);
    }

    #[test]
    fn test_dns_security_config_default() {
        let security = DnsSecurityConfig::default();
        assert!(security.rate_limiting);
        assert!(security.query_logging);
        assert!(security.allowed_query_types.contains(&"A".to_string()));
        assert!(security.allowed_query_types.contains(&"AAAA".to_string()));
    }

    #[test]
    fn test_response_code_equality() {
        assert_eq!(ResponseCode::NoError, ResponseCode::NoError);
        assert_ne!(ResponseCode::NoError, ResponseCode::NXDomain);
    }

    #[test]
    fn test_dns_error_conversion() {
        let dns_error = DnsError::Configuration("test error".to_string());
        let ghostwire_error: GhostWireError = dns_error.into();

        match ghostwire_error {
            GhostWireError::Configuration { .. } => {
                // Expected
            }
            _ => panic!("Unexpected error type"),
        }
    }
}