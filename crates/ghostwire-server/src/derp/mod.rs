/// DERP (Designated Encrypted Relay Protocol) server implementation
///
/// Provides a high-performance QUIC-based relay server for NAT traversal
/// and mesh connectivity when direct connections are not possible.
/// Based on Tailscale's DERP protocol with GhostWire enhancements.

pub mod server;
pub mod client;
pub mod protocol;
pub mod mesh;
pub mod stun;

pub use server::DerpServer;
pub use client::DerpClient;
pub use protocol::*;
pub use mesh::DerpMesh;
pub use stun::StunServer;

use ghostwire_common::{
    types::*,
    error::{Result, GhostWireError},
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::{SystemTime, Duration};
use uuid::Uuid;

/// DERP server configuration
#[derive(Debug, Clone, Deserialize)]
pub struct DerpConfig {
    /// Enable DERP relay
    pub enabled: bool,

    /// Listen address for DERP
    pub listen_addr: String,

    /// HTTPS listen port
    pub https_port: u16,

    /// STUN listen port
    pub stun_port: u16,

    /// QUIC configuration
    pub quic: QuicConfig,

    /// STUN configuration
    pub stun: StunConfig,

    /// Mesh configuration
    pub mesh: MeshConfig,

    /// Rate limiting configuration
    pub rate_limiting: RateLimitConfig,

    /// Regional configuration
    pub region: RegionConfig,

    /// TLS configuration
    pub tls: TlsConfig,

    /// Metrics configuration
    pub metrics: MetricsConfig,
}

impl Default for DerpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen_addr: "0.0.0.0".to_string(),
            https_port: 443,
            stun_port: 3478,
            quic: QuicConfig::default(),
            stun: StunConfig::default(),
            mesh: MeshConfig::default(),
            rate_limiting: RateLimitConfig::default(),
            region: RegionConfig::default(),
            tls: TlsConfig::default(),
            metrics: MetricsConfig::default(),
        }
    }
}

/// QUIC configuration
#[derive(Debug, Clone, Deserialize)]
pub struct QuicConfig {
    /// Enable QUIC transport
    pub enabled: bool,

    /// Maximum concurrent connections
    pub max_connections: u32,

    /// Connection idle timeout (seconds)
    pub idle_timeout_seconds: u64,

    /// Keep-alive interval (seconds)
    pub keep_alive_seconds: u64,

    /// Maximum packet size
    pub max_packet_size: u16,

    /// Initial congestion window
    pub initial_congestion_window: u32,

    /// Enable 0-RTT
    pub enable_0rtt: bool,
}

impl Default for QuicConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_connections: 10000,
            idle_timeout_seconds: 60,
            keep_alive_seconds: 25,
            max_packet_size: 1350,
            initial_congestion_window: 32,
            enable_0rtt: true,
        }
    }
}

/// STUN configuration
#[derive(Debug, Clone, Deserialize)]
pub struct StunConfig {
    /// Enable STUN server
    pub enabled: bool,

    /// Enable fingerprint validation
    pub validate_fingerprint: bool,

    /// Software identifier
    pub software: String,

    /// Rate limiting per IP
    pub rate_limit_per_ip: u32,

    /// Rate limit window (seconds)
    pub rate_limit_window: u64,
}

impl Default for StunConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            validate_fingerprint: true,
            software: "GhostWire STUN Server".to_string(),
            rate_limit_per_ip: 100,
            rate_limit_window: 60,
        }
    }
}

/// Mesh configuration
#[derive(Debug, Clone, Deserialize)]
pub struct MeshConfig {
    /// Enable mesh networking
    pub enabled: bool,

    /// Mesh peers
    pub peers: Vec<MeshPeer>,

    /// Mesh key for authentication
    pub mesh_key: Option<String>,

    /// Forwarding policy
    pub forwarding_policy: ForwardingPolicy,

    /// Regional forwarding enabled
    pub regional_forwarding: bool,
}

impl Default for MeshConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            peers: vec![],
            mesh_key: None,
            forwarding_policy: ForwardingPolicy::RestrictedForwarding,
            regional_forwarding: true,
        }
    }
}

/// Mesh peer configuration
#[derive(Debug, Clone, Deserialize)]
pub struct MeshPeer {
    /// Peer hostname
    pub hostname: String,

    /// Peer region ID
    pub region_id: u16,

    /// Peer public key
    pub public_key: Option<String>,

    /// Peer priority
    pub priority: u8,
}

/// Forwarding policy
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ForwardingPolicy {
    /// No forwarding
    NoForwarding,
    /// Restricted forwarding (same user only)
    RestrictedForwarding,
    /// Open forwarding (any authenticated user)
    OpenForwarding,
}

/// Rate limiting configuration
#[derive(Debug, Clone, Deserialize)]
pub struct RateLimitConfig {
    /// Enable rate limiting
    pub enabled: bool,

    /// Connections per IP per minute
    pub connections_per_ip_per_minute: u32,

    /// Bytes per connection per second
    pub bytes_per_connection_per_second: u64,

    /// Maximum concurrent connections per IP
    pub max_connections_per_ip: u32,

    /// Ban duration for rate limit violations (seconds)
    pub ban_duration_seconds: u64,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            connections_per_ip_per_minute: 60,
            bytes_per_connection_per_second: 1024 * 1024, // 1MB/s
            max_connections_per_ip: 100,
            ban_duration_seconds: 300, // 5 minutes
        }
    }
}

/// Regional configuration
#[derive(Debug, Clone, Deserialize)]
pub struct RegionConfig {
    /// Region ID
    pub region_id: u16,

    /// Region name
    pub region_name: String,

    /// Geographic location
    pub location: String,

    /// Geographic coordinates
    pub coordinates: Option<(f64, f64)>,

    /// Avoid this region
    pub avoid: bool,

    /// Regional tags
    pub tags: Vec<String>,
}

impl Default for RegionConfig {
    fn default() -> Self {
        Self {
            region_id: 1,
            region_name: "default".to_string(),
            location: "Unknown".to_string(),
            coordinates: None,
            avoid: false,
            tags: vec![],
        }
    }
}

/// TLS configuration
#[derive(Debug, Clone, Deserialize)]
pub struct TlsConfig {
    /// Certificate file path
    pub cert_file: Option<String>,

    /// Private key file path
    pub key_file: Option<String>,

    /// Enable automatic certificate generation
    pub auto_cert: bool,

    /// Certificate domains
    pub domains: Vec<String>,

    /// ACME directory URL
    pub acme_directory: Option<String>,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            cert_file: None,
            key_file: None,
            auto_cert: false,
            domains: vec![],
            acme_directory: Some("https://acme-v02.api.letsencrypt.org/directory".to_string()),
        }
    }
}

/// Metrics configuration
#[derive(Debug, Clone, Deserialize)]
pub struct MetricsConfig {
    /// Enable metrics collection
    pub enabled: bool,

    /// Metrics endpoint path
    pub endpoint: String,

    /// Enable detailed connection metrics
    pub detailed_metrics: bool,

    /// Metrics retention duration (seconds)
    pub retention_seconds: u64,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            endpoint: "/metrics".to_string(),
            detailed_metrics: false,
            retention_seconds: 3600, // 1 hour
        }
    }
}

/// DERP connection information
#[derive(Debug, Clone, Serialize)]
pub struct DerpConnectionInfo {
    /// Connection ID
    pub connection_id: Uuid,

    /// Client node ID
    pub node_id: Option<NodeId>,

    /// Client address
    pub client_addr: SocketAddr,

    /// Connection established at
    pub connected_at: SystemTime,

    /// Last activity
    pub last_activity: SystemTime,

    /// Bytes sent
    pub bytes_sent: u64,

    /// Bytes received
    pub bytes_received: u64,

    /// Connection type
    pub connection_type: ConnectionType,

    /// Regional preference
    pub preferred_region: Option<u16>,
}

/// Connection type
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionType {
    /// QUIC connection
    Quic,
    /// WebSocket connection
    WebSocket,
    /// HTTP connection
    Http,
    /// STUN connection
    Stun,
}

/// DERP service statistics
#[derive(Debug, Clone, Serialize)]
pub struct DerpStats {
    /// Active connections
    pub active_connections: u32,

    /// Total connections since start
    pub total_connections: u64,

    /// Bytes relayed
    pub bytes_relayed: u64,

    /// Packets relayed
    pub packets_relayed: u64,

    /// Average latency (ms)
    pub average_latency_ms: f64,

    /// Regional stats
    pub regional_stats: HashMap<u16, RegionalStats>,

    /// Rate limiting stats
    pub rate_limit_stats: RateLimitStats,

    /// Uptime
    pub uptime_seconds: u64,
}

/// Regional statistics
#[derive(Debug, Clone, Serialize)]
pub struct RegionalStats {
    /// Region ID
    pub region_id: u16,

    /// Active connections in region
    pub active_connections: u32,

    /// Bytes relayed in region
    pub bytes_relayed: u64,

    /// Average latency in region (ms)
    pub average_latency_ms: f64,
}

/// Rate limiting statistics
#[derive(Debug, Clone, Serialize)]
pub struct RateLimitStats {
    /// Currently banned IPs
    pub banned_ips: u32,

    /// Rate limit violations in last hour
    pub violations_last_hour: u32,

    /// Connections dropped due to rate limiting
    pub dropped_connections: u64,
}

/// DERP service error types
#[derive(Debug, thiserror::Error)]
pub enum DerpError {
    #[error("Configuration error: {0}")]
    Configuration(String),

    #[error("Network error: {0}")]
    Network(String),

    #[error("Protocol error: {0}")]
    Protocol(String),

    #[error("Authentication error: {0}")]
    Authentication(String),

    #[error("Rate limit exceeded: {0}")]
    RateLimit(String),

    #[error("Mesh error: {0}")]
    Mesh(String),

    #[error("TLS error: {0}")]
    Tls(String),
}

impl From<DerpError> for GhostWireError {
    fn from(err: DerpError) -> Self {
        match err {
            DerpError::Configuration(msg) => GhostWireError::configuration(msg),
            DerpError::Network(msg) => GhostWireError::network(msg),
            DerpError::Protocol(msg) => GhostWireError::protocol(msg),
            DerpError::Authentication(msg) => GhostWireError::authentication(msg),
            DerpError::RateLimit(msg) => GhostWireError::rate_limit(msg),
            DerpError::Mesh(msg) => GhostWireError::network(msg),
            DerpError::Tls(msg) => GhostWireError::crypto(msg),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derp_config_default() {
        let config = DerpConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.https_port, 443);
        assert_eq!(config.stun_port, 3478);
        assert!(config.quic.enabled);
    }

    #[test]
    fn test_quic_config_default() {
        let config = QuicConfig::default();
        assert!(config.enabled);
        assert_eq!(config.max_connections, 10000);
        assert_eq!(config.idle_timeout_seconds, 60);
        assert_eq!(config.max_packet_size, 1350);
    }

    #[test]
    fn test_rate_limit_config_default() {
        let config = RateLimitConfig::default();
        assert!(config.enabled);
        assert_eq!(config.connections_per_ip_per_minute, 60);
        assert_eq!(config.bytes_per_connection_per_second, 1024 * 1024);
        assert_eq!(config.ban_duration_seconds, 300);
    }

    #[test]
    fn test_forwarding_policy_serialization() {
        let policy = ForwardingPolicy::RestrictedForwarding;
        let serialized = serde_json::to_string(&policy).unwrap();
        assert!(serialized.contains("restricted_forwarding"));
    }

    #[test]
    fn test_connection_type_serialization() {
        let conn_type = ConnectionType::Quic;
        let serialized = serde_json::to_string(&conn_type).unwrap();
        assert!(serialized.contains("quic"));
    }

    #[test]
    fn test_derp_error_conversion() {
        let derp_error = DerpError::Configuration("test error".to_string());
        let ghostwire_error: GhostWireError = derp_error.into();

        match ghostwire_error {
            GhostWireError::Configuration { .. } => {
                // Expected
            }
            _ => panic!("Unexpected error type"),
        }
    }
}