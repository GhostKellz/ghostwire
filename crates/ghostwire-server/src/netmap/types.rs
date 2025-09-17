/// Network map data structures
///
/// Defines the core data structures used for representing the network map,
/// including nodes, routes, DNS configuration, and delta updates.

use ghostwire_common::types::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::SystemTime;
use uuid::Uuid;

/// Complete network map representation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NetworkMap {
    /// Map version (incrementing)
    pub version: u64,

    /// Generation timestamp
    pub generated_at: SystemTime,

    /// Map TTL (time to live)
    pub ttl_seconds: u64,

    /// Network configuration
    pub network_config: NetworkConfig,

    /// All nodes in the network
    pub nodes: Vec<NetworkNode>,

    /// Route advertisements
    pub routes: Vec<RouteAdvertisement>,

    /// DNS configuration
    pub dns_config: Option<DnsConfig>,

    /// ACL policies (if included)
    pub policies: Option<Vec<NetworkPolicy>>,

    /// Derp relay servers
    pub derp_servers: Vec<DerpServer>,

    /// Network statistics
    pub stats: NetworkStats,

    /// Checksum for integrity verification
    pub checksum: String,
}

/// Network configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NetworkConfig {
    /// Network name
    pub name: String,

    /// IPv4 address pool
    pub ipv4_pool: String,

    /// IPv6 address pool
    pub ipv6_pool: Option<String>,

    /// Default routes
    pub default_routes: Vec<String>,

    /// Network-wide settings
    pub settings: NetworkSettings,
}

/// Network settings
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NetworkSettings {
    /// Enable IPv6
    pub enable_ipv6: bool,

    /// Enable MagicDNS
    pub enable_magic_dns: bool,

    /// Enable SSH over network
    pub enable_ssh: bool,

    /// Default keepalive interval
    pub keepalive_seconds: u64,

    /// Maximum transmission unit
    pub mtu: u16,

    /// Encryption settings
    pub encryption: EncryptionSettings,
}

/// Encryption settings
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EncryptionSettings {
    /// Encryption algorithm
    pub algorithm: String,

    /// Key rotation interval
    pub key_rotation_hours: u64,

    /// Forward secrecy enabled
    pub forward_secrecy: bool,
}

/// Network node representation in the map
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NetworkNode {
    /// Node ID
    pub id: NodeId,

    /// Node name
    pub name: String,

    /// Owner user ID
    pub owner: UserId,

    /// Primary IPv4 address
    pub ipv4: Ipv4Addr,

    /// IPv6 address
    pub ipv6: Option<Ipv6Addr>,

    /// WireGuard public key
    pub public_key: PublicKey,

    /// Node endpoints
    pub endpoints: Vec<Endpoint>,

    /// Node capabilities
    pub capabilities: NodeCapabilities,

    /// Online status
    pub online: bool,

    /// Last seen timestamp
    pub last_seen: SystemTime,

    /// Node tags
    pub tags: Vec<String>,

    /// Node-specific settings
    pub settings: NodeSettings,

    /// Connection information
    pub connection_info: ConnectionInfo,
}

/// Node capabilities
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NodeCapabilities {
    /// Can route traffic (exit node)
    pub can_route: bool,

    /// Can advertise routes
    pub can_advertise_routes: bool,

    /// Supports SSH
    pub supports_ssh: bool,

    /// Supports DERP relay
    pub supports_derp: bool,

    /// Operating system
    pub operating_system: String,

    /// Client version
    pub client_version: String,

    /// Supported features
    pub features: Vec<String>,
}

/// Node settings
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NodeSettings {
    /// Custom MTU
    pub mtu: Option<u16>,

    /// Keepalive override
    pub keepalive_seconds: Option<u64>,

    /// Exit node preference
    pub exit_node_preference: Option<NodeId>,

    /// DNS override
    pub dns_override: Option<Vec<IpAddr>>,

    /// Accept routes
    pub accept_routes: bool,

    /// Accept DNS
    pub accept_dns: bool,
}

/// Connection information
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ConnectionInfo {
    /// Preferred DERP region
    pub preferred_derp: Option<u16>,

    /// Direct connection available
    pub direct_connection: bool,

    /// Connection quality metrics
    pub quality_metrics: Option<QualityMetrics>,

    /// Bandwidth limits
    pub bandwidth_limits: Option<BandwidthLimits>,
}

/// Connection quality metrics
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct QualityMetrics {
    /// Round-trip time (ms)
    pub rtt_ms: u32,

    /// Packet loss percentage
    pub packet_loss: f32,

    /// Jitter (ms)
    pub jitter_ms: u32,

    /// Bandwidth (bytes/sec)
    pub bandwidth_bps: u64,
}

/// Bandwidth limits
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BandwidthLimits {
    /// Upload limit (bytes/sec)
    pub upload_bps: Option<u64>,

    /// Download limit (bytes/sec)
    pub download_bps: Option<u64>,

    /// Burst limit (bytes)
    pub burst_bytes: Option<u64>,
}

/// Route advertisement
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RouteAdvertisement {
    /// Advertising node
    pub node_id: NodeId,

    /// Advertised routes
    pub routes: Vec<Route>,

    /// Advertisement timestamp
    pub advertised_at: SystemTime,

    /// Route priority
    pub priority: u8,

    /// Route metrics
    pub metrics: RouteMetrics,
}

/// Route information
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Route {
    /// Destination prefix
    pub prefix: String,

    /// Route enabled
    pub enabled: bool,

    /// Route description
    pub description: Option<String>,

    /// Route tags
    pub tags: Vec<String>,
}

/// Route metrics
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RouteMetrics {
    /// Route cost
    pub cost: u32,

    /// Hop count
    pub hop_count: u8,

    /// Reliability score (0-100)
    pub reliability: u8,

    /// Bandwidth estimate (bytes/sec)
    pub bandwidth_bps: u64,
}

/// DNS configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DnsConfig {
    /// DNS servers
    pub servers: Vec<IpAddr>,

    /// Search domains
    pub search_domains: Vec<String>,

    /// DNS records (for MagicDNS)
    pub records: Vec<DnsRecord>,

    /// DNS settings
    pub settings: DnsSettings,
}

/// DNS record
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DnsRecord {
    /// Record name
    pub name: String,

    /// Record type
    pub record_type: DnsRecordType,

    /// Record value
    pub value: String,

    /// TTL in seconds
    pub ttl: u32,

    /// Record tags
    pub tags: Vec<String>,
}

/// DNS record types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "UPPERCASE")]
pub enum DnsRecordType {
    A,
    Aaaa,
    Cname,
    Mx,
    Txt,
    Srv,
    Ptr,
}

/// DNS settings
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DnsSettings {
    /// Enable split DNS
    pub enable_split_dns: bool,

    /// DNS override for internal domains
    pub internal_domains: Vec<String>,

    /// Fallback to public DNS
    pub fallback_to_public: bool,

    /// DNS cache TTL
    pub cache_ttl_seconds: u32,
}

/// Network policy (simplified for network map)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NetworkPolicy {
    /// Policy ID
    pub id: String,

    /// Policy name
    pub name: String,

    /// Policy rules (simplified)
    pub rules: Vec<PolicyRuleRef>,

    /// Policy version
    pub version: String,
}

/// Policy rule reference
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PolicyRuleRef {
    /// Rule ID
    pub id: String,

    /// Rule effect
    pub effect: String,

    /// Rule priority
    pub priority: i32,

    /// Rule summary
    pub summary: String,
}

/// DERP relay server information
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DerpServer {
    /// DERP region ID
    pub region_id: u16,

    /// Region name
    pub region_name: String,

    /// DERP nodes in this region
    pub nodes: Vec<DerpNode>,

    /// Region metadata
    pub metadata: DerpRegionMetadata,
}

/// DERP node
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DerpNode {
    /// Node ID
    pub id: String,

    /// Node hostname
    pub hostname: String,

    /// IPv4 address
    pub ipv4: Option<Ipv4Addr>,

    /// IPv6 address
    pub ipv6: Option<Ipv6Addr>,

    /// STUN port
    pub stun_port: u16,

    /// HTTPS port
    pub https_port: u16,

    /// Node capabilities
    pub capabilities: Vec<String>,
}

/// DERP region metadata
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DerpRegionMetadata {
    /// Geographic location
    pub location: String,

    /// Approximate coordinates
    pub coordinates: Option<Coordinates>,

    /// Avoid this region
    pub avoid: bool,

    /// Region tags
    pub tags: Vec<String>,
}

/// Geographic coordinates
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Coordinates {
    pub latitude: f64,
    pub longitude: f64,
}

/// Network statistics
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NetworkStats {
    /// Total nodes
    pub total_nodes: usize,

    /// Online nodes
    pub online_nodes: usize,

    /// Total routes
    pub total_routes: usize,

    /// Active routes
    pub active_routes: usize,

    /// DNS records
    pub dns_records: usize,

    /// Network utilization
    pub utilization: NetworkUtilization,
}

/// Network utilization metrics
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NetworkUtilization {
    /// IPv4 addresses used
    pub ipv4_used: u32,

    /// IPv4 addresses available
    pub ipv4_total: u32,

    /// IPv6 addresses used
    pub ipv6_used: Option<u64>,

    /// IPv6 addresses available
    pub ipv6_total: Option<u64>,

    /// Average bandwidth usage (bytes/sec)
    pub avg_bandwidth_bps: u64,

    /// Peak bandwidth usage (bytes/sec)
    pub peak_bandwidth_bps: u64,
}

/// Network map delta (for incremental updates)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkMapDelta {
    /// Delta version
    pub version: u64,

    /// Previous version this delta applies to
    pub previous_version: u64,

    /// Generation timestamp
    pub generated_at: SystemTime,

    /// Delta operations
    pub operations: Vec<DeltaOperation>,

    /// Delta checksum
    pub checksum: String,
}

/// Delta operation types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "lowercase")]
pub enum DeltaOperation {
    /// Add a new node
    AddNode { node: NetworkNode },

    /// Update existing node
    UpdateNode {
        node_id: NodeId,
        changes: NodeChanges,
    },

    /// Remove a node
    RemoveNode { node_id: NodeId },

    /// Add route advertisement
    AddRoute { route: RouteAdvertisement },

    /// Update route advertisement
    UpdateRoute {
        node_id: NodeId,
        changes: RouteChanges,
    },

    /// Remove route advertisement
    RemoveRoute { node_id: NodeId },

    /// Update DNS configuration
    UpdateDns { dns_config: DnsConfig },

    /// Update network configuration
    UpdateNetworkConfig { network_config: NetworkConfig },

    /// Update DERP servers
    UpdateDerpServers { derp_servers: Vec<DerpServer> },
}

/// Node change set
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeChanges {
    pub endpoints: Option<Vec<Endpoint>>,
    pub online: Option<bool>,
    pub last_seen: Option<SystemTime>,
    pub tags: Option<Vec<String>>,
    pub settings: Option<NodeSettings>,
    pub connection_info: Option<ConnectionInfo>,
}

/// Route change set
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteChanges {
    pub routes: Option<Vec<Route>>,
    pub priority: Option<u8>,
    pub metrics: Option<RouteMetrics>,
}

/// Network map filter for node-specific views
#[derive(Debug, Clone)]
pub struct NetworkMapFilter {
    /// Target node ID
    pub node_id: NodeId,

    /// Include offline nodes
    pub include_offline: bool,

    /// Include route advertisements
    pub include_routes: bool,

    /// Include DNS configuration
    pub include_dns: bool,

    /// Include policies
    pub include_policies: bool,

    /// ACL-based filtering
    pub acl_filter: bool,

    /// Maximum nodes to include
    pub max_nodes: Option<usize>,
}

impl Default for NetworkMapFilter {
    fn default() -> Self {
        Self {
            node_id: Uuid::nil(),
            include_offline: false,
            include_routes: true,
            include_dns: true,
            include_policies: false,
            acl_filter: true,
            max_nodes: None,
        }
    }
}

impl NetworkMap {
    /// Create a new empty network map
    pub fn new(version: u64) -> Self {
        Self {
            version,
            generated_at: SystemTime::now(),
            ttl_seconds: 300, // 5 minutes default
            network_config: NetworkConfig {
                name: "ghostwire".to_string(),
                ipv4_pool: "100.64.0.0/10".to_string(),
                ipv6_pool: Some("fd7a:115c:a1e0::/48".to_string()),
                default_routes: vec![],
                settings: NetworkSettings {
                    enable_ipv6: true,
                    enable_magic_dns: true,
                    enable_ssh: true,
                    keepalive_seconds: 25,
                    mtu: 1280,
                    encryption: EncryptionSettings {
                        algorithm: "ChaCha20-Poly1305".to_string(),
                        key_rotation_hours: 24,
                        forward_secrecy: true,
                    },
                },
            },
            nodes: vec![],
            routes: vec![],
            dns_config: None,
            policies: None,
            derp_servers: vec![],
            stats: NetworkStats {
                total_nodes: 0,
                online_nodes: 0,
                total_routes: 0,
                active_routes: 0,
                dns_records: 0,
                utilization: NetworkUtilization {
                    ipv4_used: 0,
                    ipv4_total: 1024 * 1024, // /10 network
                    ipv6_used: None,
                    ipv6_total: None,
                    avg_bandwidth_bps: 0,
                    peak_bandwidth_bps: 0,
                },
            },
            checksum: String::new(),
        }
    }

    /// Calculate and update the checksum
    pub fn update_checksum(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        // Serialize map without checksum
        let mut temp_map = self.clone();
        temp_map.checksum = String::new();

        let serialized = serde_json::to_string(&temp_map)?;
        let hash = blake3::hash(serialized.as_bytes());
        self.checksum = hex::encode(hash.as_bytes());

        Ok(())
    }

    /// Verify the checksum
    pub fn verify_checksum(&self) -> Result<bool, Box<dyn std::error::Error>> {
        let mut temp_map = self.clone();
        let original_checksum = temp_map.checksum.clone();
        temp_map.checksum = String::new();

        let serialized = serde_json::to_string(&temp_map)?;
        let hash = blake3::hash(serialized.as_bytes());
        let calculated_checksum = hex::encode(hash.as_bytes());

        Ok(calculated_checksum == original_checksum)
    }

    /// Update statistics based on current data
    pub fn update_stats(&mut self) {
        self.stats.total_nodes = self.nodes.len();
        self.stats.online_nodes = self.nodes.iter().filter(|n| n.online).count();
        self.stats.total_routes = self.routes.iter().map(|r| r.routes.len()).sum();
        self.stats.active_routes = self.routes.iter()
            .map(|r| r.routes.iter().filter(|route| route.enabled).count())
            .sum();
        self.stats.dns_records = self.dns_config.as_ref()
            .map_or(0, |dns| dns.records.len());

        // Update utilization
        self.stats.utilization.ipv4_used = self.nodes.len() as u32;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_network_map_creation() {
        let map = NetworkMap::new(1);
        assert_eq!(map.version, 1);
        assert_eq!(map.nodes.len(), 0);
        assert_eq!(map.routes.len(), 0);
        assert_eq!(map.network_config.name, "ghostwire");
    }

    #[test]
    fn test_network_map_checksum() {
        let mut map = NetworkMap::new(1);

        // Update checksum
        assert!(map.update_checksum().is_ok());
        assert!(!map.checksum.is_empty());

        // Verify checksum
        assert!(map.verify_checksum().unwrap());

        // Modify map and verify checksum changes
        map.version = 2;
        assert!(!map.verify_checksum().unwrap());
    }

    #[test]
    fn test_network_map_stats_update() {
        let mut map = NetworkMap::new(1);

        // Add a test node
        let node = NetworkNode {
            id: Uuid::new_v4(),
            name: "test-node".to_string(),
            owner: Uuid::new_v4(),
            ipv4: Ipv4Addr::new(100, 64, 0, 1),
            ipv6: None,
            public_key: PublicKey([0u8; 32]),
            endpoints: vec![],
            capabilities: NodeCapabilities {
                can_route: false,
                can_advertise_routes: false,
                supports_ssh: true,
                supports_derp: true,
                operating_system: "Linux".to_string(),
                client_version: "1.0.0".to_string(),
                features: vec![],
            },
            online: true,
            last_seen: SystemTime::now(),
            tags: vec![],
            settings: NodeSettings {
                mtu: None,
                keepalive_seconds: None,
                exit_node_preference: None,
                dns_override: None,
                accept_routes: true,
                accept_dns: true,
            },
            connection_info: ConnectionInfo {
                preferred_derp: None,
                direct_connection: false,
                quality_metrics: None,
                bandwidth_limits: None,
            },
        };

        map.nodes.push(node);
        map.update_stats();

        assert_eq!(map.stats.total_nodes, 1);
        assert_eq!(map.stats.online_nodes, 1);
        assert_eq!(map.stats.utilization.ipv4_used, 1);
    }

    #[test]
    fn test_dns_record_types() {
        let record = DnsRecord {
            name: "test.example.com".to_string(),
            record_type: DnsRecordType::A,
            value: "192.168.1.1".to_string(),
            ttl: 300,
            tags: vec![],
        };

        assert_eq!(record.record_type, DnsRecordType::A);
        assert_eq!(record.ttl, 300);
    }

    #[test]
    fn test_delta_operation_serialization() {
        let operation = DeltaOperation::RemoveNode {
            node_id: Uuid::new_v4(),
        };

        let serialized = serde_json::to_string(&operation).unwrap();
        assert!(serialized.contains("removenode"));

        let deserialized: DeltaOperation = serde_json::from_str(&serialized).unwrap();
        assert!(matches!(deserialized, DeltaOperation::RemoveNode { .. }));
    }
}