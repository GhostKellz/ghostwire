use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, SystemTime};
use uuid::Uuid;
use ipnet::IpNet;

/// Node ID - unique identifier for each node in the network
pub type NodeId = Uuid;

/// User ID - unique identifier for each user
pub type UserId = Uuid;

/// WireGuard public key
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PublicKey(pub [u8; 32]);

impl PublicKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// WireGuard private key
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateKey(pub [u8; 32]);

impl PrivateKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn public_key(&self) -> PublicKey {
        // This would use actual crypto to derive public key
        // Placeholder for now
        PublicKey([0u8; 32])
    }
}

/// Network endpoint information
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Endpoint {
    pub addr: SocketAddr,
    pub last_seen: SystemTime,
}

/// Node information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Node {
    pub id: NodeId,
    pub user_id: UserId,
    pub name: String,
    pub public_key: PublicKey,
    pub ipv4: IpAddr,
    pub ipv6: Option<IpAddr>,
    pub endpoints: Vec<Endpoint>,
    pub allowed_ips: Vec<IpNet>,
    pub routes: Vec<Route>,
    pub tags: Vec<String>,
    pub created_at: SystemTime,
    pub last_seen: SystemTime,
    pub expires_at: Option<SystemTime>,
    pub online: bool,
}

/// User information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: UserId,
    pub name: String,
    pub email: Option<String>,
    pub provider: AuthProvider,
    pub provider_id: String,
    pub created_at: SystemTime,
    pub last_seen: SystemTime,
}

/// Authentication provider
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthProvider {
    #[serde(rename = "oidc")]
    Oidc,
    #[serde(rename = "cli")]
    Cli,
    #[serde(rename = "preauthkey")]
    PreAuthKey,
}

/// Route information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Route {
    pub id: Uuid,
    pub node_id: NodeId,
    pub prefix: IpNet,
    pub advertised: bool,
    pub enabled: bool,
    pub is_primary: bool,
    pub created_at: SystemTime,
}

/// Pre-authentication key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreAuthKey {
    pub id: Uuid,
    pub user_id: UserId,
    pub key: String,
    pub reusable: bool,
    pub ephemeral: bool,
    pub used: bool,
    pub tags: Vec<String>,
    pub created_at: SystemTime,
    pub expires_at: Option<SystemTime>,
}

/// API key for programmatic access
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKey {
    pub id: Uuid,
    pub prefix: String,
    pub hash: String,
    pub created_at: SystemTime,
    pub last_used: Option<SystemTime>,
    pub expires_at: Option<SystemTime>,
}

/// ACL policy structure (compatible with Tailscale format)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub groups: Option<HashMap<String, Vec<String>>>,
    pub hosts: Option<HashMap<String, String>>,
    pub acls: Vec<Acl>,
    pub auto_approvers: Option<AutoApprovers>,
    pub ssh: Option<Vec<SshRule>>,
    pub node_attrs: Option<Vec<NodeAttr>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Acl {
    pub action: AclAction,
    pub src: Vec<String>,
    pub dst: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AclAction {
    Accept,
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoApprovers {
    pub routes: Option<HashMap<String, Vec<String>>>,
    pub exit_node: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshRule {
    pub action: AclAction,
    pub src: Vec<String>,
    pub dst: Vec<String>,
    pub users: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeAttr {
    pub target: Vec<String>,
    pub attr: Vec<String>,
}

/// DERP region configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DerpRegion {
    pub region_id: u16,
    pub region_code: String,
    pub region_name: String,
    pub avoid: Option<bool>,
    pub nodes: Vec<DerpNode>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DerpNode {
    pub name: String,
    pub region_id: u16,
    pub hostname: String,
    pub ipv4: Option<IpAddr>,
    pub ipv6: Option<IpAddr>,
    pub stun_port: Option<u16>,
    pub stun_only: Option<bool>,
    pub derp_port: Option<u16>,
    pub insecure_for_tests: Option<bool>,
    pub force_http: Option<bool>,
    pub stun_test_ip: Option<IpAddr>,
    pub can_port_80: Option<bool>,
}

/// DNS record for MagicDNS
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRecord {
    pub id: Uuid,
    pub name: String,
    pub record_type: String,
    pub value: String,
    pub ttl: u32,
    pub created_at: SystemTime,
    pub updated_at: SystemTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum DnsRecordType {
    A,
    Aaaa,
    Cname,
    Mx,
    Txt,
}

/// Network map sent to clients (similar to Tailscale's NetworkMap)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkMap {
    pub node_key: PublicKey,
    pub private_key: Option<PrivateKey>,
    pub peers: Vec<Node>,
    pub dns: DnsConfig,
    pub derp_map: DerpMap,
    pub packet_filter: Vec<PacketFilter>,
    pub user_profiles: HashMap<UserId, UserProfile>,
    pub domain: String,
    pub collect_services: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsConfig {
    pub resolvers: Vec<IpAddr>,
    pub domains: Vec<String>,
    pub magic_dns: bool,
    pub routes: HashMap<String, Vec<IpAddr>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DerpMap {
    pub regions: HashMap<u16, DerpRegion>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketFilter {
    pub src_ips: Vec<String>,
    pub dst_ports: Vec<PortRange>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortRange {
    pub first: u16,
    pub last: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserProfile {
    pub id: UserId,
    pub login_name: String,
    pub display_name: String,
    pub profile_pic_url: Option<String>,
}

/// QUIC connection info for enhanced peer connections
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuicEndpoint {
    pub addr: SocketAddr,
    pub connection_id: Option<String>,
    pub supported_versions: Vec<u32>,
    pub last_handshake: Option<SystemTime>,
    pub rtt: Option<Duration>,
}

impl Node {
    pub fn new(
        user_id: UserId,
        name: String,
        public_key: PublicKey,
        ipv4: IpAddr,
    ) -> Self {
        let now = SystemTime::now();
        Self {
            id: Uuid::new_v4(),
            user_id,
            name,
            public_key,
            ipv4,
            ipv6: None,
            endpoints: Vec::new(),
            allowed_ips: Vec::new(),
            routes: Vec::new(),
            tags: Vec::new(),
            created_at: now,
            last_seen: now,
            expires_at: None,
            online: false,
        }
    }

    pub fn is_expired(&self) -> bool {
        self.expires_at
            .map(|exp| exp < SystemTime::now())
            .unwrap_or(false)
    }

    pub fn add_endpoint(&mut self, endpoint: Endpoint) {
        // Remove existing endpoint with same address
        self.endpoints.retain(|ep| ep.addr != endpoint.addr);
        self.endpoints.push(endpoint);
        self.last_seen = SystemTime::now();
    }
}

/// ACL rule for policy evaluation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AclRule {
    pub id: Option<i64>,
    pub policy_version: u32,
    pub rule_index: usize,
    pub action: AclAction,
    pub source_spec: Vec<String>,
    pub dest_spec: Vec<String>,
    pub created_at: SystemTime,
}

impl std::fmt::Display for AclAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AclAction::Accept => write!(f, "accept"),
            AclAction::Deny => write!(f, "deny"),
        }
    }
}

/// Node metrics for monitoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeMetrics {
    pub node_id: NodeId,
    pub timestamp: SystemTime,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub latency_ms: Option<f64>,
    pub packet_loss: Option<f64>,
    pub bandwidth_bps: Option<u64>,
}

/// Aggregated metrics across all nodes
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AggregateMetrics {
    pub total_rx_bytes: u64,
    pub total_tx_bytes: u64,
    pub total_rx_packets: u64,
    pub total_tx_packets: u64,
    pub avg_latency_ms: Option<f64>,
    pub avg_packet_loss: Option<f64>,
    pub avg_bandwidth_bps: Option<u64>,
    pub active_nodes: u32,
}

/// Audit event for security logging
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub id: Uuid,
    pub timestamp: SystemTime,
    pub user_id: Option<UserId>,
    pub node_id: Option<NodeId>,
    pub action: String,
    pub resource_type: String,
    pub resource_id: Option<String>,
    pub details: Option<serde_json::Value>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub result: AuditResult,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuditResult {
    Success,
    Failure,
    Denied,
}

impl std::fmt::Display for AuditResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuditResult::Success => write!(f, "success"),
            AuditResult::Failure => write!(f, "failure"),
            AuditResult::Denied => write!(f, "denied"),
        }
    }
}