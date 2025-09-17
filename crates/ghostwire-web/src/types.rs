/// Type definitions for the GhostWire web interface
///
/// Shared data structures for nodes, users, policies, and network configuration.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Node {
    pub id: String,
    pub name: String,
    pub hostname: String,
    pub user: String,
    pub online: bool,
    pub ip_addresses: Vec<String>,
    pub node_key: String,
    pub machine_key: String,
    pub os: Option<String>,
    pub arch: Option<String>,
    pub version: Option<String>,
    pub last_seen: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub ephemeral: bool,
    pub register_method: String,
    pub tags: Vec<String>,
    pub routes: Vec<Route>,
    pub derp_region: Option<u32>,
    pub endpoints: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub name: String,
    pub email: String,
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
    pub role: UserRole,
    pub created_at: DateTime<Utc>,
    pub last_login: Option<DateTime<Utc>>,
    pub active: bool,
    pub provider: String,
    pub provider_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UserRole {
    Admin,
    User,
    ReadOnly,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Route {
    pub id: String,
    pub destination: String,
    pub advertiser: String,
    pub enabled: bool,
    pub primary: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DerpRegion {
    pub id: u32,
    pub name: String,
    pub nodes: Vec<DerpNode>,
    pub avoid: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DerpNode {
    pub name: String,
    pub host_name: String,
    pub ipv4: Option<String>,
    pub ipv6: Option<String>,
    pub stun_port: Option<u16>,
    pub stun_only: bool,
    pub derp_port: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tag {
    pub name: String,
    pub owner: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharePermission {
    pub id: String,
    pub machine_id: String,
    pub user_id: String,
    pub permission_level: PermissionLevel,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PermissionLevel {
    View,
    Admin,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreAuthKey {
    pub id: String,
    pub key: String,
    pub user: String,
    pub reusable: bool,
    pub ephemeral: bool,
    pub used: bool,
    pub tags: Vec<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub used_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AclPolicy {
    pub id: String,
    pub name: String,
    pub content: String,
    pub version: u32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub created_by: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsConfig {
    pub id: String,
    pub base_domain: String,
    pub magic_dns: bool,
    pub nameservers: Vec<String>,
    pub search_domains: Vec<String>,
    pub extra_records: Vec<DnsRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRecord {
    pub name: String,
    pub record_type: String,
    pub value: String,
    pub ttl: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkStats {
    pub total_nodes: u32,
    pub online_nodes: u32,
    pub total_users: u32,
    pub active_routes: u32,
    pub derp_regions: u32,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub last_updated: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub data: Option<T>,
    pub error: Option<String>,
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaginatedResponse<T> {
    pub items: Vec<T>,
    pub total: u32,
    pub page: u32,
    pub per_page: u32,
    pub has_more: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: Option<String>,
    pub provider: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginResponse {
    pub token: String,
    pub user: User,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionInfo {
    pub endpoint: String,
    pub relay: bool,
    pub latency: Option<u32>,
    pub last_handshake: Option<DateTime<Utc>>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachineStatus {
    pub online: bool,
    pub last_seen: Option<DateTime<Utc>>,
    pub connection: Option<ConnectionInfo>,
    pub endpoints: Vec<String>,
    pub derp_region: Option<u32>,
    pub os_version: Option<String>,
    pub client_version: Option<String>,
}

impl Default for Node {
    fn default() -> Self {
        Self {
            id: String::new(),
            name: String::new(),
            hostname: String::new(),
            user: String::new(),
            online: false,
            ip_addresses: Vec::new(),
            node_key: String::new(),
            machine_key: String::new(),
            os: None,
            arch: None,
            version: None,
            last_seen: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            ephemeral: false,
            register_method: "web".to_string(),
            tags: Vec::new(),
            routes: Vec::new(),
            derp_region: None,
            endpoints: Vec::new(),
        }
    }
}

impl Default for User {
    fn default() -> Self {
        Self {
            id: String::new(),
            name: String::new(),
            email: String::new(),
            display_name: None,
            avatar_url: None,
            role: UserRole::User,
            created_at: Utc::now(),
            last_login: None,
            active: true,
            provider: "oidc".to_string(),
            provider_id: String::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemStatus {
    pub server_version: String,
    pub uptime: String,
    pub connected_nodes: u32,
    pub active_connections: u32,
    pub cpu_usage: f64,
    pub memory_usage: String,
    pub network_traffic: NetworkTraffic,
    pub derp_relays: Vec<DerpRelayStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkTraffic {
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub packets_in: u64,
    pub packets_out: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DerpRelayStatus {
    pub region: String,
    pub healthy: bool,
    pub latency: Option<u32>,
    pub clients: u32,
}