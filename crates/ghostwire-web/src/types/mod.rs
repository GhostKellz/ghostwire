/// Type definitions for the GhostWire web interface
///
/// Shared types for API communication, UI state, and business logic.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Node/Machine representation in the web UI
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Node {
    pub id: String,
    pub name: String,
    pub node_key: String,
    pub machine_key: String,
    pub ip_addresses: Vec<String>,
    pub user: String,
    pub hostname: String,
    pub given_name: Option<String>,
    pub online: bool,
    pub last_seen: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub tags: Vec<String>,
    pub forced_tags: Vec<String>,
    pub invalid_tags: Vec<String>,
    pub register_method: String,
    pub ephemeral: bool,
    pub pre_auth_key_used: Option<String>,
    pub version: Option<String>,
    pub os: Option<String>,
    pub arch: Option<String>,
}

/// User representation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct User {
    pub id: String,
    pub name: String,
    pub email: Option<String>,
    pub provider: String,
    pub provider_id: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub role: String,
    pub active: bool,
    pub last_login: Option<DateTime<Utc>>,
}

/// Pre-authentication key
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PreAuthKey {
    pub id: String,
    pub key: String,
    pub user: String,
    pub reusable: bool,
    pub ephemeral: bool,
    pub used: bool,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub tags: Vec<String>,
    pub acl_tags: Vec<String>,
}

/// API Key representation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ApiKey {
    pub id: String,
    pub prefix: String,
    pub name: String,
    pub user: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_used: Option<DateTime<Utc>>,
    pub scopes: Vec<String>,
    pub active: bool,
}

/// DNS record for MagicDNS
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DnsRecord {
    pub id: String,
    pub name: String,
    pub record_type: String,
    pub value: String,
    pub ttl: u32,
    pub node: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Network route
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Route {
    pub id: String,
    pub destination: String,
    pub node: String,
    pub metric: Option<u32>,
    pub enabled: bool,
    pub advertised: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// DERP relay server information
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DerpRelay {
    pub id: String,
    pub region: String,
    pub hostname: String,
    pub ipv4: Option<String>,
    pub ipv6: Option<String>,
    pub port: u16,
    pub stun_port: Option<u16>,
    pub healthy: bool,
    pub latency: Option<u32>,
    pub connected_clients: u32,
    pub last_health_check: Option<DateTime<Utc>>,
    pub uptime: Option<String>,
}

/// System status and metrics
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NetworkTraffic {
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub packets_in: u64,
    pub packets_out: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DerpRelayStatus {
    pub region: String,
    pub healthy: bool,
    pub latency: Option<u32>,
    pub clients: u32,
}

/// Authentication session information
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuthSession {
    pub user: User,
    pub token: String,
    pub expires_at: DateTime<Utc>,
    pub permissions: Permissions,
}

/// User permissions for UI access control
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Permissions {
    pub ui_access: bool,
    pub read_machines: bool,
    pub write_machines: bool,
    pub read_users: bool,
    pub write_users: bool,
    pub read_network: bool,
    pub write_network: bool,
    pub read_policy: bool,
    pub write_policy: bool,
    pub read_settings: bool,
    pub write_settings: bool,
    pub generate_auth_keys: bool,
}

/// Real-time update message types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type")]
pub enum UpdateMessage {
    NodeStatusChanged { node_id: String, online: bool },
    NodeAdded { node: Node },
    NodeRemoved { node_id: String },
    NodeUpdated { node: Node },
    UserAdded { user: User },
    UserUpdated { user: User },
    UserRemoved { user_id: String },
    SystemStatusUpdate { status: SystemStatus },
    DerpStatusUpdate { relay: DerpRelay },
    PolicyUpdated,
    DnsRecordChanged { record: DnsRecord },
    RouteChanged { route: Route },
}

/// API response wrapper
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub data: Option<T>,
    pub error: Option<String>,
    pub message: Option<String>,
}

impl<T> ApiResponse<T> {
    pub fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
            message: None,
        }
    }

    pub fn error(error: String) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(error),
            message: None,
        }
    }

    pub fn with_message(mut self, message: String) -> Self {
        self.message = Some(message);
        self
    }
}

/// Pagination information
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Pagination {
    pub page: u32,
    pub per_page: u32,
    pub total: u32,
    pub total_pages: u32,
}

/// List response with pagination
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ListResponse<T> {
    pub items: Vec<T>,
    pub pagination: Pagination,
}

/// Form validation error
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ValidationError {
    pub field: String,
    pub message: String,
}

/// UI notification types
#[derive(Debug, Clone, PartialEq)]
pub enum NotificationType {
    Success,
    Error,
    Warning,
    Info,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Notification {
    pub id: Uuid,
    pub notification_type: NotificationType,
    pub title: String,
    pub message: Option<String>,
    pub auto_dismiss: bool,
    pub duration: Option<u32>, // seconds
}