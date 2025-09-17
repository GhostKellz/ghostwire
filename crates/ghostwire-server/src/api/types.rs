/// Common type definitions for API layer
///
/// Provides shared types used across gRPC and REST APIs:
/// - Request/response structures
/// - Error types and codes
/// - Validation helpers
/// - Serialization utilities

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use ghostwire_common::types::*;

/// API version information
#[derive(Serialize, Deserialize, Debug)]
pub struct ApiVersion {
    pub version: String,
    pub git_commit: Option<String>,
    pub build_time: Option<String>,
    pub supported_protocols: Vec<String>,
}

/// Server status information
#[derive(Serialize, Deserialize, Debug)]
pub struct ServerStatus {
    pub status: String,
    pub uptime_seconds: u64,
    pub version: ApiVersion,
    pub stats: ServerStats,
}

/// Server statistics
#[derive(Serialize, Deserialize, Debug)]
pub struct ServerStats {
    pub total_nodes: u64,
    pub online_nodes: u64,
    pub total_users: u64,
    pub active_sessions: u64,
    pub network_version: u64,
    pub database_size_mb: f64,
    pub memory_usage_mb: f64,
    pub cpu_usage_percent: f64,
}

/// Node registration request (REST API)
#[derive(Serialize, Deserialize, Debug)]
pub struct ApiNodeRegistrationRequest {
    pub name: String,
    pub public_key: String, // hex-encoded
    pub endpoints: Vec<ApiEndpointRequest>,
    pub capabilities: Option<ApiNodeCapabilities>,
    pub pre_auth_key: Option<String>,
    pub tags: Vec<String>,
}

/// Endpoint request structure
#[derive(Serialize, Deserialize, Debug)]
pub struct ApiEndpointRequest {
    pub addr: String,
    pub endpoint_type: String,
    pub preference: Option<u32>,
}

/// Node capabilities structure
#[derive(Serialize, Deserialize, Debug)]
pub struct ApiNodeCapabilities {
    pub can_derp: bool,
    pub can_exit_node: bool,
    pub supports_ipv6: bool,
    pub supports_pcp: bool,
    pub supports_pmp: bool,
    pub supports_upnp: bool,
}

/// Node registration response (REST API)
#[derive(Serialize, Deserialize, Debug)]
pub struct ApiNodeRegistrationResponse {
    pub node_id: String,
    pub ipv4: String,
    pub ipv6: Option<String>,
    pub session_token: String,
    pub network_map: ApiNetworkMap,
    pub derp_map: ApiDerpMap,
}

/// Heartbeat request (REST API)
#[derive(Serialize, Deserialize, Debug)]
pub struct ApiHeartbeatRequest {
    pub endpoints: Vec<ApiEndpointRequest>,
    pub stats: Option<ApiNodeStats>,
}

/// Node statistics
#[derive(Serialize, Deserialize, Debug)]
pub struct ApiNodeStats {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub active_connections: u32,
    pub latency_ms: Option<f64>,
    pub packet_loss: Option<f64>,
}

/// Heartbeat response (REST API)
#[derive(Serialize, Deserialize, Debug)]
pub struct ApiHeartbeatResponse {
    pub network_map: Option<ApiNetworkMap>,
    pub next_heartbeat_seconds: u64,
    pub messages: Vec<String>,
}

/// Network map request
#[derive(Serialize, Deserialize, Debug)]
pub struct ApiNetworkMapRequest {
    pub current_version: Option<u64>,
}

/// Network map response
#[derive(Serialize, Deserialize, Debug)]
pub struct ApiNetworkMapResponse {
    pub network_map: ApiNetworkMap,
    pub is_delta: bool,
}

/// User creation request
#[derive(Serialize, Deserialize, Debug)]
pub struct ApiCreateUserRequest {
    pub name: String,
    pub email: Option<String>,
    pub is_admin: Option<bool>,
}

/// User update request
#[derive(Serialize, Deserialize, Debug)]
pub struct ApiUpdateUserRequest {
    pub name: Option<String>,
    pub email: Option<String>,
    pub is_admin: Option<bool>,
}

/// User response
#[derive(Serialize, Deserialize, Debug)]
pub struct ApiUserResponse {
    pub id: String,
    pub name: String,
    pub email: Option<String>,
    pub is_admin: bool,
    pub created_at: String,
    pub last_active: Option<String>,
    pub node_count: u32,
}

/// Node filter for list operations
#[derive(Serialize, Deserialize, Debug)]
pub struct ApiNodeFilter {
    pub user_id: Option<String>,
    pub online: Option<bool>,
    pub tag: Option<String>,
    pub name_contains: Option<String>,
}

/// User filter for list operations
#[derive(Serialize, Deserialize, Debug)]
pub struct ApiUserFilter {
    pub name_contains: Option<String>,
    pub is_admin: Option<bool>,
    pub has_nodes: Option<bool>,
}

/// Pagination parameters
#[derive(Serialize, Deserialize, Debug)]
pub struct ApiPagination {
    pub page: Option<u32>,
    pub per_page: Option<u32>,
    pub sort_by: Option<String>,
    pub sort_order: Option<String>, // "asc" or "desc"
}

/// Paginated response wrapper
#[derive(Serialize, Deserialize, Debug)]
pub struct ApiPaginatedResponse<T> {
    pub data: Vec<T>,
    pub pagination: ApiPaginationInfo,
}

/// Pagination information
#[derive(Serialize, Deserialize, Debug)]
pub struct ApiPaginationInfo {
    pub page: u32,
    pub per_page: u32,
    pub total_pages: u32,
    pub total_items: u64,
    pub has_next: bool,
    pub has_prev: bool,
}

/// Standard API error response
#[derive(Serialize, Deserialize, Debug)]
pub struct ApiErrorResponse {
    pub error: String,
    pub code: String,
    pub message: String,
    pub details: Option<serde_json::Value>,
    pub request_id: Option<String>,
}

/// Standard API success response
#[derive(Serialize, Deserialize, Debug)]
pub struct ApiSuccessResponse<T> {
    pub success: bool,
    pub data: T,
    pub message: Option<String>,
    pub request_id: Option<String>,
}

/// Route management structures
#[derive(Serialize, Deserialize, Debug)]
pub struct ApiRouteRequest {
    pub prefix: String,
    pub advertised: bool,
    pub enabled: bool,
    pub is_primary: bool,
}

/// ACL rule structure (simplified for API)
#[derive(Serialize, Deserialize, Debug)]
pub struct ApiAclRule {
    pub id: String,
    pub action: String, // "accept" or "deny"
    pub source: String, // Tag, user, or node spec
    pub destination: String, // Tag, user, or node spec
    pub ports: Option<Vec<String>>, // Port ranges
    pub protocol: Option<String>, // "tcp", "udp", "icmp", etc.
    pub created_at: String,
    pub enabled: bool,
}

/// Pre-auth key structure
#[derive(Serialize, Deserialize, Debug)]
pub struct ApiPreAuthKey {
    pub id: String,
    pub key: String,
    pub user_id: String,
    pub uses_remaining: Option<u32>,
    pub expires_at: Option<String>,
    pub created_at: String,
    pub tags: Vec<String>,
    pub ephemeral: bool,
}

/// Create pre-auth key request
#[derive(Serialize, Deserialize, Debug)]
pub struct ApiCreatePreAuthKeyRequest {
    pub uses: Option<u32>,
    pub expires_in_seconds: Option<u64>,
    pub tags: Vec<String>,
    pub ephemeral: bool,
}

/// Network configuration
#[derive(Serialize, Deserialize, Debug)]
pub struct ApiNetworkConfig {
    pub ipv4_range: String,
    pub ipv6_range: Option<String>,
    pub dns_config: ApiDnsConfig,
    pub derp_map: ApiDerpMap,
    pub domain: String,
}

/// Update network configuration request
#[derive(Serialize, Deserialize, Debug)]
pub struct ApiUpdateNetworkConfigRequest {
    pub ipv4_range: Option<String>,
    pub ipv6_range: Option<String>,
    pub dns_config: Option<ApiDnsConfig>,
    pub domain: Option<String>,
}

/// Audit log entry
#[derive(Serialize, Deserialize, Debug)]
pub struct ApiAuditLogEntry {
    pub id: String,
    pub timestamp: String,
    pub user_id: Option<String>,
    pub node_id: Option<String>,
    pub action: String,
    pub resource: String,
    pub details: Option<serde_json::Value>,
    pub client_ip: String,
    pub user_agent: Option<String>,
    pub success: bool,
}

/// Audit log filter
#[derive(Serialize, Deserialize, Debug)]
pub struct ApiAuditLogFilter {
    pub user_id: Option<String>,
    pub node_id: Option<String>,
    pub action: Option<String>,
    pub resource: Option<String>,
    pub success: Option<bool>,
    pub from_timestamp: Option<String>,
    pub to_timestamp: Option<String>,
}

/// Metrics query parameters
#[derive(Serialize, Deserialize, Debug)]
pub struct ApiMetricsQuery {
    pub metric: String,
    pub from_timestamp: Option<String>,
    pub to_timestamp: Option<String>,
    pub resolution: Option<String>, // "minute", "hour", "day"
    pub node_id: Option<String>,
    pub user_id: Option<String>,
}

/// Metrics response
#[derive(Serialize, Deserialize, Debug)]
pub struct ApiMetricsResponse {
    pub metric: String,
    pub data_points: Vec<ApiMetricDataPoint>,
    pub unit: String,
    pub description: String,
}

/// Metric data point
#[derive(Serialize, Deserialize, Debug)]
pub struct ApiMetricDataPoint {
    pub timestamp: String,
    pub value: f64,
    pub labels: HashMap<String, String>,
}

/// System configuration
#[derive(Serialize, Deserialize, Debug)]
pub struct ApiSystemConfig {
    pub server_name: String,
    pub base_domain: String,
    pub magic_dns_enabled: bool,
    pub derp_enabled: bool,
    pub registration_enabled: bool,
    pub max_nodes_per_user: Option<u32>,
    pub session_timeout_seconds: u64,
    pub heartbeat_interval_seconds: u64,
}

/// Update system configuration request
#[derive(Serialize, Deserialize, Debug)]
pub struct ApiUpdateSystemConfigRequest {
    pub server_name: Option<String>,
    pub base_domain: Option<String>,
    pub magic_dns_enabled: Option<bool>,
    pub derp_enabled: Option<bool>,
    pub registration_enabled: Option<bool>,
    pub max_nodes_per_user: Option<u32>,
    pub session_timeout_seconds: Option<u64>,
    pub heartbeat_interval_seconds: Option<u64>,
}

/// Re-export shared types from handlers module
pub use crate::api::handlers::{
    ApiNode, ApiEndpoint, ApiRoute, ApiNetworkMap, ApiDnsConfig, ApiDnsRoutes,
    ApiDerpMap, ApiDerpRegion, ApiDerpNode, ApiPacketFilter, ApiPortRange,
    ApiUserProfile,
};

/// Utility functions for API types
impl ApiErrorResponse {
    pub fn new(code: &str, message: &str) -> Self {
        Self {
            error: "error".to_string(),
            code: code.to_string(),
            message: message.to_string(),
            details: None,
            request_id: None,
        }
    }

    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = Some(details);
        self
    }

    pub fn with_request_id(mut self, request_id: String) -> Self {
        self.request_id = Some(request_id);
        self
    }
}

impl<T> ApiSuccessResponse<T> {
    pub fn new(data: T) -> Self {
        Self {
            success: true,
            data,
            message: None,
            request_id: None,
        }
    }

    pub fn with_message(mut self, message: String) -> Self {
        self.message = Some(message);
        self
    }

    pub fn with_request_id(mut self, request_id: String) -> Self {
        self.request_id = Some(request_id);
        self
    }
}

impl Default for ApiPagination {
    fn default() -> Self {
        Self {
            page: Some(1),
            per_page: Some(50),
            sort_by: None,
            sort_order: Some("asc".to_string()),
        }
    }
}

impl ApiPagination {
    pub fn validate(&self) -> Result<(), String> {
        if let Some(page) = self.page {
            if page == 0 {
                return Err("Page number must be >= 1".to_string());
            }
        }

        if let Some(per_page) = self.per_page {
            if per_page == 0 || per_page > 1000 {
                return Err("Per page must be between 1 and 1000".to_string());
            }
        }

        if let Some(sort_order) = &self.sort_order {
            if !matches!(sort_order.as_str(), "asc" | "desc") {
                return Err("Sort order must be 'asc' or 'desc'".to_string());
            }
        }

        Ok(())
    }

    pub fn page(&self) -> u32 {
        self.page.unwrap_or(1)
    }

    pub fn per_page(&self) -> u32 {
        self.per_page.unwrap_or(50)
    }

    pub fn offset(&self) -> u32 {
        (self.page() - 1) * self.per_page()
    }
}