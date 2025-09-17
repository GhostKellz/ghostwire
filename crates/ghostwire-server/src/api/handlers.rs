/// Shared API handlers and utilities for both gRPC and REST endpoints
///
/// This module provides common functionality that can be used by both
/// gRPC and REST API implementations, including:
/// - Request validation
/// - Response formatting
/// - Error handling
/// - Data conversion utilities

use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use crate::coordinator::{Coordinator, Node, NetworkMap, Endpoint, EndpointType};
use ghostwire_common::{
    types::*,
    error::{Result, GhostWireError},
};

/// Common request validation utilities
pub struct RequestValidator;

impl RequestValidator {
    /// Validate a WireGuard public key
    pub fn validate_public_key(key: &[u8]) -> Result<PublicKey> {
        if key.len() != 32 {
            return Err(GhostWireError::validation("Public key must be 32 bytes"));
        }

        let key_array: [u8; 32] = key.try_into()
            .map_err(|_| GhostWireError::validation("Invalid public key format"))?;

        // Check for zero key (invalid)
        if key_array == [0u8; 32] {
            return Err(GhostWireError::validation("Public key cannot be all zeros"));
        }

        Ok(PublicKey(key_array))
    }

    /// Validate node name
    pub fn validate_node_name(name: &str) -> Result<()> {
        if name.is_empty() {
            return Err(GhostWireError::validation("Node name cannot be empty"));
        }

        if name.len() > 255 {
            return Err(GhostWireError::validation("Node name too long (max 255 characters)"));
        }

        // Check for valid hostname characters
        if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '_') {
            return Err(GhostWireError::validation("Invalid characters in node name"));
        }

        Ok(())
    }

    /// Validate endpoint address
    pub fn validate_endpoint(addr: &str) -> Result<std::net::SocketAddr> {
        addr.parse()
            .map_err(|_| GhostWireError::validation(format!("Invalid endpoint address: {}", addr)))
    }

    /// Validate tags
    pub fn validate_tags(tags: &[String]) -> Result<()> {
        if tags.len() > 50 {
            return Err(GhostWireError::validation("Too many tags (max 50)"));
        }

        for tag in tags {
            if tag.is_empty() {
                return Err(GhostWireError::validation("Tag cannot be empty"));
            }

            if tag.len() > 64 {
                return Err(GhostWireError::validation("Tag too long (max 64 characters)"));
            }

            if !tag.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == ':') {
                return Err(GhostWireError::validation(format!("Invalid tag format: {}", tag)));
            }
        }

        Ok(())
    }
}

/// Response formatting utilities
pub struct ResponseFormatter;

impl ResponseFormatter {
    /// Format a node for external API consumption
    pub fn format_node(node: &Node) -> ApiNode {
        ApiNode {
            id: node.id.to_string(),
            user_id: node.user_id.to_string(),
            name: node.name.clone(),
            public_key: hex::encode(&node.public_key.0),
            ipv4: node.ipv4.to_string(),
            ipv6: node.ipv6.map(|ip| ip.to_string()),
            endpoints: node.endpoints.iter().map(Self::format_endpoint).collect(),
            allowed_ips: node.allowed_ips.iter().map(|ip| ip.to_string()).collect(),
            routes: node.routes.iter().map(Self::format_route).collect(),
            tags: node.tags.clone(),
            created_at: node.created_at.duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default().as_secs(),
            last_seen: node.last_seen.duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default().as_secs(),
            expires_at: node.expires_at.map(|t| t.duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default().as_secs()),
            online: node.online,
        }
    }

    /// Format an endpoint for external API consumption
    pub fn format_endpoint(endpoint: &Endpoint) -> ApiEndpoint {
        ApiEndpoint {
            addr: endpoint.addr.to_string(),
            endpoint_type: match endpoint.endpoint_type {
                EndpointType::DirectIPv4 => "direct_ipv4".to_string(),
                EndpointType::DirectIPv6 => "direct_ipv6".to_string(),
                EndpointType::Stun => "stun".to_string(),
                EndpointType::Derp => "derp".to_string(),
                EndpointType::Unknown => "unknown".to_string(),
            },
            preference: endpoint.preference,
        }
    }

    /// Format a route for external API consumption
    pub fn format_route(route: &crate::coordinator::Route) -> ApiRoute {
        ApiRoute {
            id: route.id.to_string(),
            node_id: route.node_id.to_string(),
            prefix: route.prefix.to_string(),
            advertised: route.advertised,
            enabled: route.enabled,
            is_primary: route.is_primary,
        }
    }

    /// Format a network map for external API consumption
    pub fn format_network_map(map: &NetworkMap) -> ApiNetworkMap {
        ApiNetworkMap {
            node_key: hex::encode(&map.node_key.0),
            peers: map.peers.iter().map(Self::format_node).collect(),
            dns: ApiDnsConfig {
                resolvers: map.dns.resolvers.clone(),
                domains: map.dns.domains.clone(),
                magic_dns: map.dns.magic_dns,
                routes: map.dns.routes.iter().map(|(domain, routes)| {
                    (domain.clone(), ApiDnsRoutes {
                        resolvers: routes.resolvers.clone(),
                    })
                }).collect(),
            },
            derp_map: ApiDerpMap {
                regions: map.derp_map.regions.iter().map(|(id, region)| {
                    (*id, ApiDerpRegion {
                        region_id: region.region_id,
                        region_code: region.region_code.clone(),
                        region_name: region.region_name.clone(),
                        nodes: region.nodes.iter().map(|node| ApiDerpNode {
                            name: node.name.clone(),
                            hostname: node.hostname.clone(),
                            port: node.port,
                            public_key: hex::encode(&node.public_key.0),
                            stun_only: node.stun_only,
                            stun_port: node.stun_port,
                        }).collect(),
                    })
                }).collect(),
            },
            packet_filters: map.packet_filters.iter().map(|filter| ApiPacketFilter {
                src_ips: filter.src_ips.clone(),
                dst_ports: filter.dst_ports.iter().map(|range| ApiPortRange {
                    first: range.start,
                    last: range.end,
                }).collect(),
            }).collect(),
            user_profiles: map.user_profiles.iter().map(|(id, profile)| {
                (id.to_string(), ApiUserProfile {
                    id: profile.id.to_string(),
                    login_name: profile.login_name.clone(),
                    display_name: profile.display_name.clone(),
                    profile_pic_url: profile.profile_pic_url.clone(),
                })
            }).collect(),
            domain: map.domain.clone(),
            version: map.version,
        }
    }
}

/// External API data structures

#[derive(Serialize, Deserialize, Debug)]
pub struct ApiNode {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub public_key: String, // hex-encoded
    pub ipv4: String,
    pub ipv6: Option<String>,
    pub endpoints: Vec<ApiEndpoint>,
    pub allowed_ips: Vec<String>,
    pub routes: Vec<ApiRoute>,
    pub tags: Vec<String>,
    pub created_at: u64, // Unix timestamp
    pub last_seen: u64,  // Unix timestamp
    pub expires_at: Option<u64>, // Unix timestamp
    pub online: bool,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ApiEndpoint {
    pub addr: String,
    pub endpoint_type: String,
    pub preference: u32,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ApiRoute {
    pub id: String,
    pub node_id: String,
    pub prefix: String,
    pub advertised: bool,
    pub enabled: bool,
    pub is_primary: bool,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ApiNetworkMap {
    pub node_key: String, // hex-encoded
    pub peers: Vec<ApiNode>,
    pub dns: ApiDnsConfig,
    pub derp_map: ApiDerpMap,
    pub packet_filters: Vec<ApiPacketFilter>,
    pub user_profiles: HashMap<String, ApiUserProfile>,
    pub domain: String,
    pub version: u64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ApiDnsConfig {
    pub resolvers: Vec<String>,
    pub domains: Vec<String>,
    pub magic_dns: bool,
    pub routes: HashMap<String, ApiDnsRoutes>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ApiDnsRoutes {
    pub resolvers: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ApiDerpMap {
    pub regions: HashMap<u32, ApiDerpRegion>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ApiDerpRegion {
    pub region_id: u32,
    pub region_code: String,
    pub region_name: String,
    pub nodes: Vec<ApiDerpNode>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ApiDerpNode {
    pub name: String,
    pub hostname: String,
    pub port: u32,
    pub public_key: String, // hex-encoded
    pub stun_only: bool,
    pub stun_port: Option<u32>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ApiPacketFilter {
    pub src_ips: Vec<String>,
    pub dst_ports: Vec<ApiPortRange>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ApiPortRange {
    pub first: u32,
    pub last: u32,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ApiUserProfile {
    pub id: String,
    pub login_name: String,
    pub display_name: String,
    pub profile_pic_url: Option<String>,
}

/// Authentication utilities
pub struct AuthHandler;

impl AuthHandler {
    /// Validate API key for administrative operations
    pub async fn validate_api_key(_coordinator: &Coordinator, _api_key: &str) -> Result<()> {
        // TODO: Implement API key validation
        // This would typically check against a database of valid API keys
        // with associated permissions and expiration dates
        warn!("API key validation not implemented");
        Ok(())
    }

    /// Validate session token for node operations
    pub async fn validate_session_token(
        coordinator: &Coordinator,
        node_id: &NodeId,
        token: &str,
    ) -> Result<()> {
        if !coordinator.validate_session(node_id, token).await? {
            return Err(GhostWireError::authentication("Invalid session token"));
        }
        Ok(())
    }

    /// Validate bearer token for user operations
    pub async fn validate_bearer_token(
        _coordinator: &Coordinator,
        _token: &str,
    ) -> Result<UserId> {
        // TODO: Implement bearer token validation
        // This would typically validate JWT tokens or OAuth tokens
        // and return the associated user ID
        warn!("Bearer token validation not implemented");
        Err(GhostWireError::authentication("Bearer token validation not implemented"))
    }
}

/// Rate limiting utilities
pub struct RateLimiter;

impl RateLimiter {
    /// Check rate limit for API endpoint
    pub async fn check_rate_limit(
        _endpoint: &str,
        _client_ip: std::net::IpAddr,
    ) -> Result<()> {
        // TODO: Implement rate limiting
        // This would track requests per IP/endpoint and enforce limits
        Ok(())
    }
}

/// Audit logging utilities
pub struct AuditLogger;

impl AuditLogger {
    /// Log administrative action
    pub fn log_admin_action(
        action: &str,
        resource: &str,
        user_id: Option<&UserId>,
        result: &Result<()>,
    ) {
        match result {
            Ok(()) => {
                debug!(
                    action = action,
                    resource = resource,
                    user_id = user_id.map(|u| u.to_string()).unwrap_or_else(|| "unknown".to_string()),
                    "Admin action succeeded"
                );
            }
            Err(e) => {
                warn!(
                    action = action,
                    resource = resource,
                    user_id = user_id.map(|u| u.to_string()).unwrap_or_else(|| "unknown".to_string()),
                    error = %e,
                    "Admin action failed"
                );
            }
        }
    }

    /// Log node action
    pub fn log_node_action(
        action: &str,
        node_id: &NodeId,
        result: &Result<()>,
    ) {
        match result {
            Ok(()) => {
                debug!(
                    action = action,
                    node_id = %node_id,
                    "Node action succeeded"
                );
            }
            Err(e) => {
                warn!(
                    action = action,
                    node_id = %node_id,
                    error = %e,
                    "Node action failed"
                );
            }
        }
    }
}