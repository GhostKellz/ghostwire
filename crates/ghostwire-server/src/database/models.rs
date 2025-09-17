/// Database models with optimized serialization for zqlite
///
/// These models provide:
/// - Efficient JSON compression for metadata fields
/// - Type-safe conversions between database and application types
/// - Optimized queries using zqlite's advanced indexing

use ghostwire_common::{
    error::{Result, GhostWireError},
    types::*,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::SystemTime;

/// Database representation of a user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbUser {
    pub id: String,
    pub name: String,
    pub email: Option<String>,
    pub provider: String,
    pub provider_id: Option<String>,
    pub metadata: Option<String>, // Compressed JSON
    pub created_at: i64,
    pub last_seen: i64,
}

/// Database representation of a node
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbNode {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub public_key: Vec<u8>,
    pub ipv4: String,
    pub ipv6: Option<String>,
    pub endpoints: Option<String>, // Compressed JSON
    pub allowed_ips: Option<String>, // Compressed JSON
    pub tags: Option<String>, // Compressed JSON
    pub created_at: i64,
    pub last_seen: i64,
    pub expires_at: Option<i64>,
    pub online: bool,
}

/// Database representation of a route
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbRoute {
    pub id: String,
    pub node_id: String,
    pub prefix: String,
    pub advertised: bool,
    pub enabled: bool,
    pub is_primary: bool,
    pub created_at: i64,
}

/// Database representation of an API key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbApiKey {
    pub id: String,
    pub user_id: String,
    pub prefix: String,
    pub hash: String,
    pub description: Option<String>,
    pub created_at: i64,
    pub last_used: Option<i64>,
    pub expires_at: Option<i64>,
}

/// Database representation of a pre-auth key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbPreAuthKey {
    pub id: String,
    pub user_id: String,
    pub key_hash: String,
    pub reusable: bool,
    pub ephemeral: bool,
    pub used: bool,
    pub tags: Option<String>, // Compressed JSON
    pub created_at: i64,
    pub expires_at: Option<i64>,
    pub used_at: Option<i64>,
}

/// Database representation of an ACL rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbAclRule {
    pub id: i64,
    pub policy_version: i64,
    pub rule_index: i64,
    pub action: String,
    pub source_spec: String, // Compressed JSON
    pub dest_spec: String, // Compressed JSON
    pub created_at: i64,
}

/// Database representation of a DNS record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbDnsRecord {
    pub id: String,
    pub name: String,
    pub record_type: String,
    pub value: String,
    pub ttl: Option<i64>,
    pub created_at: i64,
    pub updated_at: i64,
}

/// Database representation of metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbMetrics {
    pub node_id: String,
    pub timestamp: i64,
    pub rx_bytes: i64,
    pub tx_bytes: i64,
    pub rx_packets: i64,
    pub tx_packets: i64,
    pub latency_ms: Option<f64>,
    pub packet_loss: Option<f64>,
    pub bandwidth_bps: Option<i64>,
}

/// Database representation of audit log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbAuditLog {
    pub id: String,
    pub timestamp: i64,
    pub user_id: Option<String>,
    pub node_id: Option<String>,
    pub action: String,
    pub resource_type: String,
    pub resource_id: Option<String>,
    pub details: Option<String>, // Compressed JSON
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub result: String,
}

// Conversion implementations

impl TryFrom<DbUser> for User {
    type Error = GhostWireError;

    fn try_from(db_user: DbUser) -> Result<Self> {
        let id = UserId::parse_str(&db_user.id)
            .map_err(|e| GhostWireError::database(format!("Invalid user ID: {}", e)))?;

        let provider = match db_user.provider.as_str() {
            "cli" => AuthProvider::Cli,
            "oidc" => AuthProvider::Oidc,
            "preauthkey" => AuthProvider::PreAuthKey,
            _ => return Err(GhostWireError::database(format!("Invalid auth provider: {}", db_user.provider))),
        };

        let created_at = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(db_user.created_at as u64);
        let last_seen = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(db_user.last_seen as u64);

        Ok(User {
            id,
            name: db_user.name,
            email: db_user.email,
            provider,
            provider_id: db_user.provider_id.unwrap_or_default(),
            created_at,
            last_seen,
        })
    }
}

impl From<&User> for DbUser {
    fn from(user: &User) -> Self {
        let created_at = user.created_at
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let last_seen = user.last_seen
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let provider = match user.provider {
            AuthProvider::Cli => "cli",
            AuthProvider::Oidc => "oidc",
            AuthProvider::PreAuthKey => "preauthkey",
        };

        Self {
            id: user.id.to_string(),
            name: user.name.clone(),
            email: user.email.clone(),
            provider: provider.to_string(),
            provider_id: if user.provider_id.is_empty() { None } else { Some(user.provider_id.clone()) },
            metadata: None, // TODO: Serialize metadata if needed
            created_at,
            last_seen,
        }
    }
}

impl TryFrom<DbNode> for Node {
    type Error = GhostWireError;

    fn try_from(db_node: DbNode) -> Result<Self> {
        let id = NodeId::parse_str(&db_node.id)
            .map_err(|e| GhostWireError::database(format!("Invalid node ID: {}", e)))?;

        let user_id = UserId::parse_str(&db_node.user_id)
            .map_err(|e| GhostWireError::database(format!("Invalid user ID: {}", e)))?;

        if db_node.public_key.len() != 32 {
            return Err(GhostWireError::database("Invalid public key length".to_string()));
        }

        let mut public_key_bytes = [0u8; 32];
        public_key_bytes.copy_from_slice(&db_node.public_key);
        let public_key = PublicKey::from_bytes(public_key_bytes);

        let ipv4: IpAddr = db_node.ipv4.parse()
            .map_err(|e| GhostWireError::database(format!("Invalid IPv4 address: {}", e)))?;

        let ipv6 = if let Some(ipv6_str) = db_node.ipv6 {
            Some(ipv6_str.parse()
                .map_err(|e| GhostWireError::database(format!("Invalid IPv6 address: {}", e)))?)
        } else {
            None
        };

        // Decompress and parse endpoints
        let endpoints = if let Some(endpoints_json) = db_node.endpoints {
            serde_json::from_str::<Vec<SocketAddr>>(&endpoints_json)
                .map_err(|e| GhostWireError::database(format!("Invalid endpoints JSON: {}", e)))?
                .into_iter()
                .map(|addr| Endpoint {
                    addr,
                    last_seen: SystemTime::now(), // TODO: Store last_seen per endpoint
                })
                .collect()
        } else {
            Vec::new()
        };

        // Decompress and parse allowed IPs
        let allowed_ips = if let Some(allowed_ips_json) = db_node.allowed_ips {
            serde_json::from_str::<Vec<ipnet::IpNet>>(&allowed_ips_json)
                .map_err(|e| GhostWireError::database(format!("Invalid allowed_ips JSON: {}", e)))?
        } else {
            Vec::new()
        };

        // Decompress and parse tags
        let tags = if let Some(tags_json) = db_node.tags {
            serde_json::from_str::<Vec<String>>(&tags_json)
                .map_err(|e| GhostWireError::database(format!("Invalid tags JSON: {}", e)))?
        } else {
            Vec::new()
        };

        let created_at = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(db_node.created_at as u64);
        let last_seen = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(db_node.last_seen as u64);

        let expires_at = db_node.expires_at.map(|exp| {
            SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(exp as u64)
        });

        Ok(Node {
            id,
            user_id,
            name: db_node.name,
            public_key,
            ipv4,
            ipv6,
            endpoints,
            allowed_ips,
            routes: Vec::new(), // Routes are loaded separately
            tags,
            created_at,
            last_seen,
            expires_at,
            online: db_node.online,
        })
    }
}

impl From<&Node> for DbNode {
    fn from(node: &Node) -> Self {
        let created_at = node.created_at
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let last_seen = node.last_seen
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let expires_at = node.expires_at.map(|exp| {
            exp.duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64
        });

        // Compress endpoints to JSON
        let endpoints = if !node.endpoints.is_empty() {
            let endpoint_addrs: Vec<SocketAddr> = node.endpoints.iter().map(|e| e.addr).collect();
            Some(serde_json::to_string(&endpoint_addrs).unwrap_or_default())
        } else {
            None
        };

        // Compress allowed IPs to JSON
        let allowed_ips = if !node.allowed_ips.is_empty() {
            Some(serde_json::to_string(&node.allowed_ips).unwrap_or_default())
        } else {
            None
        };

        // Compress tags to JSON
        let tags = if !node.tags.is_empty() {
            Some(serde_json::to_string(&node.tags).unwrap_or_default())
        } else {
            None
        };

        Self {
            id: node.id.to_string(),
            user_id: node.user_id.to_string(),
            name: node.name.clone(),
            public_key: node.public_key.as_bytes().to_vec(),
            ipv4: node.ipv4.to_string(),
            ipv6: node.ipv6.map(|ip| ip.to_string()),
            endpoints,
            allowed_ips,
            tags,
            created_at,
            last_seen,
            expires_at,
            online: node.online,
        }
    }
}

impl TryFrom<DbRoute> for Route {
    type Error = GhostWireError;

    fn try_from(db_route: DbRoute) -> Result<Self> {
        let id = uuid::Uuid::parse_str(&db_route.id)
            .map_err(|e| GhostWireError::database(format!("Invalid route ID: {}", e)))?;

        let node_id = NodeId::parse_str(&db_route.node_id)
            .map_err(|e| GhostWireError::database(format!("Invalid node ID: {}", e)))?;

        let prefix: ipnet::IpNet = db_route.prefix.parse()
            .map_err(|e| GhostWireError::database(format!("Invalid CIDR prefix: {}", e)))?;

        let created_at = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(db_route.created_at as u64);

        Ok(Route {
            id,
            node_id,
            prefix,
            advertised: db_route.advertised,
            enabled: db_route.enabled,
            is_primary: db_route.is_primary,
            created_at,
        })
    }
}

impl From<&Route> for DbRoute {
    fn from(route: &Route) -> Self {
        let created_at = route.created_at
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        Self {
            id: route.id.to_string(),
            node_id: route.node_id.to_string(),
            prefix: route.prefix.to_string(),
            advertised: route.advertised,
            enabled: route.enabled,
            is_primary: route.is_primary,
            created_at,
        }
    }
}

impl TryFrom<DbApiKey> for ApiKey {
    type Error = GhostWireError;

    fn try_from(db_key: DbApiKey) -> Result<Self> {
        let id = uuid::Uuid::parse_str(&db_key.id)
            .map_err(|e| GhostWireError::database(format!("Invalid API key ID: {}", e)))?;

        let created_at = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(db_key.created_at as u64);

        let last_used = db_key.last_used.map(|lu| {
            SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(lu as u64)
        });

        let expires_at = db_key.expires_at.map(|exp| {
            SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(exp as u64)
        });

        Ok(ApiKey {
            id,
            prefix: db_key.prefix,
            hash: db_key.hash,
            created_at,
            last_used,
            expires_at,
        })
    }
}

impl From<&ApiKey> for DbApiKey {
    fn from(key: &ApiKey) -> Self {
        let created_at = key.created_at
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let last_used = key.last_used.map(|lu| {
            lu.duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64
        });

        let expires_at = key.expires_at.map(|exp| {
            exp.duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64
        });

        Self {
            id: key.id.to_string(),
            user_id: String::new(), // Set by caller
            prefix: key.prefix.clone(),
            hash: key.hash.clone(),
            description: None, // TODO: Add description field to ApiKey
            created_at,
            last_used,
            expires_at,
        }
    }
}

impl TryFrom<DbPreAuthKey> for PreAuthKey {
    type Error = GhostWireError;

    fn try_from(db_key: DbPreAuthKey) -> Result<Self> {
        let id = uuid::Uuid::parse_str(&db_key.id)
            .map_err(|e| GhostWireError::database(format!("Invalid pre-auth key ID: {}", e)))?;

        let user_id = UserId::parse_str(&db_key.user_id)
            .map_err(|e| GhostWireError::database(format!("Invalid user ID: {}", e)))?;

        let tags = if let Some(tags_json) = db_key.tags {
            serde_json::from_str::<Vec<String>>(&tags_json)
                .map_err(|e| GhostWireError::database(format!("Invalid tags JSON: {}", e)))?
        } else {
            Vec::new()
        };

        let created_at = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(db_key.created_at as u64);

        let expires_at = db_key.expires_at.map(|exp| {
            SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(exp as u64)
        });

        Ok(PreAuthKey {
            id,
            user_id,
            key: String::new(), // Key is never stored, only hash
            reusable: db_key.reusable,
            ephemeral: db_key.ephemeral,
            used: db_key.used,
            tags,
            created_at,
            expires_at,
        })
    }
}

impl From<&PreAuthKey> for DbPreAuthKey {
    fn from(key: &PreAuthKey) -> Self {
        let created_at = key.created_at
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let expires_at = key.expires_at.map(|exp| {
            exp.duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64
        });

        let tags = if !key.tags.is_empty() {
            Some(serde_json::to_string(&key.tags).unwrap_or_default())
        } else {
            None
        };

        Self {
            id: key.id.to_string(),
            user_id: key.user_id.to_string(),
            key_hash: String::new(), // Set by caller with hash of actual key
            reusable: key.reusable,
            ephemeral: key.ephemeral,
            used: key.used,
            tags,
            created_at,
            expires_at,
            used_at: None, // Set when key is used
        }
    }
}

impl TryFrom<DbAclRule> for AclRule {
    type Error = GhostWireError;

    fn try_from(db_rule: DbAclRule) -> Result<Self> {
        let source_spec: Vec<String> = serde_json::from_str(&db_rule.source_spec)
            .map_err(|e| GhostWireError::database(format!("Invalid source spec JSON: {}", e)))?;

        let dest_spec: Vec<String> = serde_json::from_str(&db_rule.dest_spec)
            .map_err(|e| GhostWireError::database(format!("Invalid dest spec JSON: {}", e)))?;

        let action = match db_rule.action.as_str() {
            "accept" => AclAction::Accept,
            "deny" => AclAction::Deny,
            _ => return Err(GhostWireError::database(format!("Invalid ACL action: {}", db_rule.action))),
        };

        let created_at = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(db_rule.created_at as u64);

        Ok(AclRule {
            id: Some(db_rule.id),
            policy_version: db_rule.policy_version as u32,
            rule_index: db_rule.rule_index as usize,
            action,
            source_spec,
            dest_spec,
            created_at,
        })
    }
}

impl TryFrom<DbDnsRecord> for DnsRecord {
    type Error = GhostWireError;

    fn try_from(db_record: DbDnsRecord) -> Result<Self> {
        let id = uuid::Uuid::parse_str(&db_record.id)
            .map_err(|e| GhostWireError::database(format!("Invalid DNS record ID: {}", e)))?;

        let created_at = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(db_record.created_at as u64);
        let updated_at = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(db_record.updated_at as u64);

        Ok(DnsRecord {
            id,
            name: db_record.name,
            record_type: db_record.record_type,
            value: db_record.value,
            ttl: db_record.ttl.unwrap_or(300) as u32,
            created_at,
            updated_at,
        })
    }
}

impl TryFrom<DbNodeMetrics> for NodeMetrics {
    type Error = GhostWireError;

    fn try_from(db_metrics: DbNodeMetrics) -> Result<Self> {
        let node_id = uuid::Uuid::parse_str(&db_metrics.node_id)
            .map_err(|e| GhostWireError::database(format!("Invalid node ID: {}", e)))?;

        let timestamp = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(db_metrics.timestamp as u64);

        Ok(NodeMetrics {
            node_id,
            timestamp,
            rx_bytes: db_metrics.rx_bytes as u64,
            tx_bytes: db_metrics.tx_bytes as u64,
            rx_packets: db_metrics.rx_packets as u64,
            tx_packets: db_metrics.tx_packets as u64,
            latency_ms: db_metrics.latency_ms,
            packet_loss: db_metrics.packet_loss,
            bandwidth_bps: db_metrics.bandwidth_bps.map(|b| b as u64),
        })
    }
}

impl TryFrom<DbAuditEvent> for AuditEvent {
    type Error = GhostWireError;

    fn try_from(db_event: DbAuditEvent) -> Result<Self> {
        let id = uuid::Uuid::parse_str(&db_event.id)
            .map_err(|e| GhostWireError::database(format!("Invalid audit event ID: {}", e)))?;

        let timestamp = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(db_event.timestamp as u64);

        let user_id = db_event.user_id.as_ref()
            .map(|uid| uuid::Uuid::parse_str(uid))
            .transpose()
            .map_err(|e| GhostWireError::database(format!("Invalid user ID: {}", e)))?;

        let node_id = db_event.node_id.as_ref()
            .map(|nid| uuid::Uuid::parse_str(nid))
            .transpose()
            .map_err(|e| GhostWireError::database(format!("Invalid node ID: {}", e)))?;

        let details = db_event.details.as_ref()
            .map(|d| serde_json::from_str(d))
            .transpose()
            .map_err(|e| GhostWireError::database(format!("Invalid details JSON: {}", e)))?;

        let result = match db_event.result.as_str() {
            "success" => AuditResult::Success,
            "failure" => AuditResult::Failure,
            "denied" => AuditResult::Denied,
            _ => return Err(GhostWireError::database(format!("Invalid audit result: {}", db_event.result))),
        };

        Ok(AuditEvent {
            id,
            timestamp,
            user_id,
            node_id,
            action: db_event.action,
            resource_type: db_event.resource_type,
            resource_id: db_event.resource_id,
            details,
            ip_address: db_event.ip_address,
            user_agent: db_event.user_agent,
            result,
        })
    }
}


/// Helper functions for compressed JSON fields
pub mod compression {
    use ghostwire_common::error::{Result, GhostWireError};
    use serde::{Deserialize, Serialize};

    /// Compress data to JSON string for storage
    pub fn compress_json<T: Serialize>(data: &T) -> Result<String> {
        serde_json::to_string(data)
            .map_err(|e| GhostWireError::database(format!("JSON compression failed: {}", e)))
    }

    /// Decompress JSON string to data
    pub fn decompress_json<T: for<'de> Deserialize<'de>>(json: &str) -> Result<T> {
        serde_json::from_str(json)
            .map_err(|e| GhostWireError::database(format!("JSON decompression failed: {}", e)))
    }

    /// Compress optional data
    pub fn compress_optional<T: Serialize>(data: &Option<T>) -> Result<Option<String>> {
        match data {
            Some(d) => Ok(Some(compress_json(d)?)),
            None => Ok(None),
        }
    }

    /// Decompress optional data
    pub fn decompress_optional<T: for<'de> Deserialize<'de>>(json: &Option<String>) -> Result<Option<T>> {
        match json {
            Some(j) => Ok(Some(decompress_json(j)?)),
            None => Ok(None),
        }
    }
}