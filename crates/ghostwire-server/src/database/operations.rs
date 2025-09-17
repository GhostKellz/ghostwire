/// High-performance CRUD operations using zqlite optimizations
///
/// This module provides database operations optimized for:
/// - Fast peer queries using bitmap indexes
/// - Spatial CIDR operations using R-tree indexes
/// - Compressed metadata storage
/// - Parallel write operations
/// - Real-time metrics with time-series support

use crate::database::{
    connection::DatabaseConnection,
    models::*,
};
use ghostwire_common::{
    error::{Result, GhostWireError},
    types::*,
};
use std::net::SocketAddr;
use std::time::SystemTime;
use tracing::{debug, trace};

/// User operations
pub struct UserOperations;

impl UserOperations {
    /// Create a new user
    pub async fn create(
        conn: &DatabaseConnection,
        name: &str,
        email: Option<&str>,
    ) -> Result<User> {
        let user_id = uuid::Uuid::new_v4();
        let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default().as_secs() as i64;

        let rows_affected = conn.execute(
            r#"
            INSERT INTO users (id, name, email, provider, created_at, last_seen)
            VALUES (?1, ?2, ?3, 'cli', ?4, ?5)
            "#,
            &[
                user_id.to_string().into(),
                name.into(),
                email.map(|e| e.into()).unwrap_or("".into()),
                now.into(),
                now.into(),
            ]
        ).await?;

        if rows_affected == 0 {
            return Err(GhostWireError::database("Failed to create user"));
        }

        debug!("Created user: {} ({})", name, user_id);

        Ok(User {
            id: user_id,
            name: name.to_string(),
            email: email.map(|s| s.to_string()),
            provider: AuthProvider::Cli,
            provider_id: String::new(),
            created_at: SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(now as u64),
            last_seen: SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(now as u64),
        })
    }

    /// Get user by name or ID
    pub async fn get_by_identifier(
        conn: &DatabaseConnection,
        identifier: &str,
    ) -> Result<User> {
        let db_user = conn.query_row(
            r#"
            SELECT id, name, email, provider, provider_id, metadata, created_at, last_seen
            FROM users
            WHERE id = ?1 OR name = ?1
            LIMIT 1
            "#,
            &[identifier.into()],
            |row| {
                Ok(DbUser {
                    id: row.get::<String>("id")?,
                    name: row.get::<String>("name")?,
                    email: row.get::<Option<String>>("email")?,
                    provider: row.get::<String>("provider")?,
                    provider_id: row.get::<Option<String>>("provider_id")?,
                    metadata: row.get::<Option<String>>("metadata")?,
                    created_at: row.get::<i64>("created_at")?,
                    last_seen: row.get::<i64>("last_seen")?,
                })
            }
        ).await?;

        User::try_from(db_user)
    }

    /// List all users
    pub async fn list_all(conn: &DatabaseConnection) -> Result<Vec<User>> {
        let db_users = conn.query_rows(
            r#"
            SELECT id, name, email, provider, provider_id, metadata, created_at, last_seen
            FROM users
            ORDER BY name
            "#,
            &[],
            |row| {
                Ok(DbUser {
                    id: row.get::<String>("id")?,
                    name: row.get::<String>("name")?,
                    email: row.get::<Option<String>>("email")?,
                    provider: row.get::<String>("provider")?,
                    provider_id: row.get::<Option<String>>("provider_id")?,
                    metadata: row.get::<Option<String>>("metadata")?,
                    created_at: row.get::<i64>("created_at")?,
                    last_seen: row.get::<i64>("last_seen")?,
                })
            }
        ).await?;

        db_users.into_iter()
            .map(User::try_from)
            .collect()
    }

    /// Delete user
    pub async fn delete(conn: &DatabaseConnection, identifier: &str) -> Result<()> {
        let rows_affected = conn.execute(
            "DELETE FROM users WHERE id = ?1 OR name = ?1",
            &[identifier.into()]
        ).await?;

        if rows_affected == 0 {
            return Err(GhostWireError::database("User not found"));
        }

        debug!("Deleted user: {}", identifier);
        Ok(())
    }

    /// Update user last seen
    pub async fn update_last_seen(
        conn: &DatabaseConnection,
        user_id: &UserId,
    ) -> Result<()> {
        let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default().as_secs() as i64;

        conn.execute(
            "UPDATE users SET last_seen = ?1 WHERE id = ?2",
            &[now.into(), user_id.to_string().into()]
        ).await?;

        Ok(())
    }
}

/// Node operations with spatial indexing optimization
pub struct NodeOperations;

impl NodeOperations {
    /// Create a new node with IP allocation
    pub async fn create(
        conn: &DatabaseConnection,
        user_id: &UserId,
        name: &str,
        public_key: PublicKey,
    ) -> Result<Node> {
        let node_id = uuid::Uuid::new_v4();
        let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default().as_secs() as i64;

        // Allocate IP address (simplified - would use proper IP allocation)
        let ipv4 = Self::allocate_ip(conn).await?;

        let rows_affected = conn.execute(
            r#"
            INSERT INTO nodes (
                id, user_id, name, public_key, ipv4, created_at, last_seen, online
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            "#,
            &[
                node_id.to_string().into(),
                user_id.to_string().into(),
                name.into(),
                public_key.as_bytes().to_vec().into(),
                ipv4.to_string().into(),
                now.into(),
                now.into(),
                false.into(),
            ]
        ).await?;

        if rows_affected == 0 {
            return Err(GhostWireError::database("Failed to create node"));
        }

        debug!("Created node: {} ({}) for user {}", name, node_id, user_id);

        Ok(Node {
            id: node_id,
            user_id: *user_id,
            name: name.to_string(),
            public_key,
            ipv4,
            ipv6: None,
            endpoints: Vec::new(),
            allowed_ips: Vec::new(),
            routes: Vec::new(),
            tags: Vec::new(),
            created_at: SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(now as u64),
            last_seen: SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(now as u64),
            expires_at: None,
            online: false,
        })
    }

    /// Get node by ID or name
    pub async fn get_by_identifier(
        conn: &DatabaseConnection,
        identifier: &str,
    ) -> Result<Node> {
        let db_node = conn.query_row(
            r#"
            SELECT id, user_id, name, public_key, ipv4, ipv6, endpoints,
                   allowed_ips, tags, created_at, last_seen, expires_at, online
            FROM nodes
            WHERE id = ?1 OR name = ?1
            LIMIT 1
            "#,
            &[identifier.into()],
            |row| {
                Ok(DbNode {
                    id: row.get::<String>("id")?,
                    user_id: row.get::<String>("user_id")?,
                    name: row.get::<String>("name")?,
                    public_key: row.get::<Vec<u8>>("public_key")?,
                    ipv4: row.get::<String>("ipv4")?,
                    ipv6: row.get::<Option<String>>("ipv6")?,
                    endpoints: row.get::<Option<String>>("endpoints")?,
                    allowed_ips: row.get::<Option<String>>("allowed_ips")?,
                    tags: row.get::<Option<String>>("tags")?,
                    created_at: row.get::<i64>("created_at")?,
                    last_seen: row.get::<i64>("last_seen")?,
                    expires_at: row.get::<Option<i64>>("expires_at")?,
                    online: row.get::<bool>("online")?,
                })
            }
        ).await?;

        let mut node = Node::try_from(db_node)?;

        // Load routes for this node
        node.routes = RouteOperations::get_by_node(conn, &node.id).await?;

        Ok(node)
    }

    /// Get nodes by user
    pub async fn get_by_user(
        conn: &DatabaseConnection,
        user_id: &UserId,
    ) -> Result<Vec<Node>> {
        let db_nodes = conn.query_rows(
            r#"
            SELECT id, user_id, name, public_key, ipv4, ipv6, endpoints,
                   allowed_ips, tags, created_at, last_seen, expires_at, online
            FROM nodes
            WHERE user_id = ?1
            ORDER BY name
            "#,
            &[user_id.to_string().into()],
            |row| {
                Ok(DbNode {
                    id: row.get::<String>("id")?,
                    user_id: row.get::<String>("user_id")?,
                    name: row.get::<String>("name")?,
                    public_key: row.get::<Vec<u8>>("public_key")?,
                    ipv4: row.get::<String>("ipv4")?,
                    ipv6: row.get::<Option<String>>("ipv6")?,
                    endpoints: row.get::<Option<String>>("endpoints")?,
                    allowed_ips: row.get::<Option<String>>("allowed_ips")?,
                    tags: row.get::<Option<String>>("tags")?,
                    created_at: row.get::<i64>("created_at")?,
                    last_seen: row.get::<i64>("last_seen")?,
                    expires_at: row.get::<Option<i64>>("expires_at")?,
                    online: row.get::<bool>("online")?,
                })
            }
        ).await?;

        let mut nodes = Vec::new();
        for db_node in db_nodes {
            let mut node = Node::try_from(db_node)?;
            node.routes = RouteOperations::get_by_node(conn, &node.id).await?;
            nodes.push(node);
        }

        Ok(nodes)
    }

    /// List all nodes with optional filters
    pub async fn list_all(
        conn: &DatabaseConnection,
        include_expired: bool,
    ) -> Result<Vec<Node>> {
        let sql = if include_expired {
            r#"
            SELECT id, user_id, name, public_key, ipv4, ipv6, endpoints,
                   allowed_ips, tags, created_at, last_seen, expires_at, online
            FROM nodes
            ORDER BY last_seen DESC
            "#
        } else {
            r#"
            SELECT id, user_id, name, public_key, ipv4, ipv6, endpoints,
                   allowed_ips, tags, created_at, last_seen, expires_at, online
            FROM nodes
            WHERE expires_at IS NULL OR expires_at > ?1
            ORDER BY last_seen DESC
            "#
        };

        let params = if include_expired {
            vec![]
        } else {
            vec![SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default().as_secs().into()]
        };

        let db_nodes = conn.query_rows(sql, &params, |row| {
            Ok(DbNode {
                id: row.get::<String>("id")?,
                user_id: row.get::<String>("user_id")?,
                name: row.get::<String>("name")?,
                public_key: row.get::<Vec<u8>>("public_key")?,
                ipv4: row.get::<String>("ipv4")?,
                ipv6: row.get::<Option<String>>("ipv6")?,
                endpoints: row.get::<Option<String>>("endpoints")?,
                allowed_ips: row.get::<Option<String>>("allowed_ips")?,
                tags: row.get::<Option<String>>("tags")?,
                created_at: row.get::<i64>("created_at")?,
                last_seen: row.get::<i64>("last_seen")?,
                expires_at: row.get::<Option<i64>>("expires_at")?,
                online: row.get::<bool>("online")?,
            })
        }).await?;

        db_nodes.into_iter()
            .map(Node::try_from)
            .collect()
    }

    /// Update node endpoint
    pub async fn update_endpoint(
        conn: &DatabaseConnection,
        node_id: &NodeId,
        endpoint: &Endpoint,
    ) -> Result<()> {
        // Get current endpoints and update
        let current_endpoints_json = conn.query_scalar::<String>(
            "SELECT COALESCE(endpoints, '[]') FROM nodes WHERE id = ?1"
        ).await.unwrap_or_else(|_| "[]".to_string());

        let mut endpoints: Vec<SocketAddr> = serde_json::from_str(&current_endpoints_json)
            .unwrap_or_default();

        // Remove existing endpoint with same address and add new one
        endpoints.retain(|ep| ep != &endpoint.addr);
        endpoints.push(endpoint.addr);

        let endpoints_json = serde_json::to_string(&endpoints)
            .map_err(|e| GhostWireError::database(format!("Failed to serialize endpoints: {}", e)))?;

        let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default().as_secs() as i64;

        conn.execute(
            "UPDATE nodes SET endpoints = ?1, last_seen = ?2, online = true WHERE id = ?3",
            &[endpoints_json.into(), now.into(), node_id.to_string().into()]
        ).await?;

        trace!("Updated endpoint for node {}: {}", node_id, endpoint.addr);
        Ok(())
    }

    /// Update node heartbeat
    pub async fn update_heartbeat(
        conn: &DatabaseConnection,
        node_id: &NodeId,
    ) -> Result<()> {
        let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default().as_secs() as i64;

        conn.execute(
            "UPDATE nodes SET last_seen = ?1, online = true WHERE id = ?2",
            &[now.into(), node_id.to_string().into()]
        ).await?;

        Ok(())
    }

    /// Delete node
    pub async fn delete(conn: &DatabaseConnection, identifier: &str) -> Result<()> {
        let rows_affected = conn.execute(
            "DELETE FROM nodes WHERE id = ?1 OR name = ?1",
            &[identifier.into()]
        ).await?;

        if rows_affected == 0 {
            return Err(GhostWireError::database("Node not found"));
        }

        debug!("Deleted node: {}", identifier);
        Ok(())
    }

    /// Move node to different user
    pub async fn move_to_user(
        conn: &DatabaseConnection,
        node_identifier: &str,
        new_user_id: &UserId,
    ) -> Result<()> {
        let rows_affected = conn.execute(
            "UPDATE nodes SET user_id = ?1 WHERE id = ?2 OR name = ?2",
            &[new_user_id.to_string().into(), node_identifier.into()]
        ).await?;

        if rows_affected == 0 {
            return Err(GhostWireError::database("Node not found"));
        }

        debug!("Moved node {} to user {}", node_identifier, new_user_id);
        Ok(())
    }

    /// Execute complex query for network topology
    pub async fn execute_complex_query(
        conn: &DatabaseConnection,
        sql: &str,
        params: &[zqlite::Value],
    ) -> Result<Vec<Node>> {
        let db_nodes = conn.query_rows(sql, params, |row| {
            Ok(DbNode {
                id: row.get::<String>("id")?,
                user_id: row.get::<String>("user_id")?,
                name: row.get::<String>("name")?,
                public_key: row.get::<Vec<u8>>("public_key")?,
                ipv4: row.get::<String>("ipv4")?,
                ipv6: row.get::<Option<String>>("ipv6")?,
                endpoints: row.get::<Option<String>>("endpoints")?,
                allowed_ips: row.get::<Option<String>>("allowed_ips")?,
                tags: row.get::<Option<String>>("tags")?,
                created_at: row.get::<i64>("created_at")?,
                last_seen: row.get::<i64>("last_seen")?,
                expires_at: row.get::<Option<i64>>("expires_at")?,
                online: row.get::<bool>("online")?,
            })
        }).await?;

        db_nodes.into_iter()
            .map(Node::try_from)
            .collect()
    }

    /// Allocate IP address (simplified implementation)
    async fn allocate_ip(conn: &DatabaseConnection) -> Result<std::net::IpAddr> {
        // Simple IP allocation - in production would use proper CIDR management
        let existing_count = conn.query_scalar::<u64>(
            "SELECT COUNT(*) FROM nodes"
        ).await.unwrap_or(0);

        let ip_suffix = (existing_count + 1) % 254 + 1;
        let ip_str = format!("100.64.0.{}", ip_suffix);

        ip_str.parse()
            .map_err(|e| GhostWireError::database(format!("Invalid IP address: {}", e)))
    }
}

/// Route operations with spatial indexing
pub struct RouteOperations;

impl RouteOperations {
    /// Create a new route
    pub async fn create(
        conn: &DatabaseConnection,
        node_id: &NodeId,
        prefix: ipnet::IpNet,
    ) -> Result<Route> {
        let route_id = uuid::Uuid::new_v4();
        let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default().as_secs() as i64;

        let rows_affected = conn.execute(
            r#"
            INSERT INTO routes (id, node_id, prefix, advertised, enabled, is_primary, created_at)
            VALUES (?1, ?2, ?3, true, false, false, ?4)
            "#,
            &[
                route_id.to_string().into(),
                node_id.to_string().into(),
                prefix.to_string().into(),
                now.into(),
            ]
        ).await?;

        if rows_affected == 0 {
            return Err(GhostWireError::database("Failed to create route"));
        }

        debug!("Created route: {} for node {}", prefix, node_id);

        Ok(Route {
            id: route_id,
            node_id: *node_id,
            prefix,
            advertised: true,
            enabled: false,
            is_primary: false,
            created_at: SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(now as u64),
        })
    }

    /// Get routes by node
    pub async fn get_by_node(
        conn: &DatabaseConnection,
        node_id: &NodeId,
    ) -> Result<Vec<Route>> {
        let db_routes = conn.query_rows(
            r#"
            SELECT id, node_id, prefix, advertised, enabled, is_primary, created_at
            FROM routes
            WHERE node_id = ?1
            ORDER BY prefix
            "#,
            &[node_id.to_string().into()],
            |row| {
                Ok(DbRoute {
                    id: row.get::<String>("id")?,
                    node_id: row.get::<String>("node_id")?,
                    prefix: row.get::<String>("prefix")?,
                    advertised: row.get::<bool>("advertised")?,
                    enabled: row.get::<bool>("enabled")?,
                    is_primary: row.get::<bool>("is_primary")?,
                    created_at: row.get::<i64>("created_at")?,
                })
            }
        ).await?;

        db_routes.into_iter()
            .map(Route::try_from)
            .collect()
    }

    /// List routes with optional node filter
    pub async fn list(
        conn: &DatabaseConnection,
        node_id: Option<&NodeId>,
    ) -> Result<Vec<Route>> {
        let (sql, params) = if let Some(node_id) = node_id {
            (
                r#"
                SELECT id, node_id, prefix, advertised, enabled, is_primary, created_at
                FROM routes
                WHERE node_id = ?1
                ORDER BY prefix
                "#,
                vec![node_id.to_string().into()],
            )
        } else {
            (
                r#"
                SELECT id, node_id, prefix, advertised, enabled, is_primary, created_at
                FROM routes
                ORDER BY prefix
                "#,
                vec![],
            )
        };

        let db_routes = conn.query_rows(sql, &params, |row| {
            Ok(DbRoute {
                id: row.get::<String>("id")?,
                node_id: row.get::<String>("node_id")?,
                prefix: row.get::<String>("prefix")?,
                advertised: row.get::<bool>("advertised")?,
                enabled: row.get::<bool>("enabled")?,
                is_primary: row.get::<bool>("is_primary")?,
                created_at: row.get::<i64>("created_at")?,
            })
        }).await?;

        db_routes.into_iter()
            .map(Route::try_from)
            .collect()
    }

    /// Enable/disable route
    pub async fn set_enabled(
        conn: &DatabaseConnection,
        route_id: &uuid::Uuid,
        enabled: bool,
    ) -> Result<()> {
        let rows_affected = conn.execute(
            "UPDATE routes SET enabled = ?1 WHERE id = ?2",
            &[enabled.into(), route_id.to_string().into()]
        ).await?;

        if rows_affected == 0 {
            return Err(GhostWireError::database("Route not found"));
        }

        debug!("Route {} enabled: {}", route_id, enabled);
        Ok(())
    }

    /// Delete route
    pub async fn delete(
        conn: &DatabaseConnection,
        route_id: &uuid::Uuid,
    ) -> Result<()> {
        let rows_affected = conn.execute(
            "DELETE FROM routes WHERE id = ?1",
            &[route_id.to_string().into()]
        ).await?;

        if rows_affected == 0 {
            return Err(GhostWireError::database("Route not found"));
        }

        debug!("Deleted route: {}", route_id);
        Ok(())
    }

    /// Execute spatial query using R-tree optimization
    pub async fn execute_spatial_query(
        conn: &DatabaseConnection,
        sql: &str,
        params: &[zqlite::Value],
    ) -> Result<Vec<Route>> {
        let db_routes = conn.execute_spatial_query(sql, params, |row| {
            Ok(DbRoute {
                id: row.get::<String>("id")?,
                node_id: row.get::<String>("node_id")?,
                prefix: row.get::<String>("prefix")?,
                advertised: row.get::<bool>("advertised")?,
                enabled: row.get::<bool>("enabled")?,
                is_primary: row.get::<bool>("is_primary")?,
                created_at: row.get::<i64>("created_at")?,
            })
        }).await?;

        db_routes.into_iter()
            .map(Route::try_from)
            .collect()
    }
}

/// API key operations
pub struct ApiKeyOperations;

impl ApiKeyOperations {
    /// Create API key with secure random generation
    pub async fn create(
        conn: &DatabaseConnection,
        user_id: &UserId,
        description: &str,
    ) -> Result<(ApiKey, String)> {
        use blake3::Hasher;
        use rand::Rng;

        let key_id = uuid::Uuid::new_v4();
        let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default().as_secs() as i64;

        // Generate secure random key
        let mut rng = rand::thread_rng();
        let key_bytes: [u8; 32] = rng.gen();
        let key = base64::encode(&key_bytes);
        let prefix = &key[..8];

        // Hash the key for storage
        let mut hasher = Hasher::new();
        hasher.update(key.as_bytes());
        let hash = hasher.finalize().to_hex().to_string();

        let rows_affected = conn.execute(
            r#"
            INSERT INTO api_keys (id, user_id, prefix, hash, description, created_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            "#,
            &[
                key_id.to_string().into(),
                user_id.to_string().into(),
                prefix.into(),
                hash.clone().into(),
                description.into(),
                now.into(),
            ]
        ).await?;

        if rows_affected == 0 {
            return Err(GhostWireError::database("Failed to create API key"));
        }

        debug!("Created API key for user {}: {}", user_id, prefix);

        let api_key = ApiKey {
            id: key_id,
            prefix: prefix.to_string(),
            hash,
            created_at: SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(now as u64),
            last_used: None,
            expires_at: None,
        };

        Ok((api_key, key))
    }

    /// Validate API key
    pub async fn validate(conn: &DatabaseConnection, key: &str) -> Result<ApiKey> {
        use blake3::Hasher;

        // Hash the provided key
        let mut hasher = Hasher::new();
        hasher.update(key.as_bytes());
        let hash = hasher.finalize().to_hex().to_string();

        let db_key = conn.query_row(
            r#"
            SELECT id, user_id, prefix, hash, description, created_at, last_used, expires_at
            FROM api_keys
            WHERE hash = ?1 AND (expires_at IS NULL OR expires_at > ?2)
            LIMIT 1
            "#,
            &[
                hash.into(),
                SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap_or_default().as_secs().into()
            ],
            |row| {
                Ok(DbApiKey {
                    id: row.get::<String>("id")?,
                    user_id: row.get::<String>("user_id")?,
                    prefix: row.get::<String>("prefix")?,
                    hash: row.get::<String>("hash")?,
                    description: row.get::<Option<String>>("description")?,
                    created_at: row.get::<i64>("created_at")?,
                    last_used: row.get::<Option<i64>>("last_used")?,
                    expires_at: row.get::<Option<i64>>("expires_at")?,
                })
            }
        ).await?;

        // Update last used timestamp
        let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default().as_secs() as i64;

        conn.execute(
            "UPDATE api_keys SET last_used = ?1 WHERE id = ?2",
            &[now.into(), db_key.id.clone().into()]
        ).await?;

        ApiKey::try_from(db_key)
    }

    /// List API keys for user
    pub async fn list_for_user(
        conn: &DatabaseConnection,
        user_id: &UserId,
    ) -> Result<Vec<ApiKey>> {
        let db_keys = conn.query_rows(
            r#"
            SELECT id, user_id, prefix, hash, description, created_at, last_used, expires_at
            FROM api_keys
            WHERE user_id = ?1
            ORDER BY created_at DESC
            "#,
            &[user_id.to_string().into()],
            |row| {
                Ok(DbApiKey {
                    id: row.get::<String>("id")?,
                    user_id: row.get::<String>("user_id")?,
                    prefix: row.get::<String>("prefix")?,
                    hash: row.get::<String>("hash")?,
                    description: row.get::<Option<String>>("description")?,
                    created_at: row.get::<i64>("created_at")?,
                    last_used: row.get::<Option<i64>>("last_used")?,
                    expires_at: row.get::<Option<i64>>("expires_at")?,
                })
            }
        ).await?;

        db_keys.into_iter()
            .map(ApiKey::try_from)
            .collect()
    }

    /// Delete API key
    pub async fn delete(
        conn: &DatabaseConnection,
        key_id: &uuid::Uuid,
    ) -> Result<()> {
        let rows_affected = conn.execute(
            "DELETE FROM api_keys WHERE id = ?1",
            &[key_id.to_string().into()]
        ).await?;

        if rows_affected == 0 {
            return Err(GhostWireError::database("API key not found"));
        }

        debug!("Deleted API key: {}", key_id);
        Ok(())
    }
}

/// Pre-auth key operations
pub struct PreAuthKeyOperations;

impl PreAuthKeyOperations {
    /// Create pre-auth key
    pub async fn create(
        conn: &DatabaseConnection,
        user_id: &UserId,
        reusable: bool,
        ephemeral: bool,
        tags: Vec<String>,
        expires_at: Option<SystemTime>,
    ) -> Result<PreAuthKey> {
        use blake3::Hasher;
        use rand::Rng;

        let key_id = uuid::Uuid::new_v4();
        let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default().as_secs() as i64;

        // Generate secure random key
        let mut rng = rand::thread_rng();
        let key_bytes: [u8; 32] = rng.gen();
        let key = base64::encode(&key_bytes);

        // Hash the key for storage
        let mut hasher = Hasher::new();
        hasher.update(key.as_bytes());
        let key_hash = hasher.finalize().to_hex().to_string();

        let tags_json = if !tags.is_empty() {
            Some(serde_json::to_string(&tags)
                .map_err(|e| GhostWireError::database(format!("Failed to serialize tags: {}", e)))?)
        } else {
            None
        };

        let expires_at_timestamp = expires_at.map(|exp| {
            exp.duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default().as_secs() as i64
        });

        let rows_affected = conn.execute(
            r#"
            INSERT INTO preauth_keys (
                id, user_id, key_hash, reusable, ephemeral, used, tags, created_at, expires_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, false, ?6, ?7, ?8)
            "#,
            &[
                key_id.to_string().into(),
                user_id.to_string().into(),
                key_hash.into(),
                reusable.into(),
                ephemeral.into(),
                tags_json.map(|t| t.into()).unwrap_or("".into()),
                now.into(),
                expires_at_timestamp.map(|t| t.into()).unwrap_or("".into()),
            ]
        ).await?;

        if rows_affected == 0 {
            return Err(GhostWireError::database("Failed to create pre-auth key"));
        }

        debug!("Created pre-auth key for user {}: {}", user_id, key_id);

        Ok(PreAuthKey {
            id: key_id,
            user_id: *user_id,
            key, // Return the actual key, not stored
            reusable,
            ephemeral,
            used: false,
            tags,
            created_at: SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(now as u64),
            expires_at,
        })
    }

    /// Use/validate pre-auth key
    pub async fn use_key(conn: &DatabaseConnection, key: &str) -> Result<PreAuthKey> {
        use blake3::Hasher;

        // Hash the provided key
        let mut hasher = Hasher::new();
        hasher.update(key.as_bytes());
        let key_hash = hasher.finalize().to_hex().to_string();

        let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default().as_secs() as i64;

        // Find and validate the key
        let db_key = conn.query_row(
            r#"
            SELECT id, user_id, key_hash, reusable, ephemeral, used, tags, created_at, expires_at, used_at
            FROM preauth_keys
            WHERE key_hash = ?1
              AND (used = false OR reusable = true)
              AND (expires_at IS NULL OR expires_at > ?2)
            LIMIT 1
            "#,
            &[key_hash.into(), now.into()],
            |row| {
                Ok(DbPreAuthKey {
                    id: row.get::<String>("id")?,
                    user_id: row.get::<String>("user_id")?,
                    key_hash: row.get::<String>("key_hash")?,
                    reusable: row.get::<bool>("reusable")?,
                    ephemeral: row.get::<bool>("ephemeral")?,
                    used: row.get::<bool>("used")?,
                    tags: row.get::<Option<String>>("tags")?,
                    created_at: row.get::<i64>("created_at")?,
                    expires_at: row.get::<Option<i64>>("expires_at")?,
                    used_at: row.get::<Option<i64>>("used_at")?,
                })
            }
        ).await?;

        // Mark as used if not reusable
        if !db_key.reusable {
            conn.execute(
                "UPDATE preauth_keys SET used = true, used_at = ?1 WHERE id = ?2",
                &[now.into(), db_key.id.clone().into()]
            ).await?;
        }

        PreAuthKey::try_from(db_key)
    }

    /// List pre-auth keys for user
    pub async fn list_for_user(
        conn: &DatabaseConnection,
        user_id: &UserId,
    ) -> Result<Vec<PreAuthKey>> {
        let db_keys = conn.query_rows(
            r#"
            SELECT id, user_id, key_hash, reusable, ephemeral, used, tags, created_at, expires_at, used_at
            FROM preauth_keys
            WHERE user_id = ?1
            ORDER BY created_at DESC
            "#,
            &[user_id.to_string().into()],
            |row| {
                Ok(DbPreAuthKey {
                    id: row.get::<String>("id")?,
                    user_id: row.get::<String>("user_id")?,
                    key_hash: row.get::<String>("key_hash")?,
                    reusable: row.get::<bool>("reusable")?,
                    ephemeral: row.get::<bool>("ephemeral")?,
                    used: row.get::<bool>("used")?,
                    tags: row.get::<Option<String>>("tags")?,
                    created_at: row.get::<i64>("created_at")?,
                    expires_at: row.get::<Option<i64>>("expires_at")?,
                    used_at: row.get::<Option<i64>>("used_at")?,
                })
            }
        ).await?;

        db_keys.into_iter()
            .map(PreAuthKey::try_from)
            .collect()
    }

    /// Delete pre-auth key
    pub async fn delete(
        conn: &DatabaseConnection,
        key_id: &uuid::Uuid,
    ) -> Result<()> {
        let rows_affected = conn.execute(
            "DELETE FROM preauth_keys WHERE id = ?1",
            &[key_id.to_string().into()]
        ).await?;

        if rows_affected == 0 {
            return Err(GhostWireError::database("Pre-auth key not found"));
        }

        debug!("Deleted pre-auth key: {}", key_id);
        Ok(())
    }

    /// Count pre-auth keys for user
    pub async fn count_for_user(
        conn: &DatabaseConnection,
        user_id: &UserId,
    ) -> Result<u64> {
        conn.query_scalar::<Option<u64>>(
            "SELECT COUNT(*) FROM preauth_keys WHERE user_id = ?1"
        ).await.map(|opt| opt.unwrap_or(0))
    }
}

/// ACL rule operations with bitmap indexing for fast policy evaluation
pub struct AclOperations;

impl AclOperations {
    /// Update ACL rules for a policy version (atomic replacement)
    pub async fn update_policy(
        conn: &DatabaseConnection,
        policy_version: u32,
        rules: Vec<AclRule>,
    ) -> Result<()> {
        // Execute in transaction for atomicity
        conn.execute_transaction(|| {
            Box::pin(async move {
                // Delete existing rules for this policy version
                conn.execute(
                    "DELETE FROM acl_rules WHERE policy_version = ?1",
                    &[policy_version.into()]
                ).await?;

                // Insert new rules
                for (index, rule) in rules.into_iter().enumerate() {
                    let source_json = serde_json::to_string(&rule.source_spec)
                        .map_err(|e| GhostWireError::database(format!("Failed to serialize source spec: {}", e)))?;
                    let dest_json = serde_json::to_string(&rule.dest_spec)
                        .map_err(|e| GhostWireError::database(format!("Failed to serialize dest spec: {}", e)))?;

                    let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)
                        .unwrap_or_default().as_secs() as i64;

                    conn.execute(
                        r#"
                        INSERT INTO acl_rules (policy_version, rule_index, action, source_spec, dest_spec, created_at)
                        VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                        "#,
                        &[
                            policy_version.into(),
                            (index as i64).into(),
                            rule.action.to_string().into(),
                            source_json.into(),
                            dest_json.into(),
                            now.into(),
                        ]
                    ).await?;
                }

                debug!("Updated ACL policy version {} with {} rules", policy_version, rules.len());
                Ok(())
            })
        }).await
    }

    /// Get ACL rules for policy evaluation (leverages bitmap indexes)
    pub async fn get_policy_rules(
        conn: &DatabaseConnection,
        policy_version: u32,
    ) -> Result<Vec<AclRule>> {
        let db_rules = conn.execute_acl_query(
            r#"
            SELECT id, policy_version, rule_index, action, source_spec, dest_spec, created_at
            FROM acl_rules
            WHERE policy_version = ?1
            ORDER BY rule_index
            "#,
            &[policy_version.into()],
            |row| {
                Ok(DbAclRule {
                    id: row.get::<i64>("id")?,
                    policy_version: row.get::<u32>("policy_version")?,
                    rule_index: row.get::<i64>("rule_index")?,
                    action: row.get::<String>("action")?,
                    source_spec: row.get::<String>("source_spec")?,
                    dest_spec: row.get::<String>("dest_spec")?,
                    created_at: row.get::<i64>("created_at")?,
                })
            }
        ).await?;

        db_rules.into_iter()
            .map(AclRule::try_from)
            .collect()
    }

    /// Get latest policy version
    pub async fn get_latest_policy_version(conn: &DatabaseConnection) -> Result<Option<u32>> {
        let version = conn.query_scalar::<Option<u32>>(
            "SELECT MAX(policy_version) FROM acl_rules"
        ).await.unwrap_or(None);

        Ok(version)
    }
}

/// DNS record operations for MagicDNS
pub struct DnsOperations;

impl DnsOperations {
    /// Create or update DNS record
    pub async fn upsert_record(
        conn: &DatabaseConnection,
        name: &str,
        record_type: &str,
        value: &str,
        ttl: Option<u32>,
    ) -> Result<DnsRecord> {
        let record_id = uuid::Uuid::new_v4();
        let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default().as_secs() as i64;

        let rows_affected = conn.execute(
            r#"
            INSERT INTO dns_records (id, name, record_type, value, ttl, created_at, updated_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            ON CONFLICT(name, record_type) DO UPDATE SET
                value = excluded.value,
                ttl = excluded.ttl,
                updated_at = excluded.updated_at
            "#,
            &[
                record_id.to_string().into(),
                name.into(),
                record_type.into(),
                value.into(),
                ttl.unwrap_or(300).into(),
                now.into(),
                now.into(),
            ]
        ).await?;

        debug!("Upserted DNS record: {} {} {}", name, record_type, value);

        Ok(DnsRecord {
            id: record_id,
            name: name.to_string(),
            record_type: record_type.to_string(),
            value: value.to_string(),
            ttl: ttl.unwrap_or(300),
            created_at: SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(now as u64),
            updated_at: SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(now as u64),
        })
    }

    /// Query DNS records by name and type
    pub async fn query_records(
        conn: &DatabaseConnection,
        name: &str,
        record_type: Option<&str>,
    ) -> Result<Vec<DnsRecord>> {
        let (sql, params): (String, Vec<zqlite::Value>) = if let Some(rtype) = record_type {
            (
                "SELECT id, name, record_type, value, ttl, created_at, updated_at FROM dns_records WHERE name = ?1 AND record_type = ?2".to_string(),
                vec![name.into(), rtype.into()]
            )
        } else {
            (
                "SELECT id, name, record_type, value, ttl, created_at, updated_at FROM dns_records WHERE name = ?1".to_string(),
                vec![name.into()]
            )
        };

        let db_records = conn.query_rows(
            &sql,
            &params,
            |row| {
                Ok(DbDnsRecord {
                    id: row.get::<String>("id")?,
                    name: row.get::<String>("name")?,
                    record_type: row.get::<String>("record_type")?,
                    value: row.get::<String>("value")?,
                    ttl: row.get::<u32>("ttl")?,
                    created_at: row.get::<i64>("created_at")?,
                    updated_at: row.get::<i64>("updated_at")?,
                })
            }
        ).await?;

        db_records.into_iter()
            .map(DnsRecord::try_from)
            .collect()
    }

    /// Delete DNS record
    pub async fn delete_record(
        conn: &DatabaseConnection,
        name: &str,
        record_type: &str,
    ) -> Result<()> {
        let rows_affected = conn.execute(
            "DELETE FROM dns_records WHERE name = ?1 AND record_type = ?2",
            &[name.into(), record_type.into()]
        ).await?;

        if rows_affected == 0 {
            return Err(GhostWireError::database("DNS record not found"));
        }

        debug!("Deleted DNS record: {} {}", name, record_type);
        Ok(())
    }

    /// List all DNS records
    pub async fn list_all(conn: &DatabaseConnection) -> Result<Vec<DnsRecord>> {
        let db_records = conn.query_rows(
            "SELECT id, name, record_type, value, ttl, created_at, updated_at FROM dns_records ORDER BY name, record_type",
            &[],
            |row| {
                Ok(DbDnsRecord {
                    id: row.get::<String>("id")?,
                    name: row.get::<String>("name")?,
                    record_type: row.get::<String>("record_type")?,
                    value: row.get::<String>("value")?,
                    ttl: row.get::<u32>("ttl")?,
                    created_at: row.get::<i64>("created_at")?,
                    updated_at: row.get::<i64>("updated_at")?,
                })
            }
        ).await?;

        db_records.into_iter()
            .map(DnsRecord::try_from)
            .collect()
    }
}

/// Metrics operations with time-series optimization
pub struct MetricsOperations;

impl MetricsOperations {
    /// Record node metrics (optimized for high-frequency writes)
    pub async fn record_metrics(
        conn: &DatabaseConnection,
        node_id: &NodeId,
        metrics: &NodeMetrics,
    ) -> Result<()> {
        let timestamp = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default().as_secs() as i64;

        // Use time-series optimized insert
        conn.execute_timeseries_query(
            r#"
            INSERT INTO metrics (
                node_id, timestamp, rx_bytes, tx_bytes, rx_packets, tx_packets,
                latency_ms, packet_loss, bandwidth_bps
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
            ON CONFLICT(node_id, timestamp) DO UPDATE SET
                rx_bytes = excluded.rx_bytes,
                tx_bytes = excluded.tx_bytes,
                rx_packets = excluded.rx_packets,
                tx_packets = excluded.tx_packets,
                latency_ms = excluded.latency_ms,
                packet_loss = excluded.packet_loss,
                bandwidth_bps = excluded.bandwidth_bps
            "#,
            &[
                node_id.to_string().into(),
                timestamp.into(),
                (metrics.rx_bytes as i64).into(),
                (metrics.tx_bytes as i64).into(),
                (metrics.rx_packets as i64).into(),
                (metrics.tx_packets as i64).into(),
                metrics.latency_ms.map(|l| l.into()).unwrap_or("".into()),
                metrics.packet_loss.map(|p| p.into()).unwrap_or("".into()),
                metrics.bandwidth_bps.map(|b| (b as i64).into()).unwrap_or("".into()),
            ],
            |_| Ok(())
        ).await?;

        trace!("Recorded metrics for node: {}", node_id);
        Ok(())
    }

    /// Get metrics for node within time range
    pub async fn get_node_metrics(
        conn: &DatabaseConnection,
        node_id: &NodeId,
        start_time: SystemTime,
        end_time: SystemTime,
    ) -> Result<Vec<NodeMetrics>> {
        let start_timestamp = start_time.duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default().as_secs() as i64;
        let end_timestamp = end_time.duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default().as_secs() as i64;

        let db_metrics = conn.execute_timeseries_query(
            r#"
            SELECT node_id, timestamp, rx_bytes, tx_bytes, rx_packets, tx_packets,
                   latency_ms, packet_loss, bandwidth_bps
            FROM metrics
            WHERE node_id = ?1 AND timestamp BETWEEN ?2 AND ?3
            ORDER BY timestamp
            "#,
            &[node_id.to_string().into(), start_timestamp.into(), end_timestamp.into()],
            |row| {
                Ok(DbNodeMetrics {
                    node_id: row.get::<String>("node_id")?,
                    timestamp: row.get::<i64>("timestamp")?,
                    rx_bytes: row.get::<i64>("rx_bytes")?,
                    tx_bytes: row.get::<i64>("tx_bytes")?,
                    rx_packets: row.get::<i64>("rx_packets")?,
                    tx_packets: row.get::<i64>("tx_packets")?,
                    latency_ms: row.get::<Option<f64>>("latency_ms")?,
                    packet_loss: row.get::<Option<f64>>("packet_loss")?,
                    bandwidth_bps: row.get::<Option<i64>>("bandwidth_bps")?,
                })
            }
        ).await?;

        db_metrics.into_iter()
            .map(NodeMetrics::try_from)
            .collect()
    }

    /// Get aggregated metrics for all nodes
    pub async fn get_aggregate_metrics(
        conn: &DatabaseConnection,
        start_time: SystemTime,
        end_time: SystemTime,
    ) -> Result<AggregateMetrics> {
        let start_timestamp = start_time.duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default().as_secs() as i64;
        let end_timestamp = end_time.duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default().as_secs() as i64;

        let aggregate = conn.execute_timeseries_query(
            r#"
            SELECT
                SUM(rx_bytes) as total_rx_bytes,
                SUM(tx_bytes) as total_tx_bytes,
                SUM(rx_packets) as total_rx_packets,
                SUM(tx_packets) as total_tx_packets,
                AVG(latency_ms) as avg_latency_ms,
                AVG(packet_loss) as avg_packet_loss,
                AVG(bandwidth_bps) as avg_bandwidth_bps,
                COUNT(DISTINCT node_id) as active_nodes
            FROM metrics
            WHERE timestamp BETWEEN ?1 AND ?2
            "#,
            &[start_timestamp.into(), end_timestamp.into()],
            |row| {
                Ok(AggregateMetrics {
                    total_rx_bytes: row.get::<i64>("total_rx_bytes")? as u64,
                    total_tx_bytes: row.get::<i64>("total_tx_bytes")? as u64,
                    total_rx_packets: row.get::<i64>("total_rx_packets")? as u64,
                    total_tx_packets: row.get::<i64>("total_tx_packets")? as u64,
                    avg_latency_ms: row.get::<Option<f64>>("avg_latency_ms")?,
                    avg_packet_loss: row.get::<Option<f64>>("avg_packet_loss")?,
                    avg_bandwidth_bps: row.get::<Option<i64>>("avg_bandwidth_bps")?.map(|b| b as u64),
                    active_nodes: row.get::<i64>("active_nodes")? as u32,
                })
            }
        ).await?;

        Ok(aggregate.into_iter().next().unwrap_or_default())
    }
}

/// Audit log operations for security and compliance
pub struct AuditOperations;

impl AuditOperations {
    /// Record audit event
    pub async fn record_event(
        conn: &DatabaseConnection,
        user_id: Option<&UserId>,
        node_id: Option<&NodeId>,
        action: &str,
        resource_type: &str,
        resource_id: Option<&str>,
        details: Option<serde_json::Value>,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
        result: &str,
    ) -> Result<()> {
        let event_id = uuid::Uuid::new_v4();
        let timestamp = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default().as_secs() as i64;

        let details_json = details.map(|d| {
            serde_json::to_string(&d)
                .map_err(|e| GhostWireError::database(format!("Failed to serialize details: {}", e)))
        }).transpose()?;

        conn.execute(
            r#"
            INSERT INTO audit_log (
                id, timestamp, user_id, node_id, action, resource_type, resource_id,
                details, ip_address, user_agent, result
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
            "#,
            &[
                event_id.to_string().into(),
                timestamp.into(),
                user_id.map(|u| u.to_string().into()).unwrap_or("".into()),
                node_id.map(|n| n.to_string().into()).unwrap_or("".into()),
                action.into(),
                resource_type.into(),
                resource_id.map(|r| r.into()).unwrap_or("".into()),
                details_json.map(|d| d.into()).unwrap_or("".into()),
                ip_address.map(|ip| ip.into()).unwrap_or("".into()),
                user_agent.map(|ua| ua.into()).unwrap_or("".into()),
                result.into(),
            ]
        ).await?;

        trace!("Recorded audit event: {} {} {}", action, resource_type, result);
        Ok(())
    }

    /// Query audit log with filters
    pub async fn query_events(
        conn: &DatabaseConnection,
        user_id: Option<&UserId>,
        action: Option<&str>,
        resource_type: Option<&str>,
        result: Option<&str>,
        start_time: Option<SystemTime>,
        end_time: Option<SystemTime>,
        limit: Option<u32>,
    ) -> Result<Vec<AuditEvent>> {
        let mut sql = "SELECT id, timestamp, user_id, node_id, action, resource_type, resource_id, details, ip_address, user_agent, result FROM audit_log WHERE 1=1".to_string();
        let mut params = Vec::new();

        if let Some(uid) = user_id {
            sql.push_str(" AND user_id = ?");
            params.push(uid.to_string().into());
        }

        if let Some(act) = action {
            sql.push_str(" AND action = ?");
            params.push(act.into());
        }

        if let Some(rtype) = resource_type {
            sql.push_str(" AND resource_type = ?");
            params.push(rtype.into());
        }

        if let Some(res) = result {
            sql.push_str(" AND result = ?");
            params.push(res.into());
        }

        if let Some(start) = start_time {
            let start_timestamp = start.duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default().as_secs() as i64;
            sql.push_str(" AND timestamp >= ?");
            params.push(start_timestamp.into());
        }

        if let Some(end) = end_time {
            let end_timestamp = end.duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default().as_secs() as i64;
            sql.push_str(" AND timestamp <= ?");
            params.push(end_timestamp.into());
        }

        sql.push_str(" ORDER BY timestamp DESC");

        if let Some(limit_val) = limit {
            sql.push_str(&format!(" LIMIT {}", limit_val));
        }

        let db_events = conn.query_rows(
            &sql,
            &params,
            |row| {
                Ok(DbAuditEvent {
                    id: row.get::<String>("id")?,
                    timestamp: row.get::<i64>("timestamp")?,
                    user_id: row.get::<Option<String>>("user_id")?,
                    node_id: row.get::<Option<String>>("node_id")?,
                    action: row.get::<String>("action")?,
                    resource_type: row.get::<String>("resource_type")?,
                    resource_id: row.get::<Option<String>>("resource_id")?,
                    details: row.get::<Option<String>>("details")?,
                    ip_address: row.get::<Option<String>>("ip_address")?,
                    user_agent: row.get::<Option<String>>("user_agent")?,
                    result: row.get::<String>("result")?,
                })
            }
        ).await?;

        db_events.into_iter()
            .map(AuditEvent::try_from)
            .collect()
    }
}

/// Additional operations for database management
impl UserOperations {
    /// Count total users
    pub async fn count(conn: &DatabaseConnection) -> Result<u64> {
        conn.query_scalar::<Option<u64>>(
            "SELECT COUNT(*) FROM users"
        ).await.map(|opt| opt.unwrap_or(0))
    }

    /// Update user last seen timestamp
    pub async fn update_last_seen(
        conn: &DatabaseConnection,
        user_id: &UserId,
    ) -> Result<()> {
        let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default().as_secs() as i64;

        conn.execute(
            "UPDATE users SET last_seen = ?1 WHERE id = ?2",
            &[now.into(), user_id.to_string().into()]
        ).await?;

        Ok(())
    }
}

impl NodeOperations {
    /// Count total nodes
    pub async fn count(conn: &DatabaseConnection) -> Result<u64> {
        conn.query_scalar::<Option<u64>>(
            "SELECT COUNT(*) FROM nodes"
        ).await.map(|opt| opt.unwrap_or(0))
    }

    /// List active (non-expired) nodes
    pub async fn list_active(conn: &DatabaseConnection) -> Result<Vec<Node>> {
        let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default().as_secs() as i64;

        let db_nodes = conn.query_rows(
            r#"
            SELECT id, user_id, name, public_key, ipv4, ipv6, endpoints, allowed_ips, tags,
                   created_at, last_seen, expires_at, online
            FROM nodes
            WHERE expires_at IS NULL OR expires_at > ?1
            ORDER BY last_seen DESC
            "#,
            &[now.into()],
            |row| {
                Ok(DbNode {
                    id: row.get::<String>("id")?,
                    user_id: row.get::<String>("user_id")?,
                    name: row.get::<String>("name")?,
                    public_key: row.get::<Vec<u8>>("public_key")?,
                    ipv4: row.get::<String>("ipv4")?,
                    ipv6: row.get::<Option<String>>("ipv6")?,
                    endpoints: row.get::<Option<String>>("endpoints")?,
                    allowed_ips: row.get::<Option<String>>("allowed_ips")?,
                    tags: row.get::<Option<String>>("tags")?,
                    created_at: row.get::<i64>("created_at")?,
                    last_seen: row.get::<i64>("last_seen")?,
                    expires_at: row.get::<Option<i64>>("expires_at")?,
                    online: row.get::<bool>("online")?,
                })
            }
        ).await?;

        db_nodes.into_iter().map(Node::try_from).collect()
    }

    /// Update node user (move to different user)
    pub async fn update_user(
        conn: &DatabaseConnection,
        node_id: &NodeId,
        new_user_id: &UserId,
    ) -> Result<()> {
        let rows_affected = conn.execute(
            "UPDATE nodes SET user_id = ?1 WHERE id = ?2",
            &[new_user_id.to_string().into(), node_id.to_string().into()]
        ).await?;

        if rows_affected == 0 {
            return Err(GhostWireError::database("Node not found"));
        }

        debug!("Moved node {} to user {}", node_id, new_user_id);
        Ok(())
    }
}

impl RouteOperations {
    /// Count total routes
    pub async fn count(conn: &DatabaseConnection) -> Result<u64> {
        conn.query_scalar::<Option<u64>>(
            "SELECT COUNT(*) FROM routes"
        ).await.map(|opt| opt.unwrap_or(0))
    }
}