/// Database schema definitions optimized for zqlite
///
/// This module defines the core database schema with advanced zqlite features:
/// - Compressed JSON fields for metadata
/// - Bitmap indexes for ACL rules
/// - R-tree spatial indexes for CIDR operations
/// - Time-series tables for metrics
/// - Change data capture for real-time updates

use ghostwire_common::error::Result;

/// Core schema version - increment when adding migrations
pub const CURRENT_SCHEMA_VERSION: u32 = 1;

/// Create all tables with zqlite optimizations
pub async fn create_schema(connection: &crate::database::connection::DatabaseConnection) -> Result<()> {
    // Create tables in dependency order
    create_users_table(connection).await?;
    create_nodes_table(connection).await?;
    create_routes_table(connection).await?;
    create_api_keys_table(connection).await?;
    create_preauth_keys_table(connection).await?;
    create_acl_rules_table(connection).await?;
    create_dns_records_table(connection).await?;
    create_metrics_table(connection).await?;
    create_audit_log_table(connection).await?;

    // Create indexes for performance
    create_indexes(connection).await?;

    Ok(())
}

/// Users table - stores user accounts and authentication info
async fn create_users_table(connection: &crate::database::connection::DatabaseConnection) -> Result<()> {
    let sql = r#"
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            email TEXT,
            provider TEXT NOT NULL DEFAULT 'cli',
            provider_id TEXT,
            metadata TEXT COMPRESSED,  -- zqlite compression for profile data
            created_at INTEGER NOT NULL,
            last_seen INTEGER NOT NULL,

            -- Ensure unique provider combinations
            UNIQUE(provider, provider_id)
        )
    "#;

    connection.execute(sql, &[]).await?;
    Ok(())
}

/// Nodes table - stores WireGuard peer information with endpoint data
async fn create_nodes_table(connection: &crate::database::connection::DatabaseConnection) -> Result<()> {
    let sql = r#"
        CREATE TABLE IF NOT EXISTS nodes (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            public_key BLOB NOT NULL UNIQUE,
            ipv4 TEXT NOT NULL UNIQUE,
            ipv6 TEXT UNIQUE,
            endpoints TEXT COMPRESSED,  -- zqlite compression for endpoint list
            allowed_ips TEXT COMPRESSED,  -- Compressed JSON array of CIDR blocks
            tags TEXT COMPRESSED,  -- Compressed JSON array of tags
            created_at INTEGER NOT NULL,
            last_seen INTEGER NOT NULL,
            expires_at INTEGER,  -- NULL = never expires
            online BOOLEAN NOT NULL DEFAULT false,

            -- Performance indexes
            INDEX idx_nodes_user_id(user_id),
            INDEX idx_nodes_public_key(public_key),
            INDEX idx_nodes_last_seen(last_seen),
            INDEX idx_nodes_online(online),
            INDEX idx_nodes_expires_at(expires_at)
        )
    "#;

    connection.execute(sql, &[]).await?;
    Ok(())
}

/// Routes table - stores advertised subnet routes with spatial indexing
async fn create_routes_table(connection: &crate::database::connection::DatabaseConnection) -> Result<()> {
    let sql = r#"
        CREATE TABLE IF NOT EXISTS routes (
            id TEXT PRIMARY KEY,
            node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
            prefix TEXT NOT NULL,  -- CIDR notation (e.g., "10.0.0.0/8")
            advertised BOOLEAN NOT NULL DEFAULT true,
            enabled BOOLEAN NOT NULL DEFAULT false,
            is_primary BOOLEAN NOT NULL DEFAULT false,
            created_at INTEGER NOT NULL,

            -- Spatial indexing for CIDR operations using zqlite R-tree
            INDEX idx_routes_prefix(prefix) USING RTREE,
            INDEX idx_routes_node_id(node_id),
            INDEX idx_routes_enabled(enabled),

            -- Ensure unique primary routes per prefix
            UNIQUE(prefix, is_primary) WHERE is_primary = true
        )
    "#;

    connection.execute(sql, &[]).await?;
    Ok(())
}

/// API keys table - for programmatic access
async fn create_api_keys_table(connection: &crate::database::connection::DatabaseConnection) -> Result<()> {
    let sql = r#"
        CREATE TABLE IF NOT EXISTS api_keys (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            prefix TEXT NOT NULL UNIQUE,  -- First 8 chars for identification
            hash TEXT NOT NULL UNIQUE,    -- Secure hash of full key
            description TEXT,
            created_at INTEGER NOT NULL,
            last_used INTEGER,
            expires_at INTEGER,

            INDEX idx_api_keys_user_id(user_id),
            INDEX idx_api_keys_prefix(prefix),
            INDEX idx_api_keys_expires_at(expires_at)
        )
    "#;

    connection.execute(sql, &[]).await?;
    Ok(())
}

/// Pre-authentication keys table - for node registration
async fn create_preauth_keys_table(connection: &crate::database::connection::DatabaseConnection) -> Result<()> {
    let sql = r#"
        CREATE TABLE IF NOT EXISTS preauth_keys (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            key_hash TEXT NOT NULL UNIQUE,  -- Secure hash of the key
            reusable BOOLEAN NOT NULL DEFAULT false,
            ephemeral BOOLEAN NOT NULL DEFAULT false,
            used BOOLEAN NOT NULL DEFAULT false,
            tags TEXT COMPRESSED,  -- JSON array of tags to apply
            created_at INTEGER NOT NULL,
            expires_at INTEGER,
            used_at INTEGER,

            INDEX idx_preauth_keys_user_id(user_id),
            INDEX idx_preauth_keys_used(used),
            INDEX idx_preauth_keys_expires_at(expires_at)
        )
    "#;

    connection.execute(sql, &[]).await?;
    Ok(())
}

/// ACL rules table - optimized for fast policy evaluation with bitmap indexes
async fn create_acl_rules_table(connection: &crate::database::connection::DatabaseConnection) -> Result<()> {
    let sql = r#"
        CREATE TABLE IF NOT EXISTS acl_rules (
            id INTEGER PRIMARY KEY,
            policy_version INTEGER NOT NULL,
            rule_index INTEGER NOT NULL,  -- Order within policy
            action TEXT NOT NULL CHECK(action IN ('accept', 'deny')),
            source_spec TEXT COMPRESSED,  -- JSON array of source specifications
            dest_spec TEXT COMPRESSED,    -- JSON array of destination specifications
            created_at INTEGER NOT NULL,

            -- Bitmap indexing for fast ACL evaluation using zqlite
            INDEX idx_acl_rules_policy_version(policy_version) USING BITMAP,
            INDEX idx_acl_rules_action(action) USING BITMAP,
            INDEX idx_acl_rules_rule_index(rule_index),

            UNIQUE(policy_version, rule_index)
        )
    "#;

    connection.execute(sql, &[]).await?;
    Ok(())
}

/// DNS records table - for MagicDNS
async fn create_dns_records_table(connection: &crate::database::connection::DatabaseConnection) -> Result<()> {
    let sql = r#"
        CREATE TABLE IF NOT EXISTS dns_records (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            record_type TEXT NOT NULL CHECK(record_type IN ('A', 'AAAA', 'CNAME', 'MX', 'TXT')),
            value TEXT NOT NULL,
            ttl INTEGER DEFAULT 300,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,

            -- DNS lookups need to be fast
            INDEX idx_dns_records_name(name),
            INDEX idx_dns_records_type(record_type),

            UNIQUE(name, record_type)
        )
    "#;

    connection.execute(sql, &[]).await?;
    Ok(())
}

/// Metrics table - time-series data for monitoring with zqlite time-series extension
async fn create_metrics_table(connection: &crate::database::connection::DatabaseConnection) -> Result<()> {
    let sql = r#"
        CREATE TABLE IF NOT EXISTS metrics (
            node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
            timestamp INTEGER NOT NULL,
            rx_bytes INTEGER NOT NULL DEFAULT 0,
            tx_bytes INTEGER NOT NULL DEFAULT 0,
            rx_packets INTEGER NOT NULL DEFAULT 0,
            tx_packets INTEGER NOT NULL DEFAULT 0,
            latency_ms REAL,
            packet_loss REAL,
            bandwidth_bps INTEGER,

            PRIMARY KEY (node_id, timestamp)
        ) WITH TIME_SERIES(
            interval='1m',      -- 1-minute aggregation
            retention='30d'     -- Keep 30 days of data
        )
    "#;

    connection.execute(sql, &[]).await?;
    Ok(())
}

/// Audit log table - security and compliance logging
async fn create_audit_log_table(connection: &crate::database::connection::DatabaseConnection) -> Result<()> {
    let sql = r#"
        CREATE TABLE IF NOT EXISTS audit_log (
            id TEXT PRIMARY KEY,
            timestamp INTEGER NOT NULL,
            user_id TEXT REFERENCES users(id),
            node_id TEXT REFERENCES nodes(id),
            action TEXT NOT NULL,
            resource_type TEXT NOT NULL,
            resource_id TEXT,
            details TEXT COMPRESSED,  -- JSON details about the action
            ip_address TEXT,
            user_agent TEXT,
            result TEXT NOT NULL CHECK(result IN ('success', 'failure', 'denied')),

            -- Audit queries need good performance
            INDEX idx_audit_log_timestamp(timestamp),
            INDEX idx_audit_log_user_id(user_id),
            INDEX idx_audit_log_action(action),
            INDEX idx_audit_log_resource_type(resource_type),
            INDEX idx_audit_log_result(result)
        )
    "#;

    connection.execute(sql, &[]).await?;
    Ok(())
}

/// Create additional performance indexes
async fn create_indexes(connection: &crate::database::connection::DatabaseConnection) -> Result<()> {
    let indexes = vec![
        // Composite indexes for common queries
        "CREATE INDEX IF NOT EXISTS idx_nodes_user_online ON nodes(user_id, online)",
        "CREATE INDEX IF NOT EXISTS idx_nodes_user_expires ON nodes(user_id, expires_at)",

        // Route optimization indexes
        "CREATE INDEX IF NOT EXISTS idx_routes_node_enabled ON routes(node_id, enabled)",
        "CREATE INDEX IF NOT EXISTS idx_routes_enabled_primary ON routes(enabled, is_primary)",

        // ACL performance indexes
        "CREATE INDEX IF NOT EXISTS idx_acl_rules_version_index ON acl_rules(policy_version, rule_index)",

        // Metrics time-series indexes
        "CREATE INDEX IF NOT EXISTS idx_metrics_timestamp ON metrics(timestamp)",
        "CREATE INDEX IF NOT EXISTS idx_metrics_node_time ON metrics(node_id, timestamp)",

        // Audit log performance indexes
        "CREATE INDEX IF NOT EXISTS idx_audit_user_time ON audit_log(user_id, timestamp)",
        "CREATE INDEX IF NOT EXISTS idx_audit_action_time ON audit_log(action, timestamp)",
    ];

    for index_sql in indexes {
        connection.execute(index_sql, &[]).await?;
    }

    Ok(())
}

/// Drop all tables (for testing)
pub async fn drop_schema(connection: &crate::database::connection::DatabaseConnection) -> Result<()> {
    let tables = vec![
        "audit_log",
        "metrics",
        "dns_records",
        "acl_rules",
        "preauth_keys",
        "api_keys",
        "routes",
        "nodes",
        "users",
        "schema_migrations",
    ];

    for table in tables {
        let sql = format!("DROP TABLE IF EXISTS {}", table);
        connection.execute(&sql, &[]).await?;
    }

    Ok(())
}

/// Database schema information for migrations and debugging
#[derive(Debug)]
pub struct SchemaInfo {
    pub version: u32,
    pub tables: Vec<TableInfo>,
    pub indexes: Vec<IndexInfo>,
}

#[derive(Debug)]
pub struct TableInfo {
    pub name: String,
    pub row_count: u64,
    pub size_mb: f64,
    pub compression_ratio: f64,
}

#[derive(Debug)]
pub struct IndexInfo {
    pub name: String,
    pub table: String,
    pub index_type: String,  // "btree", "bitmap", "rtree", "timeseries"
    pub size_mb: f64,
    pub usage_count: u64,
}

/// Get comprehensive schema information
pub async fn get_schema_info(connection: &crate::database::connection::DatabaseConnection) -> Result<SchemaInfo> {
    // Get current schema version
    let version = connection.query_scalar::<u32>(
        "SELECT COALESCE(MAX(version), 0) FROM schema_migrations"
    ).await.unwrap_or(0);

    // Get table information using zqlite's enhanced PRAGMA statements
    let tables = get_table_info(connection).await?;
    let indexes = get_index_info(connection).await?;

    Ok(SchemaInfo {
        version,
        tables,
        indexes,
    })
}

async fn get_table_info(connection: &crate::database::connection::DatabaseConnection) -> Result<Vec<TableInfo>> {
    let table_names = vec![
        "users", "nodes", "routes", "api_keys", "preauth_keys",
        "acl_rules", "dns_records", "metrics", "audit_log"
    ];

    let mut tables = Vec::new();

    for table_name in table_names {
        // Get row count
        let row_count = connection.query_scalar::<u64>(
            &format!("SELECT COUNT(*) FROM {}", table_name)
        ).await.unwrap_or(0);

        // Get table size and compression info (zqlite-specific)
        let size_info = connection.query_row(
            "SELECT size_mb, compression_ratio FROM pragma_table_info(?1)",
            &[table_name.into()],
            |row| {
                Ok((
                    row.get::<f64>("size_mb")?,
                    row.get::<f64>("compression_ratio")?,
                ))
            }
        ).await.unwrap_or((0.0, 1.0));

        tables.push(TableInfo {
            name: table_name.to_string(),
            row_count,
            size_mb: size_info.0,
            compression_ratio: size_info.1,
        });
    }

    Ok(tables)
}

async fn get_index_info(connection: &crate::database::connection::DatabaseConnection) -> Result<Vec<IndexInfo>> {
    let indexes = connection.query_rows(
        r#"
        SELECT
            name,
            tbl_name as table_name,
            type as index_type,
            size_mb,
            usage_count
        FROM pragma_index_list()
        WHERE name NOT LIKE 'sqlite_%'
        "#,
        &[],
        |row| {
            Ok(IndexInfo {
                name: row.get::<String>("name")?,
                table: row.get::<String>("table_name")?,
                index_type: row.get::<String>("index_type")?,
                size_mb: row.get::<f64>("size_mb")?,
                usage_count: row.get::<u64>("usage_count")?,
            })
        }
    ).await.unwrap_or_default();

    Ok(indexes)
}