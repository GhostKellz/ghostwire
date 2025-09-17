/// Database migrations for schema evolution
///
/// This module handles incremental schema changes using zqlite's
/// advanced migration capabilities including:
/// - Atomic migration transactions
/// - Schema version tracking
/// - Rollback support
/// - Performance impact monitoring

use ghostwire_common::error::{Result, GhostWireError};
use std::collections::HashMap;

/// Latest migration version - update when adding new migrations
pub const LATEST_VERSION: u32 = 1;

/// Migration definition
#[derive(Debug, Clone)]
pub struct Migration {
    pub version: u32,
    pub description: String,
    pub up_sql: Vec<String>,
    pub down_sql: Vec<String>,
}

/// Get migration by version
pub fn get_migration(version: u32) -> Option<Migration> {
    let migrations = get_all_migrations();
    migrations.get(&version).cloned()
}

/// Get all migrations
pub fn get_all_migrations() -> HashMap<u32, Migration> {
    let mut migrations = HashMap::new();

    // Migration 1: Initial schema
    migrations.insert(1, Migration {
        version: 1,
        description: "Initial database schema with zqlite optimizations".to_string(),
        up_sql: vec![
            // Create schema migrations table first
            r#"
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY,
                description TEXT NOT NULL,
                applied_at INTEGER NOT NULL,
                execution_time_ms INTEGER NOT NULL
            )
            "#.to_string(),

            // Users table with compressed metadata
            r#"
            CREATE TABLE users (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                email TEXT,
                provider TEXT NOT NULL DEFAULT 'cli',
                provider_id TEXT,
                metadata TEXT COMPRESSED,
                created_at INTEGER NOT NULL,
                last_seen INTEGER NOT NULL,
                UNIQUE(provider, provider_id)
            )
            "#.to_string(),

            // Nodes table with endpoint compression and spatial indexing
            r#"
            CREATE TABLE nodes (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                name TEXT NOT NULL,
                public_key BLOB NOT NULL UNIQUE,
                ipv4 TEXT NOT NULL UNIQUE,
                ipv6 TEXT UNIQUE,
                endpoints TEXT COMPRESSED,
                allowed_ips TEXT COMPRESSED,
                tags TEXT COMPRESSED,
                created_at INTEGER NOT NULL,
                last_seen INTEGER NOT NULL,
                expires_at INTEGER,
                online BOOLEAN NOT NULL DEFAULT false
            )
            "#.to_string(),

            // Routes table with R-tree spatial indexing for CIDR operations
            r#"
            CREATE TABLE routes (
                id TEXT PRIMARY KEY,
                node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
                prefix TEXT NOT NULL,
                advertised BOOLEAN NOT NULL DEFAULT true,
                enabled BOOLEAN NOT NULL DEFAULT false,
                is_primary BOOLEAN NOT NULL DEFAULT false,
                created_at INTEGER NOT NULL
            )
            "#.to_string(),

            // API keys for programmatic access
            r#"
            CREATE TABLE api_keys (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                prefix TEXT NOT NULL UNIQUE,
                hash TEXT NOT NULL UNIQUE,
                description TEXT,
                created_at INTEGER NOT NULL,
                last_used INTEGER,
                expires_at INTEGER
            )
            "#.to_string(),

            // Pre-authentication keys for node registration
            r#"
            CREATE TABLE preauth_keys (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                key_hash TEXT NOT NULL UNIQUE,
                reusable BOOLEAN NOT NULL DEFAULT false,
                ephemeral BOOLEAN NOT NULL DEFAULT false,
                used BOOLEAN NOT NULL DEFAULT false,
                tags TEXT COMPRESSED,
                created_at INTEGER NOT NULL,
                expires_at INTEGER,
                used_at INTEGER
            )
            "#.to_string(),

            // ACL rules with bitmap indexing for fast evaluation
            r#"
            CREATE TABLE acl_rules (
                id INTEGER PRIMARY KEY,
                policy_version INTEGER NOT NULL,
                rule_index INTEGER NOT NULL,
                action TEXT NOT NULL CHECK(action IN ('accept', 'deny')),
                source_spec TEXT COMPRESSED,
                dest_spec TEXT COMPRESSED,
                created_at INTEGER NOT NULL,
                UNIQUE(policy_version, rule_index)
            )
            "#.to_string(),

            // DNS records for MagicDNS
            r#"
            CREATE TABLE dns_records (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                record_type TEXT NOT NULL CHECK(record_type IN ('A', 'AAAA', 'CNAME', 'MX', 'TXT')),
                value TEXT NOT NULL,
                ttl INTEGER DEFAULT 300,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                UNIQUE(name, record_type)
            )
            "#.to_string(),

            // Metrics table with time-series extension
            r#"
            CREATE TABLE metrics (
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
            ) WITH TIME_SERIES(interval='1m', retention='30d')
            "#.to_string(),

            // Audit log for security and compliance
            r#"
            CREATE TABLE audit_log (
                id TEXT PRIMARY KEY,
                timestamp INTEGER NOT NULL,
                user_id TEXT REFERENCES users(id),
                node_id TEXT REFERENCES nodes(id),
                action TEXT NOT NULL,
                resource_type TEXT NOT NULL,
                resource_id TEXT,
                details TEXT COMPRESSED,
                ip_address TEXT,
                user_agent TEXT,
                result TEXT NOT NULL CHECK(result IN ('success', 'failure', 'denied'))
            )
            "#.to_string(),

            // Performance-optimized indexes
            // User indexes
            "CREATE INDEX idx_users_name ON users(name)".to_string(),
            "CREATE INDEX idx_users_provider ON users(provider, provider_id)".to_string(),

            // Node indexes with bitmap optimization
            "CREATE INDEX idx_nodes_user_id ON nodes(user_id) USING BITMAP".to_string(),
            "CREATE INDEX idx_nodes_public_key ON nodes(public_key)".to_string(),
            "CREATE INDEX idx_nodes_last_seen ON nodes(last_seen)".to_string(),
            "CREATE INDEX idx_nodes_online ON nodes(online) USING BITMAP".to_string(),
            "CREATE INDEX idx_nodes_expires_at ON nodes(expires_at)".to_string(),
            "CREATE INDEX idx_nodes_user_online ON nodes(user_id, online)".to_string(),

            // Route indexes with R-tree spatial indexing for CIDR
            "CREATE INDEX idx_routes_prefix ON routes(prefix) USING RTREE".to_string(),
            "CREATE INDEX idx_routes_node_id ON routes(node_id)".to_string(),
            "CREATE INDEX idx_routes_enabled ON routes(enabled) USING BITMAP".to_string(),
            "CREATE INDEX idx_routes_node_enabled ON routes(node_id, enabled)".to_string(),

            // API key indexes
            "CREATE INDEX idx_api_keys_user_id ON api_keys(user_id)".to_string(),
            "CREATE INDEX idx_api_keys_prefix ON api_keys(prefix)".to_string(),
            "CREATE INDEX idx_api_keys_expires_at ON api_keys(expires_at)".to_string(),

            // Pre-auth key indexes
            "CREATE INDEX idx_preauth_keys_user_id ON preauth_keys(user_id)".to_string(),
            "CREATE INDEX idx_preauth_keys_used ON preauth_keys(used) USING BITMAP".to_string(),
            "CREATE INDEX idx_preauth_keys_expires_at ON preauth_keys(expires_at)".to_string(),

            // ACL rule indexes with bitmap optimization
            "CREATE INDEX idx_acl_rules_policy_version ON acl_rules(policy_version) USING BITMAP".to_string(),
            "CREATE INDEX idx_acl_rules_action ON acl_rules(action) USING BITMAP".to_string(),
            "CREATE INDEX idx_acl_rules_rule_index ON acl_rules(rule_index)".to_string(),

            // DNS record indexes
            "CREATE INDEX idx_dns_records_name ON dns_records(name)".to_string(),
            "CREATE INDEX idx_dns_records_type ON dns_records(record_type)".to_string(),

            // Metrics indexes (time-series optimized)
            "CREATE INDEX idx_metrics_timestamp ON metrics(timestamp)".to_string(),
            "CREATE INDEX idx_metrics_node_time ON metrics(node_id, timestamp)".to_string(),

            // Audit log indexes
            "CREATE INDEX idx_audit_log_timestamp ON audit_log(timestamp)".to_string(),
            "CREATE INDEX idx_audit_log_user_id ON audit_log(user_id)".to_string(),
            "CREATE INDEX idx_audit_log_action ON audit_log(action)".to_string(),
            "CREATE INDEX idx_audit_log_resource_type ON audit_log(resource_type)".to_string(),
            "CREATE INDEX idx_audit_log_result ON audit_log(result) USING BITMAP".to_string(),
            "CREATE INDEX idx_audit_user_time ON audit_log(user_id, timestamp)".to_string(),
        ],
        down_sql: vec![
            // Drop in reverse order to handle foreign key constraints
            "DROP TABLE IF EXISTS audit_log".to_string(),
            "DROP TABLE IF EXISTS metrics".to_string(),
            "DROP TABLE IF EXISTS dns_records".to_string(),
            "DROP TABLE IF EXISTS acl_rules".to_string(),
            "DROP TABLE IF EXISTS preauth_keys".to_string(),
            "DROP TABLE IF EXISTS api_keys".to_string(),
            "DROP TABLE IF EXISTS routes".to_string(),
            "DROP TABLE IF EXISTS nodes".to_string(),
            "DROP TABLE IF EXISTS users".to_string(),
            "DROP TABLE IF EXISTS schema_migrations".to_string(),
        ],
    });

    migrations
}

/// Run a single migration with performance monitoring
pub async fn run_migration(
    connection: &crate::database::connection::DatabaseConnection,
    migration: &Migration,
) -> Result<()> {
    let start_time = std::time::Instant::now();

    tracing::info!("Running migration {}: {}", migration.version, migration.description);

    // Execute all SQL statements in the migration
    for (i, sql) in migration.up_sql.iter().enumerate() {
        match connection.execute(sql, &[]).await {
            Ok(_) => {
                tracing::debug!("Migration {} step {} completed", migration.version, i + 1);
            }
            Err(e) => {
                tracing::error!("Migration {} step {} failed: {}", migration.version, i + 1, e);
                return Err(GhostWireError::database(
                    format!("Migration {} failed at step {}: {}", migration.version, i + 1, e)
                ));
            }
        }
    }

    let execution_time = start_time.elapsed();
    tracing::info!("Migration {} completed in {:?}", migration.version, execution_time);

    // Record migration in schema_migrations table
    connection.execute(
        r#"
        INSERT INTO schema_migrations (version, description, applied_at, execution_time_ms)
        VALUES (?1, ?2, ?3, ?4)
        "#,
        &[
            migration.version.into(),
            migration.description.clone().into(),
            chrono::Utc::now().timestamp().into(),
            execution_time.as_millis().into(),
        ]
    ).await?;

    Ok(())
}

/// Rollback a migration (if supported)
pub async fn rollback_migration(
    connection: &crate::database::connection::DatabaseConnection,
    migration: &Migration,
) -> Result<()> {
    let start_time = std::time::Instant::now();

    tracing::warn!("Rolling back migration {}: {}", migration.version, migration.description);

    // Execute rollback SQL statements
    for (i, sql) in migration.down_sql.iter().enumerate() {
        match connection.execute(sql, &[]).await {
            Ok(_) => {
                tracing::debug!("Migration {} rollback step {} completed", migration.version, i + 1);
            }
            Err(e) => {
                tracing::error!("Migration {} rollback step {} failed: {}", migration.version, i + 1, e);
                return Err(GhostWireError::database(
                    format!("Migration {} rollback failed at step {}: {}", migration.version, i + 1, e)
                ));
            }
        }
    }

    let execution_time = start_time.elapsed();
    tracing::info!("Migration {} rollback completed in {:?}", migration.version, execution_time);

    // Remove migration record
    connection.execute(
        "DELETE FROM schema_migrations WHERE version = ?1",
        &[migration.version.into()]
    ).await?;

    Ok(())
}

/// Get migration history
pub async fn get_migration_history(
    connection: &crate::database::connection::DatabaseConnection,
) -> Result<Vec<MigrationRecord>> {
    let records = connection.query_rows(
        r#"
        SELECT version, description, applied_at, execution_time_ms
        FROM schema_migrations
        ORDER BY version
        "#,
        &[],
        |row| {
            Ok(MigrationRecord {
                version: row.get::<u32>("version")?,
                description: row.get::<String>("description")?,
                applied_at: row.get::<i64>("applied_at")?,
                execution_time_ms: row.get::<u64>("execution_time_ms")?,
            })
        }
    ).await?;

    Ok(records)
}

/// Migration execution record
#[derive(Debug, Clone)]
pub struct MigrationRecord {
    pub version: u32,
    pub description: String,
    pub applied_at: i64,
    pub execution_time_ms: u64,
}

/// Validate database schema integrity
pub async fn validate_schema(
    connection: &crate::database::connection::DatabaseConnection,
) -> Result<SchemaValidation> {
    let mut validation = SchemaValidation {
        valid: true,
        errors: Vec::new(),
        warnings: Vec::new(),
    };

    // Check required tables exist
    let required_tables = vec![
        "users", "nodes", "routes", "api_keys", "preauth_keys",
        "acl_rules", "dns_records", "metrics", "audit_log"
    ];

    for table in required_tables {
        let exists = connection.query_scalar::<u64>(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1"
        ).await.unwrap_or(0) > 0;

        if !exists {
            validation.valid = false;
            validation.errors.push(format!("Required table '{}' is missing", table));
        }
    }

    // Check foreign key constraints
    let fk_violations = connection.query_scalar::<u64>(
        "PRAGMA foreign_key_check"
    ).await.unwrap_or(0);

    if fk_violations > 0 {
        validation.valid = false;
        validation.errors.push(format!("Foreign key violations detected: {}", fk_violations));
    }

    // Check for orphaned records
    let orphaned_nodes = connection.query_scalar::<u64>(
        "SELECT COUNT(*) FROM nodes WHERE user_id NOT IN (SELECT id FROM users)"
    ).await.unwrap_or(0);

    if orphaned_nodes > 0 {
        validation.warnings.push(format!("Orphaned nodes detected: {}", orphaned_nodes));
    }

    // Validate compression ratios (zqlite-specific)
    let tables_with_compression = vec!["nodes", "users", "acl_rules", "audit_log"];
    for table in tables_with_compression {
        let compression_ratio = connection.query_scalar::<f64>(
            &format!("SELECT compression_ratio FROM pragma_table_info('{}')", table)
        ).await.unwrap_or(1.0);

        if compression_ratio > 0.9 {
            validation.warnings.push(
                format!("Table '{}' has low compression ratio: {:.2}", table, compression_ratio)
            );
        }
    }

    Ok(validation)
}

/// Schema validation result
#[derive(Debug)]
pub struct SchemaValidation {
    pub valid: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

/// Get pending migrations
pub async fn get_pending_migrations(
    connection: &crate::database::connection::DatabaseConnection,
) -> Result<Vec<u32>> {
    let current_version = connection.query_scalar::<u32>(
        "SELECT COALESCE(MAX(version), 0) FROM schema_migrations"
    ).await.unwrap_or(0);

    let pending: Vec<u32> = ((current_version + 1)..=LATEST_VERSION).collect();
    Ok(pending)
}

/// Check if migrations are needed
pub async fn migrations_needed(
    connection: &crate::database::connection::DatabaseConnection,
) -> Result<bool> {
    let pending = get_pending_migrations(connection).await?;
    Ok(!pending.is_empty())
}