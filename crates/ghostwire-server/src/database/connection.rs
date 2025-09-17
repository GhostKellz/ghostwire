use ghostwire_common::{
    config::{DatabaseConfig, CompressionLevel},
    error::{Result, GhostWireError},
};
use sqlx::{
    sqlite::{SqliteConnectOptions, SqlitePool, SqlitePoolOptions, SqliteRow},
    Row, Execute, FromRow,
};
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{RwLock, Semaphore};
use tracing::{debug, trace, warn};

/// SQLite database connection with performance optimizations
///
/// This provides the core database interface with:
/// - Connection pooling via sqlx
/// - Write-ahead logging (WAL) mode
/// - Optimized pragmas for performance
/// - Prepared statement caching
/// - Transaction support
pub struct DatabaseConnection {
    pool: SqlitePool,
    config: DatabaseConfig,
    stats: Arc<RwLock<ConnectionStats>>,
}

#[derive(Debug, Default)]
struct ConnectionStats {
    total_queries: u64,
    successful_queries: u64,
    failed_queries: u64,
    avg_query_time_ns: u64,
    cache_hits: u64,
    cache_misses: u64,
    parallel_writes: u64,
}

impl DatabaseConnection {
    /// Create new SQLite connection with performance optimizations
    pub async fn new(config: &DatabaseConfig) -> Result<Self> {
        debug!("Opening SQLite database: {}", config.path.display());

        // Ensure database directory exists
        if let Some(parent) = config.path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| GhostWireError::database(format!("Failed to create database directory: {}", e)))?;
        }

        // Configure SQLite connection options
        let db_url = format!("sqlite://{}", config.path.display());

        // Parse cache size to pages (4KB per page by default)
        let cache_size = Self::parse_cache_size(&config.cache_size)?;
        let cache_pages = cache_size / 4096;

        // Configure connection pool
        let max_connections = if config.parallel_writes { 64 } else { 32 };

        let pool = SqlitePoolOptions::new()
            .max_connections(max_connections)
            .min_connections(2)
            .connect(&db_url)
            .await
            .map_err(|e| GhostWireError::database(format!("Failed to open database: {}", e)))?;

        // Configure SQLite for maximum performance
        let pragmas = vec![
            format!("PRAGMA cache_size = -{}", cache_pages), // Negative for KB
            "PRAGMA journal_mode = WAL".to_string(),
            "PRAGMA synchronous = NORMAL".to_string(),
            "PRAGMA temp_store = MEMORY".to_string(),
            "PRAGMA mmap_size = 30000000000".to_string(), // 30GB mmap
            "PRAGMA foreign_keys = ON".to_string(),
            "PRAGMA busy_timeout = 5000".to_string(),
            "PRAGMA wal_autocheckpoint = 1000".to_string(),
        ];

        // Apply pragmas
        for pragma in pragmas {
            sqlx::query(&pragma)
                .execute(&pool)
                .await
                .map_err(|e| GhostWireError::database(format!("Failed to set pragma '{}': {}", pragma, e)))?;
            debug!("Applied: {}", pragma);
        }

        debug!("SQLite database opened successfully with {} max connections", max_connections);

        Ok(Self {
            pool,
            config: config.clone(),
            stats: Arc::new(RwLock::new(ConnectionStats::default())),
        })
    }

    /// Execute a query with performance tracking
    pub async fn execute(&self, sql: &str, params: &[sqlx::any::AnyValue]) -> Result<u64> {
        let start_time = Instant::now();

        let mut query = sqlx::query(sql);
        for param in params {
            query = query.bind(param);
        }

        let result = query
            .execute(&self.pool)
            .await
            .map(|r| r.rows_affected())
            .map_err(|e| GhostWireError::database(format!("Query execution failed: {}", e)));

        let query_time = start_time.elapsed();
        self.update_stats(query_time, result.is_ok()).await;

        trace!("Query executed in {:?}: {}", query_time, sql);

        result
    }

    /// Execute a query that returns a single scalar value
    pub async fn query_scalar<T>(&self, sql: &str) -> Result<Option<T>>
    where
        T: for<'r> sqlx::decode::Decode<'r, sqlx::Sqlite> + sqlx::Type<sqlx::Sqlite>,
    {
        let start_time = Instant::now();

        let result: Result<Option<(T,)>> = sqlx::query_as(sql)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| GhostWireError::database(format!("Scalar query failed: {}", e)));

        let query_time = start_time.elapsed();
        self.update_stats(query_time, result.is_ok()).await;

        result.map(|opt| opt.map(|(val,)| val))
    }

    /// Execute a query that returns multiple rows
    pub async fn query_rows<T, F>(&self, sql: &str, params: &[sqlx::any::AnyValue], row_mapper: F) -> Result<Vec<T>>
    where
        F: Fn(&SqliteRow) -> Result<T> + Send,
    {
        let start_time = Instant::now();

        let mut query = sqlx::query(sql);
        for param in params {
            query = query.bind(param);
        }

        let rows = query
            .fetch_all(&self.pool)
            .await
            .map_err(|e| GhostWireError::database(format!("Multi-row query failed: {}", e)))?;

        let mut results = Vec::new();
        for row in rows {
            results.push(row_mapper(&row)?);
        }

        let query_time = start_time.elapsed();
        self.update_stats(query_time, true).await;

        Ok(results)
    }

    /// Execute a query that returns a single row
    pub async fn query_row<T, F>(&self, sql: &str, params: &[sqlx::any::AnyValue], row_mapper: F) -> Result<T>
    where
        F: Fn(&SqliteRow) -> Result<T> + Send,
    {
        let start_time = Instant::now();

        let mut query = sqlx::query(sql);
        for param in params {
            query = query.bind(param);
        }

        let row = query
            .fetch_one(&self.pool)
            .await
            .map_err(|e| GhostWireError::database(format!("Single-row query failed: {}", e)))?;

        let result = row_mapper(&row)?;

        let query_time = start_time.elapsed();
        self.update_stats(query_time, true).await;

        Ok(result)
    }

    /// Execute multiple queries in a transaction
    pub async fn execute_transaction<F, R>(&self, transaction_fn: F) -> Result<R>
    where
        F: for<'a> FnOnce(&'a mut sqlx::Transaction<'_, sqlx::Sqlite>) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<R>> + Send + 'a>> + Send,
        R: Send,
    {
        let start_time = Instant::now();

        let mut tx = self.pool.begin().await
            .map_err(|e| GhostWireError::database(format!("Failed to begin transaction: {}", e)))?;

        let result = transaction_fn(&mut tx).await;

        match result {
            Ok(value) => {
                tx.commit().await
                    .map_err(|e| GhostWireError::database(format!("Failed to commit transaction: {}", e)))?;

                let query_time = start_time.elapsed();
                self.update_stats(query_time, true).await;

                if self.config.parallel_writes {
                    let mut stats = self.stats.write().await;
                    stats.parallel_writes += 1;
                }

                Ok(value)
            }
            Err(e) => {
                // Transaction automatically rolls back on drop
                let query_time = start_time.elapsed();
                self.update_stats(query_time, false).await;
                Err(e)
            }
        }
    }

    /// Execute spatial query (SQLite R-tree if available)
    pub async fn execute_spatial_query<T, F>(
        &self,
        sql: &str,
        params: &[sqlx::any::AnyValue],
        row_mapper: F,
    ) -> Result<Vec<T>>
    where
        F: Fn(&SqliteRow) -> Result<T> + Send,
    {
        // SQLite supports R-tree indexes with the rtree module
        trace!("Executing spatial query");
        self.query_rows(sql, params, row_mapper).await
    }

    /// Execute ACL query with optimized indexes
    pub async fn execute_acl_query<T, F>(
        &self,
        sql: &str,
        params: &[sqlx::any::AnyValue],
        row_mapper: F,
    ) -> Result<Vec<T>>
    where
        F: Fn(&SqliteRow) -> Result<T> + Send,
    {
        // Use standard SQLite indexes for ACL queries
        trace!("Executing ACL query");
        self.query_rows(sql, params, row_mapper).await
    }

    /// Execute time-series query for metrics
    pub async fn execute_timeseries_query<T, F>(
        &self,
        sql: &str,
        params: &[sqlx::any::AnyValue],
        row_mapper: F,
    ) -> Result<Vec<T>>
    where
        F: Fn(&SqliteRow) -> Result<T> + Send,
    {
        // Standard SQLite with appropriate indexes for time-series data
        trace!("Executing time-series query");
        self.query_rows(sql, params, row_mapper).await
    }

    /// Backup database to file
    pub async fn backup_to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let backup_sql = format!("VACUUM INTO '{}'", path.as_ref().display());
        sqlx::query(&backup_sql)
            .execute(&self.pool)
            .await
            .map_err(|e| GhostWireError::database(format!("Backup failed: {}", e)))?;
        Ok(())
    }

    /// Restore database from file
    pub async fn restore_from_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        // For SQLite, restoration typically involves copying the file
        // This is a simplified version - in production you'd want proper locking
        std::fs::copy(path.as_ref(), &self.config.path)
            .map_err(|e| GhostWireError::database(format!("Restore failed: {}", e)))?;
        Ok(())
    }

    /// Get database connection statistics
    pub async fn get_stats(&self) -> ConnectionStats {
        self.stats.read().await.clone()
    }

    /// Get database pool for direct access when needed
    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    /// Parse cache size string (e.g., "256MB" -> bytes)
    fn parse_cache_size(size_str: &str) -> Result<usize> {
        let size_str = size_str.to_uppercase();

        if let Some(size) = size_str.strip_suffix("GB") {
            let gb: f64 = size.parse()
                .map_err(|_| GhostWireError::config("Invalid cache size format"))?;
            Ok((gb * 1024.0 * 1024.0 * 1024.0) as usize)
        } else if let Some(size) = size_str.strip_suffix("MB") {
            let mb: f64 = size.parse()
                .map_err(|_| GhostWireError::config("Invalid cache size format"))?;
            Ok((mb * 1024.0 * 1024.0) as usize)
        } else if let Some(size) = size_str.strip_suffix("KB") {
            let kb: f64 = size.parse()
                .map_err(|_| GhostWireError::config("Invalid cache size format"))?;
            Ok((kb * 1024.0) as usize)
        } else {
            // Assume bytes
            size_str.parse()
                .map_err(|_| GhostWireError::config("Invalid cache size format"))
        }
    }

    /// Update connection statistics
    async fn update_stats(&self, query_time: std::time::Duration, success: bool) {
        let mut stats = self.stats.write().await;

        stats.total_queries += 1;

        if success {
            stats.successful_queries += 1;
        } else {
            stats.failed_queries += 1;
        }

        // Update average query time with exponential moving average
        let query_time_ns = query_time.as_nanos() as u64;
        if stats.avg_query_time_ns == 0 {
            stats.avg_query_time_ns = query_time_ns;
        } else {
            // EMA with alpha = 0.1
            stats.avg_query_time_ns = (stats.avg_query_time_ns * 9 + query_time_ns) / 10;
        }
    }

    /// Optimize database (VACUUM, ANALYZE, etc.)
    pub async fn optimize(&self) -> Result<()> {
        debug!("Optimizing database");

        // Run ANALYZE to update statistics
        sqlx::query("ANALYZE")
            .execute(&self.pool)
            .await
            .map_err(|e| GhostWireError::database(format!("ANALYZE failed: {}", e)))?;

        // Run VACUUM to reclaim space
        sqlx::query("VACUUM")
            .execute(&self.pool)
            .await
            .map_err(|e| GhostWireError::database(format!("VACUUM failed: {}", e)))?;

        debug!("Database optimization completed");
        Ok(())
    }

    /// Get query execution plan for debugging
    pub async fn explain_query(&self, sql: &str) -> Result<String> {
        let explain_sql = format!("EXPLAIN QUERY PLAN {}", sql);

        let rows = sqlx::query(&explain_sql)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| GhostWireError::database(format!("EXPLAIN failed: {}", e)))?;

        let mut plan = String::new();
        for row in rows {
            if let Ok(detail) = row.try_get::<String, _>("detail") {
                plan.push_str(&detail);
                plan.push('\n');
            }
        }

        Ok(plan)
    }
}