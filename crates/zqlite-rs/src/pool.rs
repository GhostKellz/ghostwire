use crate::{Connection, Error, Result};
use std::sync::Arc;
use std::time::{Duration, Instant};
use parking_lot::{Mutex, RwLock};
use crossbeam::queue::SegQueue;
use dashmap::DashMap;
use tokio::sync::Notify;
use tracing::{debug, info, warn, error};

#[derive(Debug, Clone)]
pub struct PoolConfig {
    pub min_connections: usize,
    pub max_connections: usize,
    pub connection_timeout: Duration,
    pub idle_timeout: Duration,
    pub max_lifetime: Duration,
    pub health_check_interval: Duration,
    pub database_path: String,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            min_connections: 5,
            max_connections: 50,
            connection_timeout: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(600), // 10 minutes
            max_lifetime: Duration::from_secs(1800), // 30 minutes
            health_check_interval: Duration::from_secs(60),
            database_path: ":memory:".to_string(),
        }
    }
}

pub struct Pool {
    config: PoolConfig,
    available: Arc<SegQueue<PooledConnection>>,
    active: Arc<DashMap<u64, ActiveConnection>>,
    stats: Arc<RwLock<PoolStats>>,
    notifier: Arc<Notify>,
    shutdown: Arc<Mutex<bool>>,
}

#[derive(Debug)]
struct PooledConnection {
    connection: Connection,
    created_at: Instant,
    last_used: Instant,
}

#[derive(Debug)]
struct ActiveConnection {
    connection: Connection,
    created_at: Instant,
    borrowed_at: Instant,
}

#[derive(Debug, Default, Clone)]
pub struct PoolStats {
    pub total_connections: usize,
    pub active_connections: usize,
    pub idle_connections: usize,
    pub connections_created: u64,
    pub connections_destroyed: u64,
    pub connections_borrowed: u64,
    pub connections_returned: u64,
    pub connection_errors: u64,
    pub pool_timeouts: u64,
}

impl Pool {
    pub async fn new(config: PoolConfig) -> Result<Self> {
        let pool = Self {
            available: Arc::new(SegQueue::new()),
            active: Arc::new(DashMap::new()),
            stats: Arc::new(RwLock::new(PoolStats::default())),
            notifier: Arc::new(Notify::new()),
            shutdown: Arc::new(Mutex::new(false)),
            config,
        };

        // Initialize minimum connections
        pool.ensure_min_connections().await?;

        // Start background maintenance task
        pool.start_maintenance_task();

        info!(
            min_connections = pool.config.min_connections,
            max_connections = pool.config.max_connections,
            "ZQLite connection pool initialized"
        );

        Ok(pool)
    }

    async fn ensure_min_connections(&self) -> Result<()> {
        let current_total = self.total_connections();
        let needed = self.config.min_connections.saturating_sub(current_total);

        for _ in 0..needed {
            let connection = self.create_connection().await?;
            self.available.push(PooledConnection {
                connection,
                created_at: Instant::now(),
                last_used: Instant::now(),
            });
        }

        Ok(())
    }

    async fn create_connection(&self) -> Result<Connection> {
        let connection = Connection::open(&self.config.database_path)?;

        // Perform health check
        connection.ping()?;

        let mut stats = self.stats.write();
        stats.connections_created += 1;
        stats.total_connections += 1;

        debug!(
            connection_id = connection.id(),
            total_connections = stats.total_connections,
            "Created new database connection"
        );

        Ok(connection)
    }

    pub async fn get(&self) -> Result<PooledConnectionGuard> {
        let timeout = tokio::time::sleep(self.config.connection_timeout);
        tokio::pin!(timeout);

        loop {
            // Try to get an available connection
            if let Some(pooled) = self.available.pop() {
                // Check if connection is still valid
                if self.is_connection_valid(&pooled) {
                    let connection_id = pooled.connection.id();
                    let active = ActiveConnection {
                        connection: pooled.connection,
                        created_at: pooled.created_at,
                        borrowed_at: Instant::now(),
                    };

                    self.active.insert(connection_id, active);

                    let mut stats = self.stats.write();
                    stats.connections_borrowed += 1;
                    stats.active_connections = self.active.len();
                    stats.idle_connections = self.available.len();

                    return Ok(PooledConnectionGuard {
                        pool: self.clone(),
                        connection: Some(self.active.get(&connection_id).unwrap().connection.clone()),
                        connection_id,
                    });
                } else {
                    // Connection is invalid, destroy it and continue
                    self.destroy_connection(pooled.connection).await;
                    continue;
                }
            }

            // No available connections, try to create one if under limit
            if self.total_connections() < self.config.max_connections {
                match self.create_connection().await {
                    Ok(connection) => {
                        let connection_id = connection.id();
                        let active = ActiveConnection {
                            connection: connection.clone(),
                            created_at: Instant::now(),
                            borrowed_at: Instant::now(),
                        };

                        self.active.insert(connection_id, active);

                        let mut stats = self.stats.write();
                        stats.connections_borrowed += 1;
                        stats.active_connections = self.active.len();

                        return Ok(PooledConnectionGuard {
                            pool: self.clone(),
                            connection: Some(connection),
                            connection_id,
                        });
                    }
                    Err(e) => {
                        let mut stats = self.stats.write();
                        stats.connection_errors += 1;
                        warn!(error = %e, "Failed to create new connection");
                    }
                }
            }

            // Wait for a connection to become available or timeout
            tokio::select! {
                _ = &mut timeout => {
                    let mut stats = self.stats.write();
                    stats.pool_timeouts += 1;
                    return Err(Error::Timeout(format!(
                        "Timeout waiting for connection after {:?}",
                        self.config.connection_timeout
                    )));
                }
                _ = self.notifier.notified() => {
                    // A connection was returned, try again
                    continue;
                }
            }
        }
    }

    fn is_connection_valid(&self, pooled: &PooledConnection) -> bool {
        let now = Instant::now();

        // Check if connection has exceeded max lifetime
        if now.duration_since(pooled.created_at) > self.config.max_lifetime {
            debug!(
                connection_id = pooled.connection.id(),
                age = ?now.duration_since(pooled.created_at),
                "Connection exceeded max lifetime"
            );
            return false;
        }

        // Check if connection has been idle too long
        if now.duration_since(pooled.last_used) > self.config.idle_timeout {
            debug!(
                connection_id = pooled.connection.id(),
                idle_time = ?now.duration_since(pooled.last_used),
                "Connection exceeded idle timeout"
            );
            return false;
        }

        // Perform basic health check
        if let Err(e) = pooled.connection.ping() {
            warn!(
                connection_id = pooled.connection.id(),
                error = %e,
                "Connection failed health check"
            );
            return false;
        }

        true
    }

    async fn return_connection(&self, connection_id: u64) {
        if let Some((_, active)) = self.active.remove(&connection_id) {
            let pooled = PooledConnection {
                connection: active.connection,
                created_at: active.created_at,
                last_used: Instant::now(),
            };

            self.available.push(pooled);

            let mut stats = self.stats.write();
            stats.connections_returned += 1;
            stats.active_connections = self.active.len();
            stats.idle_connections = self.available.len();

            // Notify waiting tasks
            self.notifier.notify_one();
        }
    }

    async fn destroy_connection(&self, connection: Connection) {
        let mut stats = self.stats.write();
        stats.connections_destroyed += 1;
        stats.total_connections = stats.total_connections.saturating_sub(1);

        debug!(
            connection_id = connection.id(),
            total_connections = stats.total_connections,
            "Destroyed database connection"
        );

        drop(connection);
    }

    fn total_connections(&self) -> usize {
        self.active.len() + self.available.len()
    }

    pub fn stats(&self) -> PoolStats {
        let mut stats = self.stats.read().clone();
        stats.active_connections = self.active.len();
        stats.idle_connections = self.available.len();
        stats.total_connections = self.total_connections();
        stats
    }

    fn start_maintenance_task(&self) {
        let pool = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(pool.config.health_check_interval);

            loop {
                interval.tick().await;

                if *pool.shutdown.lock() {
                    break;
                }

                pool.perform_maintenance().await;
            }
        });
    }

    async fn perform_maintenance(&self) {
        // Remove expired idle connections
        let mut expired_connections = Vec::new();
        let now = Instant::now();

        // Collect expired connections
        while let Some(pooled) = self.available.pop() {
            if !self.is_connection_valid(&pooled) {
                expired_connections.push(pooled.connection);
            } else {
                self.available.push(pooled);
                break;
            }
        }

        // Destroy expired connections
        for connection in expired_connections {
            self.destroy_connection(connection).await;
        }

        // Ensure minimum connections
        if let Err(e) = self.ensure_min_connections().await {
            error!(error = %e, "Failed to ensure minimum connections during maintenance");
        }

        debug!(
            active = self.active.len(),
            idle = self.available.len(),
            total = self.total_connections(),
            "Pool maintenance completed"
        );
    }

    pub async fn shutdown(&self) {
        info!("Shutting down connection pool");

        *self.shutdown.lock() = true;

        // Close all idle connections
        while let Some(pooled) = self.available.pop() {
            self.destroy_connection(pooled.connection).await;
        }

        info!("Connection pool shutdown complete");
    }
}

impl Clone for Pool {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            available: self.available.clone(),
            active: self.active.clone(),
            stats: self.stats.clone(),
            notifier: self.notifier.clone(),
            shutdown: self.shutdown.clone(),
        }
    }
}

pub struct PooledConnectionGuard {
    pool: Pool,
    connection: Option<Connection>,
    connection_id: u64,
}

impl PooledConnectionGuard {
    pub fn connection(&self) -> &Connection {
        self.connection.as_ref().unwrap()
    }
}

impl std::ops::Deref for PooledConnectionGuard {
    type Target = Connection;

    fn deref(&self) -> &Self::Target {
        self.connection.as_ref().unwrap()
    }
}

impl Drop for PooledConnectionGuard {
    fn drop(&mut self) {
        if self.connection.is_some() {
            let pool = self.pool.clone();
            let connection_id = self.connection_id;

            tokio::spawn(async move {
                pool.return_connection(connection_id).await;
            });
        }
    }
}