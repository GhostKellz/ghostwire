/// GhostWire server integration layer
///
/// Orchestrates all server components into a cohesive system:
/// - Database layer with SQLite/sqlx
/// - Coordination server with node management
/// - gRPC and REST API endpoints
/// - Authentication with OIDC support
/// - Policy engine with HuJSON parsing
/// - Network map generation and distribution
/// - DERP relay with QUIC and STUN support
/// - MagicDNS with split-DNS backends

use crate::{
    database::DatabaseManager,
    coordinator::Coordinator,
    auth::AuthenticationManager,
    policy::PolicyEngine,
    netmap::NetworkMapService,
    derp::DerpServer,
    dns::DnsServer,
    api::{grpc::GrpcServer, rest::RestServer},
};
use ghostwire_common::{
    types::*,
    error::{Result, GhostWireError},
};
use std::sync::Arc;
use std::net::SocketAddr;
use std::time::{Duration, SystemTime};
use tokio::sync::{broadcast, RwLock};
use tokio::time::timeout;
use tracing::{info, warn, error, debug};
use serde::{Deserialize, Serialize};

/// Server configuration
#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    /// Server instance configuration
    pub instance: InstanceConfig,

    /// Database configuration
    pub database: crate::database::DatabaseConfig,

    /// Authentication configuration
    pub auth: crate::auth::AuthConfig,

    /// Policy engine configuration
    pub policy: crate::policy::PolicyConfig,

    /// Network map configuration
    pub netmap: crate::netmap::NetworkMapConfig,

    /// DERP relay configuration
    pub derp: crate::derp::DerpConfig,

    /// DNS server configuration
    pub dns: crate::dns::DnsConfig,

    /// gRPC API configuration
    pub grpc: crate::api::grpc::GrpcConfig,

    /// REST API configuration
    pub rest: crate::api::rest::RestConfig,

    /// Observability configuration
    pub observability: ObservabilityConfig,
}

/// Server instance configuration
#[derive(Debug, Clone, Deserialize)]
pub struct InstanceConfig {
    /// Server instance ID
    pub instance_id: Option<String>,

    /// Server name
    pub server_name: String,

    /// Server region
    pub region: String,

    /// Server environment (dev, staging, prod)
    pub environment: String,

    /// Graceful shutdown timeout (seconds)
    pub shutdown_timeout_seconds: u64,

    /// Health check configuration
    pub health_check: HealthCheckConfig,

    /// Resource limits
    pub limits: ResourceLimits,
}

impl Default for InstanceConfig {
    fn default() -> Self {
        Self {
            instance_id: None,
            server_name: "ghostwire-server".to_string(),
            region: "default".to_string(),
            environment: "development".to_string(),
            shutdown_timeout_seconds: 30,
            health_check: HealthCheckConfig::default(),
            limits: ResourceLimits::default(),
        }
    }
}

/// Health check configuration
#[derive(Debug, Clone, Deserialize)]
pub struct HealthCheckConfig {
    /// Enable health checks
    pub enabled: bool,

    /// Health check endpoint path
    pub endpoint: String,

    /// Health check interval (seconds)
    pub interval_seconds: u64,

    /// Health check timeout (seconds)
    pub timeout_seconds: u64,

    /// Include component status in health check
    pub include_components: bool,
}

impl Default for HealthCheckConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            endpoint: "/health".to_string(),
            interval_seconds: 30,
            timeout_seconds: 5,
            include_components: true,
        }
    }
}

/// Resource limits
#[derive(Debug, Clone, Deserialize)]
pub struct ResourceLimits {
    /// Maximum memory usage (MB)
    pub max_memory_mb: Option<u64>,

    /// Maximum CPU usage (percent)
    pub max_cpu_percent: Option<f64>,

    /// Maximum concurrent connections
    pub max_connections: Option<u32>,

    /// Maximum requests per second
    pub max_requests_per_second: Option<u32>,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_memory_mb: Some(1024), // 1GB
            max_cpu_percent: Some(80.0),
            max_connections: Some(10000),
            max_requests_per_second: Some(1000),
        }
    }
}

/// Observability configuration
#[derive(Debug, Clone, Deserialize)]
pub struct ObservabilityConfig {
    /// Enable metrics collection
    pub metrics: MetricsConfig,

    /// Logging configuration
    pub logging: LoggingConfig,

    /// Tracing configuration
    pub tracing: TracingConfig,
}

impl Default for ObservabilityConfig {
    fn default() -> Self {
        Self {
            metrics: MetricsConfig::default(),
            logging: LoggingConfig::default(),
            tracing: TracingConfig::default(),
        }
    }
}

/// Metrics configuration
#[derive(Debug, Clone, Deserialize)]
pub struct MetricsConfig {
    /// Enable metrics
    pub enabled: bool,

    /// Metrics endpoint
    pub endpoint: String,

    /// Metrics port
    pub port: u16,

    /// Metrics collection interval (seconds)
    pub collection_interval_seconds: u64,

    /// Enable custom metrics
    pub custom_metrics: bool,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            endpoint: "/metrics".to_string(),
            port: 9090,
            collection_interval_seconds: 10,
            custom_metrics: true,
        }
    }
}

/// Logging configuration
#[derive(Debug, Clone, Deserialize)]
pub struct LoggingConfig {
    /// Log level
    pub level: String,

    /// Log format
    pub format: String,

    /// Enable structured logging
    pub structured: bool,

    /// Log file path
    pub file: Option<String>,

    /// Enable log rotation
    pub rotation: bool,

    /// Maximum log file size (MB)
    pub max_file_size_mb: u64,

    /// Number of log files to keep
    pub max_files: u32,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            format: "json".to_string(),
            structured: true,
            file: None,
            rotation: false,
            max_file_size_mb: 100,
            max_files: 10,
        }
    }
}

/// Tracing configuration
#[derive(Debug, Clone, Deserialize)]
pub struct TracingConfig {
    /// Enable distributed tracing
    pub enabled: bool,

    /// Tracing endpoint
    pub endpoint: Option<String>,

    /// Service name for tracing
    pub service_name: String,

    /// Sampling rate
    pub sampling_rate: f64,
}

impl Default for TracingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: None,
            service_name: "ghostwire-server".to_string(),
            sampling_rate: 0.1,
        }
    }
}

/// Server status
#[derive(Debug, Clone, Serialize)]
pub enum ServerStatus {
    Starting,
    Running,
    Stopping,
    Stopped,
    Error(String),
}

/// Component health status
#[derive(Debug, Clone, Serialize)]
pub struct ComponentHealth {
    pub component: String,
    pub status: HealthStatus,
    pub last_check: SystemTime,
    pub message: Option<String>,
}

/// Health status
#[derive(Debug, Clone, Serialize)]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
    Unknown,
}

/// Server health report
#[derive(Debug, Clone, Serialize)]
pub struct ServerHealth {
    pub overall_status: HealthStatus,
    pub components: Vec<ComponentHealth>,
    pub uptime_seconds: u64,
    pub memory_usage_mb: f64,
    pub cpu_usage_percent: f64,
    pub active_connections: u32,
    pub requests_per_second: f64,
}

/// Main GhostWire server
pub struct GhostWireServer {
    config: ServerConfig,
    status: Arc<RwLock<ServerStatus>>,
    start_time: SystemTime,
    shutdown_sender: Option<broadcast::Sender<()>>,

    // Core components
    database: Arc<DatabaseManager>,
    coordinator: Arc<Coordinator>,
    auth_manager: Arc<AuthenticationManager>,
    policy_engine: Arc<PolicyEngine>,
    netmap_service: Arc<NetworkMapService>,

    // Network services
    derp_server: Option<Arc<DerpServer>>,
    dns_server: Option<Arc<DnsServer>>,
    grpc_server: Option<Arc<GrpcServer>>,
    rest_server: Option<Arc<RestServer>>,
}

impl GhostWireServer {
    /// Create a new GhostWire server
    pub async fn new(config: ServerConfig) -> Result<Self> {
        info!("Initializing GhostWire server: {}", config.instance.server_name);

        let status = Arc::new(RwLock::new(ServerStatus::Starting));
        let start_time = SystemTime::now();

        // Initialize database
        info!("Initializing database...");
        let database = Arc::new(DatabaseManager::new(&config.database).await?);

        // Run migrations
        database.migrate().await?;

        // Initialize coordinator
        info!("Initializing coordinator...");
        let coordinator = Arc::new(Coordinator::new(database.clone(), config.instance.server_name.clone()).await?);

        // Initialize authentication manager
        info!("Initializing authentication manager...");
        let auth_manager = Arc::new(AuthenticationManager::new(config.auth.clone(), database.clone()).await?);

        // Initialize policy engine
        info!("Initializing policy engine...");
        let policy_engine = Arc::new(PolicyEngine::new(config.policy.clone(), database.clone()).await?);

        // Initialize network map service
        info!("Initializing network map service...");
        let netmap_service = Arc::new(NetworkMapService::new(
            config.netmap.clone(),
            coordinator.clone(),
            policy_engine.clone(),
        ).await?);

        // Initialize optional services
        let derp_server = if config.derp.enabled {
            info!("Initializing DERP server...");
            Some(Arc::new(DerpServer::new(config.derp.clone(), coordinator.clone())))
        } else {
            None
        };

        let dns_server = if config.dns.enabled {
            info!("Initializing DNS server...");
            Some(Arc::new(DnsServer::new(config.dns.clone(), coordinator.clone()).await?))
        } else {
            None
        };

        let grpc_server = if config.grpc.enabled {
            info!("Initializing gRPC server...");
            Some(Arc::new(GrpcServer::new(
                config.grpc.clone(),
                coordinator.clone(),
                auth_manager.clone(),
                policy_engine.clone(),
                netmap_service.clone(),
            ).await?))
        } else {
            None
        };

        let rest_server = if config.rest.enabled {
            info!("Initializing REST server...");
            Some(Arc::new(RestServer::new(
                config.rest.clone(),
                coordinator.clone(),
                auth_manager.clone(),
                policy_engine.clone(),
                netmap_service.clone(),
            ).await?))
        } else {
            None
        };

        info!("GhostWire server initialized successfully");

        Ok(Self {
            config,
            status,
            start_time,
            shutdown_sender: None,
            database,
            coordinator,
            auth_manager,
            policy_engine,
            netmap_service,
            derp_server,
            dns_server,
            grpc_server,
            rest_server,
        })
    }

    /// Start the server
    pub async fn start(&mut self) -> Result<()> {
        info!("Starting GhostWire server...");

        *self.status.write().await = ServerStatus::Starting;

        // Create shutdown channel
        let (shutdown_tx, _) = broadcast::channel(1);
        self.shutdown_sender = Some(shutdown_tx.clone());

        // Start core services
        self.coordinator.start().await?;
        self.policy_engine.start().await?;
        self.netmap_service.start().await?;

        // Start network services
        if let Some(derp_server) = &mut self.derp_server {
            // Clone the Arc to get a mutable reference
            let mut derp_clone = DerpServer::new(self.config.derp.clone(), self.coordinator.clone());
            derp_clone.start().await?;
        }

        if let Some(dns_server) = &self.dns_server {
            dns_server.start().await?;
        }

        if let Some(grpc_server) = &self.grpc_server {
            grpc_server.start().await?;
        }

        if let Some(rest_server) = &self.rest_server {
            rest_server.start().await?;
        }

        // Start background tasks
        self.start_health_check_task(shutdown_tx.clone()).await;
        self.start_metrics_collection_task(shutdown_tx.clone()).await;
        self.start_cleanup_tasks(shutdown_tx).await;

        *self.status.write().await = ServerStatus::Running;

        info!(
            "GhostWire server started successfully on {}",
            self.config.instance.server_name
        );

        Ok(())
    }

    /// Stop the server
    pub async fn stop(&mut self) -> Result<()> {
        info!("Stopping GhostWire server...");

        *self.status.write().await = ServerStatus::Stopping;

        // Send shutdown signal
        if let Some(sender) = &self.shutdown_sender {
            let _ = sender.send(());
        }

        // Stop services with timeout
        let shutdown_timeout = Duration::from_secs(self.config.instance.shutdown_timeout_seconds);

        // Stop network services first
        if let Some(rest_server) = &mut self.rest_server {
            if let Err(e) = timeout(shutdown_timeout, rest_server.stop()).await {
                warn!("REST server shutdown timeout: {}", e);
            }
        }

        if let Some(grpc_server) = &mut self.grpc_server {
            if let Err(e) = timeout(shutdown_timeout, grpc_server.stop()).await {
                warn!("gRPC server shutdown timeout: {}", e);
            }
        }

        if let Some(dns_server) = &self.dns_server {
            if let Err(e) = timeout(shutdown_timeout, dns_server.stop()).await {
                warn!("DNS server shutdown timeout: {}", e);
            }
        }

        if let Some(derp_server) = &mut self.derp_server {
            // Clone and stop
            let mut derp_clone = DerpServer::new(self.config.derp.clone(), self.coordinator.clone());
            if let Err(e) = timeout(shutdown_timeout, derp_clone.stop()).await {
                warn!("DERP server shutdown timeout: {}", e);
            }
        }

        // Stop core services
        if let Err(e) = timeout(shutdown_timeout, self.netmap_service.stop()).await {
            warn!("Network map service shutdown timeout: {}", e);
        }

        if let Err(e) = timeout(shutdown_timeout, self.policy_engine.stop()).await {
            warn!("Policy engine shutdown timeout: {}", e);
        }

        if let Err(e) = timeout(shutdown_timeout, self.coordinator.stop()).await {
            warn!("Coordinator shutdown timeout: {}", e);
        }

        // Close database connections
        self.database.close().await?;

        *self.status.write().await = ServerStatus::Stopped;

        info!("GhostWire server stopped");
        Ok(())
    }

    /// Get server status
    pub async fn get_status(&self) -> ServerStatus {
        self.status.read().await.clone()
    }

    /// Get server health
    pub async fn get_health(&self) -> Result<ServerHealth> {
        let mut components = Vec::new();
        let now = SystemTime::now();

        // Check database health
        let db_health = match self.database.health_check().await {
            Ok(_) => ComponentHealth {
                component: "database".to_string(),
                status: HealthStatus::Healthy,
                last_check: now,
                message: None,
            },
            Err(e) => ComponentHealth {
                component: "database".to_string(),
                status: HealthStatus::Unhealthy,
                last_check: now,
                message: Some(e.to_string()),
            },
        };
        components.push(db_health);

        // Check coordinator health
        let coord_stats = self.coordinator.get_stats().await;
        let coord_health = ComponentHealth {
            component: "coordinator".to_string(),
            status: if coord_stats.active_nodes > 0 {
                HealthStatus::Healthy
            } else {
                HealthStatus::Degraded
            },
            last_check: now,
            message: Some(format!("Active nodes: {}", coord_stats.active_nodes)),
        };
        components.push(coord_health);

        // Check DERP server health if enabled
        if let Some(derp_server) = &self.derp_server {
            let derp_stats = derp_server.get_stats().await;
            let derp_health = ComponentHealth {
                component: "derp".to_string(),
                status: HealthStatus::Healthy,
                last_check: now,
                message: Some(format!("Active connections: {}", derp_stats.active_connections)),
            };
            components.push(derp_health);
        }

        // Check DNS server health if enabled
        if let Some(dns_server) = &self.dns_server {
            let dns_stats = dns_server.get_stats().await;
            let dns_health = ComponentHealth {
                component: "dns".to_string(),
                status: HealthStatus::Healthy,
                last_check: now,
                message: Some(format!("Total queries: {}", dns_stats.total_queries)),
            };
            components.push(dns_health);
        }

        // Determine overall status
        let overall_status = if components.iter().any(|c| matches!(c.status, HealthStatus::Unhealthy)) {
            HealthStatus::Unhealthy
        } else if components.iter().any(|c| matches!(c.status, HealthStatus::Degraded)) {
            HealthStatus::Degraded
        } else {
            HealthStatus::Healthy
        };

        // Get system metrics (simplified)
        let uptime_seconds = self.start_time.elapsed().unwrap_or_default().as_secs();

        Ok(ServerHealth {
            overall_status,
            components,
            uptime_seconds,
            memory_usage_mb: 0.0, // Would implement actual memory monitoring
            cpu_usage_percent: 0.0, // Would implement actual CPU monitoring
            active_connections: coord_stats.active_nodes,
            requests_per_second: 0.0, // Would implement actual RPS monitoring
        })
    }

    /// Get server configuration
    pub fn get_config(&self) -> &ServerConfig {
        &self.config
    }

    /// Get server instance ID
    pub fn get_instance_id(&self) -> String {
        self.config.instance.instance_id
            .clone()
            .unwrap_or_else(|| format!("{}-{}", self.config.instance.server_name, uuid::Uuid::new_v4()))
    }

    // Private helper methods

    async fn start_health_check_task(&self, shutdown_tx: broadcast::Sender<()>) {
        if !self.config.instance.health_check.enabled {
            return;
        }

        let server = self.clone();
        let mut shutdown_rx = shutdown_tx.subscribe();
        let interval = Duration::from_secs(self.config.instance.health_check.interval_seconds);

        tokio::spawn(async move {
            let mut health_interval = tokio::time::interval(interval);

            loop {
                tokio::select! {
                    _ = health_interval.tick() => {
                        match server.get_health().await {
                            Ok(health) => {
                                debug!("Health check: {:?}", health.overall_status);

                                // Log unhealthy components
                                for component in &health.components {
                                    if matches!(component.status, HealthStatus::Unhealthy) {
                                        warn!("Component {} is unhealthy: {:?}",
                                            component.component, component.message);
                                    }
                                }
                            }
                            Err(e) => {
                                error!("Health check failed: {}", e);
                            }
                        }
                    }
                    _ = shutdown_rx.recv() => {
                        debug!("Health check task stopped");
                        break;
                    }
                }
            }
        });
    }

    async fn start_metrics_collection_task(&self, shutdown_tx: broadcast::Sender<()>) {
        if !self.config.observability.metrics.enabled {
            return;
        }

        let mut shutdown_rx = shutdown_tx.subscribe();
        let interval = Duration::from_secs(self.config.observability.metrics.collection_interval_seconds);

        tokio::spawn(async move {
            let mut metrics_interval = tokio::time::interval(interval);

            loop {
                tokio::select! {
                    _ = metrics_interval.tick() => {
                        // Collect and export metrics
                        debug!("Collecting metrics...");
                        // Would implement actual metrics collection here
                    }
                    _ = shutdown_rx.recv() => {
                        debug!("Metrics collection task stopped");
                        break;
                    }
                }
            }
        });
    }

    async fn start_cleanup_tasks(&self, shutdown_tx: broadcast::Sender<()>) {
        let mut shutdown_rx = shutdown_tx.subscribe();

        tokio::spawn(async move {
            let mut cleanup_interval = tokio::time::interval(Duration::from_secs(300)); // 5 minutes

            loop {
                tokio::select! {
                    _ = cleanup_interval.tick() => {
                        // Perform periodic cleanup tasks
                        debug!("Running cleanup tasks...");
                        // Would implement actual cleanup logic here
                    }
                    _ = shutdown_rx.recv() => {
                        debug!("Cleanup tasks stopped");
                        break;
                    }
                }
            }
        });
    }
}

impl Clone for GhostWireServer {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            status: self.status.clone(),
            start_time: self.start_time,
            shutdown_sender: self.shutdown_sender.clone(),
            database: self.database.clone(),
            coordinator: self.coordinator.clone(),
            auth_manager: self.auth_manager.clone(),
            policy_engine: self.policy_engine.clone(),
            netmap_service: self.netmap_service.clone(),
            derp_server: self.derp_server.clone(),
            dns_server: self.dns_server.clone(),
            grpc_server: self.grpc_server.clone(),
            rest_server: self.rest_server.clone(),
        }
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            instance: InstanceConfig::default(),
            database: crate::database::DatabaseConfig::default(),
            auth: crate::auth::AuthConfig::default(),
            policy: crate::policy::PolicyConfig::default(),
            netmap: crate::netmap::NetworkMapConfig::default(),
            derp: crate::derp::DerpConfig::default(),
            dns: crate::dns::DnsConfig::default(),
            grpc: crate::api::grpc::GrpcConfig::default(),
            rest: crate::api::rest::RestConfig::default(),
            observability: ObservabilityConfig::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_config_default() {
        let config = ServerConfig::default();
        assert_eq!(config.instance.server_name, "ghostwire-server");
        assert_eq!(config.instance.region, "default");
        assert_eq!(config.instance.environment, "development");
    }

    #[test]
    fn test_health_check_config_default() {
        let config = HealthCheckConfig::default();
        assert!(config.enabled);
        assert_eq!(config.endpoint, "/health");
        assert_eq!(config.interval_seconds, 30);
    }

    #[test]
    fn test_resource_limits_default() {
        let limits = ResourceLimits::default();
        assert_eq!(limits.max_memory_mb, Some(1024));
        assert_eq!(limits.max_cpu_percent, Some(80.0));
        assert_eq!(limits.max_connections, Some(10000));
    }

    #[test]
    fn test_metrics_config_default() {
        let config = MetricsConfig::default();
        assert!(config.enabled);
        assert_eq!(config.endpoint, "/metrics");
        assert_eq!(config.port, 9090);
    }

    #[test]
    fn test_logging_config_default() {
        let config = LoggingConfig::default();
        assert_eq!(config.level, "info");
        assert_eq!(config.format, "json");
        assert!(config.structured);
    }
}