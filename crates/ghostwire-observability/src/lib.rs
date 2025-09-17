/// GhostWire Observability Library
///
/// Comprehensive metrics, logging, and observability infrastructure for GhostWire mesh VPN.
/// Provides Prometheus metrics, structured logging, distributed tracing, and health monitoring.

pub mod metrics;
pub mod logging;
pub mod tracing_ext;
pub mod health;
pub mod alerts;
pub mod exporter;
pub mod dashboard;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use tokio::sync::RwLock;
use tracing::{info, error};

pub use metrics::GhostWireMetrics;
pub use logging::LoggingConfig;
pub use health::{HealthChecker, HealthStatus};
pub use exporter::MetricsExporter;

/// Main observability coordinator for GhostWire
pub struct ObservabilityStack {
    metrics: Arc<GhostWireMetrics>,
    health_checker: Arc<RwLock<HealthChecker>>,
    exporter: Arc<MetricsExporter>,
    config: ObservabilityConfig,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ObservabilityConfig {
    pub metrics: MetricsConfig,
    pub logging: LoggingConfig,
    pub tracing: TracingConfig,
    pub health: HealthConfig,
    pub alerts: AlertConfig,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MetricsConfig {
    pub enabled: bool,
    pub listen_addr: SocketAddr,
    pub scrape_interval: Duration,
    pub retention: Duration,
    pub push_gateway: Option<String>,
    pub labels: std::collections::HashMap<String, String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TracingConfig {
    pub enabled: bool,
    pub endpoint: Option<String>,
    pub service_name: String,
    pub service_version: String,
    pub environment: String,
    pub sample_rate: f64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HealthConfig {
    pub enabled: bool,
    pub check_interval: Duration,
    pub timeout: Duration,
    pub endpoints: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AlertConfig {
    pub enabled: bool,
    pub webhook_url: Option<String>,
    pub email_config: Option<EmailConfig>,
    pub rules: Vec<AlertRule>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EmailConfig {
    pub smtp_server: String,
    pub smtp_port: u16,
    pub username: String,
    pub password: String,
    pub from: String,
    pub to: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AlertRule {
    pub name: String,
    pub metric: String,
    pub condition: String,
    pub threshold: f64,
    pub duration: Duration,
    pub severity: AlertSeverity,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum AlertSeverity {
    Info,
    Warning,
    Critical,
}

impl Default for ObservabilityConfig {
    fn default() -> Self {
        Self {
            metrics: MetricsConfig {
                enabled: true,
                listen_addr: "0.0.0.0:9090".parse().unwrap(),
                scrape_interval: Duration::from_secs(15),
                retention: Duration::from_secs(7 * 24 * 3600), // 7 days
                push_gateway: None,
                labels: std::collections::HashMap::new(),
            },
            logging: LoggingConfig::default(),
            tracing: TracingConfig {
                enabled: false,
                endpoint: None,
                service_name: "ghostwire".to_string(),
                service_version: env!("CARGO_PKG_VERSION").to_string(),
                environment: "production".to_string(),
                sample_rate: 0.1,
            },
            health: HealthConfig {
                enabled: true,
                check_interval: Duration::from_secs(30),
                timeout: Duration::from_secs(5),
                endpoints: vec![],
            },
            alerts: AlertConfig {
                enabled: false,
                webhook_url: None,
                email_config: None,
                rules: vec![],
            },
        }
    }
}

impl ObservabilityStack {
    /// Initialize the complete observability stack
    pub async fn new(config: ObservabilityConfig) -> Result<Self> {
        info!("Initializing GhostWire observability stack");

        // Initialize logging first
        logging::init_logging(&config.logging)?;
        info!("Logging initialized");

        // Initialize distributed tracing if enabled
        if config.tracing.enabled {
            tracing_ext::init_tracing(&config.tracing).await?;
            info!("Distributed tracing initialized");
        }

        // Initialize metrics
        let metrics = Arc::new(GhostWireMetrics::new(&config.metrics)?);
        info!("Metrics initialized");

        // Initialize health checker
        let health_checker = Arc::new(RwLock::new(
            HealthChecker::new(config.health.clone()).await?
        ));
        info!("Health checker initialized");

        // Initialize metrics exporter
        let exporter = Arc::new(
            MetricsExporter::new(config.metrics.clone(), metrics.clone()).await?
        );
        info!("Metrics exporter initialized");

        info!("GhostWire observability stack fully initialized");

        Ok(Self {
            metrics,
            health_checker,
            exporter,
            config,
        })
    }

    /// Start all observability services
    pub async fn start(&self) -> Result<()> {
        info!("Starting observability services");

        // Start metrics server
        let exporter_handle = {
            let exporter = self.exporter.clone();
            tokio::spawn(async move {
                if let Err(e) = exporter.start().await {
                    error!("Metrics exporter error: {}", e);
                }
            })
        };

        // Start health checker
        let health_handle = {
            let health_checker = self.health_checker.clone();
            let config = self.config.health.clone();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(config.check_interval);
                loop {
                    interval.tick().await;
                    if let Ok(mut checker) = health_checker.write().await {
                        if let Err(e) = checker.run_checks().await {
                            error!("Health check error: {}", e);
                        }
                    }
                }
            })
        };

        // Start system metrics collection
        let system_metrics_handle = {
            let metrics = self.metrics.clone();
            tokio::spawn(async move {
                Self::collect_system_metrics(metrics).await;
            })
        };

        info!("All observability services started");

        // Keep services running
        tokio::select! {
            _ = exporter_handle => error!("Metrics exporter stopped"),
            _ = health_handle => error!("Health checker stopped"),
            _ = system_metrics_handle => error!("System metrics collector stopped"),
        }

        Ok(())
    }

    /// Get metrics instance
    pub fn metrics(&self) -> Arc<GhostWireMetrics> {
        self.metrics.clone()
    }

    /// Get health checker
    pub fn health_checker(&self) -> Arc<RwLock<HealthChecker>> {
        self.health_checker.clone()
    }

    /// Record a custom event
    pub fn record_event(&self, event: &str, labels: &[(&str, &str)]) {
        self.metrics.record_event(event, labels);
    }

    /// Update connection metrics
    pub fn update_connection_metrics(&self, connected: bool, latency_ms: Option<u64>) {
        if connected {
            self.metrics.increment_connections();
            if let Some(latency) = latency_ms {
                self.metrics.record_latency(latency as f64);
            }
        } else {
            self.metrics.decrement_connections();
        }
    }

    /// Record bandwidth usage
    pub fn record_bandwidth(&self, bytes_sent: u64, bytes_received: u64) {
        self.metrics.add_bytes_sent(bytes_sent);
        self.metrics.add_bytes_received(bytes_received);
    }

    /// Collect system-level metrics periodically
    async fn collect_system_metrics(metrics: Arc<GhostWireMetrics>) {
        let mut interval = tokio::time::interval(Duration::from_secs(10));
        let mut system = sysinfo::System::new_all();

        loop {
            interval.tick().await;

            system.refresh_all();

            // CPU usage
            let cpu_usage = system.global_cpu_info().cpu_usage() as f64;
            metrics.set_cpu_usage(cpu_usage);

            // Memory usage
            let memory_used = system.used_memory();
            let memory_total = system.total_memory();
            let memory_usage = (memory_used as f64 / memory_total as f64) * 100.0;
            metrics.set_memory_usage(memory_usage);
            metrics.set_memory_bytes(memory_used);

            // Disk usage
            for disk in system.disks() {
                let disk_usage = if disk.total_space() > 0 {
                    ((disk.total_space() - disk.available_space()) as f64 / disk.total_space() as f64) * 100.0
                } else {
                    0.0
                };

                let labels = &[("disk", disk.name().to_string_lossy().as_ref())];
                metrics.set_disk_usage(disk_usage, labels);
            }

            // Network interfaces
            for (interface_name, data) in system.networks() {
                let labels = &[("interface", interface_name)];
                metrics.add_network_bytes_sent(data.transmitted(), labels);
                metrics.add_network_bytes_received(data.received(), labels);
            }

            // Process count
            let process_count = system.processes().len() as f64;
            metrics.set_process_count(process_count);
        }
    }
}

/// Initialize observability with default configuration
pub async fn init() -> Result<ObservabilityStack> {
    let config = ObservabilityConfig::default();
    ObservabilityStack::new(config).await
}

/// Initialize observability with custom configuration
pub async fn init_with_config(config: ObservabilityConfig) -> Result<ObservabilityStack> {
    ObservabilityStack::new(config).await
}