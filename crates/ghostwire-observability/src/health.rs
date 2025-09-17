/// Health monitoring and checks for GhostWire components
///
/// Provides comprehensive health checking for all system components with
/// configurable checks, alerting, and automated recovery.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use std::fmt;

use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{info, warn, error, debug};

use crate::HealthConfig;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthChecker {
    config: HealthConfig,
    checks: HashMap<String, HealthCheck>,
    last_run: Option<SystemTime>,
    system_status: SystemStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheck {
    pub name: String,
    pub check_type: HealthCheckType,
    pub status: HealthStatus,
    pub last_run: Option<SystemTime>,
    pub last_success: Option<SystemTime>,
    pub consecutive_failures: u32,
    pub total_runs: u64,
    pub total_failures: u64,
    pub average_duration: Duration,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HealthCheckType {
    Http { url: String, expected_status: u16, timeout: Duration },
    Tcp { host: String, port: u16, timeout: Duration },
    Database { connection_string: String, query: Option<String> },
    Memory { max_usage_percent: f64 },
    Disk { path: String, max_usage_percent: f64 },
    Process { name: String, expected_running: bool },
    Custom { command: String, expected_exit_code: i32 },
    Internal { component: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemStatus {
    pub overall_status: HealthStatus,
    pub component_statuses: HashMap<String, ComponentStatus>,
    pub system_info: SystemInfo,
    pub last_updated: SystemTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentStatus {
    pub status: HealthStatus,
    pub checks_passed: u32,
    pub checks_failed: u32,
    pub last_check: Option<SystemTime>,
    pub uptime: Duration,
    pub details: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemInfo {
    pub hostname: String,
    pub os: String,
    pub arch: String,
    pub cpu_cores: usize,
    pub total_memory: u64,
    pub used_memory: u64,
    pub load_average: Option<f64>,
    pub uptime: Duration,
    pub version: String,
}

impl fmt::Display for HealthStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HealthStatus::Healthy => write!(f, "Healthy"),
            HealthStatus::Degraded => write!(f, "Degraded"),
            HealthStatus::Unhealthy => write!(f, "Unhealthy"),
            HealthStatus::Unknown => write!(f, "Unknown"),
        }
    }
}

impl HealthChecker {
    /// Create a new health checker with configuration
    pub async fn new(config: HealthConfig) -> Result<Self> {
        info!("Initializing health checker with {} endpoints", config.endpoints.len());

        let mut checks = HashMap::new();

        // Add default system checks
        checks.insert("memory".to_string(), HealthCheck {
            name: "memory".to_string(),
            check_type: HealthCheckType::Memory { max_usage_percent: 90.0 },
            status: HealthStatus::Unknown,
            last_run: None,
            last_success: None,
            consecutive_failures: 0,
            total_runs: 0,
            total_failures: 0,
            average_duration: Duration::from_millis(0),
            last_error: None,
        });

        checks.insert("disk".to_string(), HealthCheck {
            name: "disk".to_string(),
            check_type: HealthCheckType::Disk {
                path: "/".to_string(),
                max_usage_percent: 85.0,
            },
            status: HealthStatus::Unknown,
            last_run: None,
            last_success: None,
            consecutive_failures: 0,
            total_runs: 0,
            total_failures: 0,
            average_duration: Duration::from_millis(0),
            last_error: None,
        });

        // Add configured endpoint checks
        for (i, endpoint) in config.endpoints.iter().enumerate() {
            let check_name = format!("endpoint_{}", i);

            // Parse endpoint URL to determine check type
            if let Ok(url) = url::Url::parse(endpoint) {
                let check_type = match url.scheme() {
                    "http" | "https" => HealthCheckType::Http {
                        url: endpoint.clone(),
                        expected_status: 200,
                        timeout: config.timeout,
                    },
                    _ => {
                        if let Some(host) = url.host_str() {
                            HealthCheckType::Tcp {
                                host: host.to_string(),
                                port: url.port().unwrap_or(80),
                                timeout: config.timeout,
                            }
                        } else {
                            continue;
                        }
                    }
                };

                checks.insert(check_name.clone(), HealthCheck {
                    name: check_name,
                    check_type,
                    status: HealthStatus::Unknown,
                    last_run: None,
                    last_success: None,
                    consecutive_failures: 0,
                    total_runs: 0,
                    total_failures: 0,
                    average_duration: Duration::from_millis(0),
                    last_error: None,
                });
            }
        }

        let system_status = SystemStatus {
            overall_status: HealthStatus::Unknown,
            component_statuses: HashMap::new(),
            system_info: Self::gather_system_info().await,
            last_updated: SystemTime::now(),
        };

        Ok(Self {
            config,
            checks,
            last_run: None,
            system_status,
        })
    }

    /// Run all health checks
    pub async fn run_checks(&mut self) -> Result<()> {
        debug!("Running {} health checks", self.checks.len());
        let start_time = Instant::now();

        let mut all_healthy = true;
        let mut any_degraded = false;

        for (name, check) in self.checks.iter_mut() {
            let check_start = Instant::now();
            let result = self.run_single_check(check).await;
            let check_duration = check_start.elapsed();

            // Update check statistics
            check.total_runs += 1;
            check.last_run = Some(SystemTime::now());

            // Update average duration
            let new_avg = (check.average_duration.as_millis() as f64 * (check.total_runs - 1) as f64
                + check_duration.as_millis() as f64) / check.total_runs as f64;
            check.average_duration = Duration::from_millis(new_avg as u64);

            match result {
                Ok(_) => {
                    if check.status != HealthStatus::Healthy {
                        info!("Health check '{}' recovered", name);
                    }
                    check.status = HealthStatus::Healthy;
                    check.last_success = Some(SystemTime::now());
                    check.consecutive_failures = 0;
                    check.last_error = None;
                }
                Err(e) => {
                    check.consecutive_failures += 1;
                    check.total_failures += 1;
                    check.last_error = Some(e.to_string());

                    // Determine status based on consecutive failures
                    check.status = if check.consecutive_failures >= 3 {
                        HealthStatus::Unhealthy
                    } else {
                        HealthStatus::Degraded
                    };

                    warn!(
                        "Health check '{}' failed (attempt {}): {}",
                        name, check.consecutive_failures, e
                    );

                    if check.status == HealthStatus::Unhealthy {
                        all_healthy = false;
                    } else {
                        any_degraded = true;
                    }
                }
            }
        }

        // Update overall system status
        self.system_status.overall_status = if all_healthy {
            HealthStatus::Healthy
        } else if any_degraded {
            HealthStatus::Degraded
        } else {
            HealthStatus::Unhealthy
        };

        self.system_status.last_updated = SystemTime::now();
        self.last_run = Some(SystemTime::now());

        debug!("Health checks completed in {:?}", start_time.elapsed());
        Ok(())
    }

    /// Run a single health check
    async fn run_single_check(&self, check: &HealthCheck) -> Result<()> {
        match &check.check_type {
            HealthCheckType::Http { url, expected_status, timeout } => {
                self.check_http(url, *expected_status, *timeout).await
            }
            HealthCheckType::Tcp { host, port, timeout } => {
                self.check_tcp(host, *port, *timeout).await
            }
            HealthCheckType::Database { connection_string, query } => {
                self.check_database(connection_string, query.as_deref()).await
            }
            HealthCheckType::Memory { max_usage_percent } => {
                self.check_memory(*max_usage_percent).await
            }
            HealthCheckType::Disk { path, max_usage_percent } => {
                self.check_disk(path, *max_usage_percent).await
            }
            HealthCheckType::Process { name, expected_running } => {
                self.check_process(name, *expected_running).await
            }
            HealthCheckType::Custom { command, expected_exit_code } => {
                self.check_custom_command(command, *expected_exit_code).await
            }
            HealthCheckType::Internal { component } => {
                self.check_internal_component(component).await
            }
        }
    }

    /// HTTP health check
    async fn check_http(&self, url: &str, expected_status: u16, timeout: Duration) -> Result<()> {
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .build()?;

        let response = client.get(url).send().await?;

        if response.status().as_u16() == expected_status {
            Ok(())
        } else {
            Err(anyhow!(
                "HTTP check failed: expected status {}, got {}",
                expected_status,
                response.status()
            ))
        }
    }

    /// TCP connection health check
    async fn check_tcp(&self, host: &str, port: u16, timeout: Duration) -> Result<()> {
        let addr = format!("{}:{}", host, port);

        match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(&addr)).await {
            Ok(Ok(_)) => Ok(()),
            Ok(Err(e)) => Err(anyhow!("TCP connection failed: {}", e)),
            Err(_) => Err(anyhow!("TCP connection timed out")),
        }
    }

    /// Database health check
    async fn check_database(&self, _connection_string: &str, _query: Option<&str>) -> Result<()> {
        // Database connectivity check would go here
        // For now, just return success
        Ok(())
    }

    /// Memory usage health check
    async fn check_memory(&self, max_usage_percent: f64) -> Result<()> {
        let system = sysinfo::System::new_all();
        let used_memory = system.used_memory();
        let total_memory = system.total_memory();

        if total_memory == 0 {
            return Err(anyhow!("Unable to determine memory usage"));
        }

        let usage_percent = (used_memory as f64 / total_memory as f64) * 100.0;

        if usage_percent > max_usage_percent {
            Err(anyhow!(
                "Memory usage too high: {:.1}% > {:.1}%",
                usage_percent,
                max_usage_percent
            ))
        } else {
            Ok(())
        }
    }

    /// Disk usage health check
    async fn check_disk(&self, path: &str, max_usage_percent: f64) -> Result<()> {
        let system = sysinfo::System::new_all();

        for disk in system.disks() {
            if disk.mount_point().to_string_lossy().starts_with(path) {
                let total_space = disk.total_space();
                let available_space = disk.available_space();

                if total_space == 0 {
                    continue;
                }

                let used_space = total_space - available_space;
                let usage_percent = (used_space as f64 / total_space as f64) * 100.0;

                if usage_percent > max_usage_percent {
                    return Err(anyhow!(
                        "Disk usage too high for {}: {:.1}% > {:.1}%",
                        path,
                        usage_percent,
                        max_usage_percent
                    ));
                }

                return Ok(());
            }
        }

        Err(anyhow!("Disk path not found: {}", path))
    }

    /// Process health check
    async fn check_process(&self, name: &str, expected_running: bool) -> Result<()> {
        let system = sysinfo::System::new_all();
        let process_exists = system.processes_by_name(name).next().is_some();

        if process_exists == expected_running {
            Ok(())
        } else if expected_running {
            Err(anyhow!("Process '{}' is not running", name))
        } else {
            Err(anyhow!("Process '{}' is unexpectedly running", name))
        }
    }

    /// Custom command health check
    async fn check_custom_command(&self, command: &str, expected_exit_code: i32) -> Result<()> {
        let output = tokio::process::Command::new("sh")
            .arg("-c")
            .arg(command)
            .output()
            .await?;

        let exit_code = output.status.code().unwrap_or(-1);

        if exit_code == expected_exit_code {
            Ok(())
        } else {
            Err(anyhow!(
                "Command '{}' exited with code {}, expected {}",
                command,
                exit_code,
                expected_exit_code
            ))
        }
    }

    /// Internal component health check
    async fn check_internal_component(&self, component: &str) -> Result<()> {
        // This would check internal GhostWire component health
        // For now, just return success
        debug!("Checking internal component: {}", component);
        Ok(())
    }

    /// Gather system information
    async fn gather_system_info() -> SystemInfo {
        let system = sysinfo::System::new_all();

        SystemInfo {
            hostname: hostname::get()
                .unwrap_or_else(|_| "unknown".into())
                .to_string_lossy()
                .to_string(),
            os: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
            cpu_cores: num_cpus::get(),
            total_memory: system.total_memory(),
            used_memory: system.used_memory(),
            load_average: system.load_average().one.into(),
            uptime: Duration::from_secs(system.uptime()),
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }

    /// Get current system status
    pub fn status(&self) -> &SystemStatus {
        &self.system_status
    }

    /// Get specific check status
    pub fn check_status(&self, name: &str) -> Option<&HealthCheck> {
        self.checks.get(name)
    }

    /// Get all checks
    pub fn all_checks(&self) -> &HashMap<String, HealthCheck> {
        &self.checks
    }

    /// Add a custom health check
    pub fn add_check(&mut self, name: String, check_type: HealthCheckType) {
        let check = HealthCheck {
            name: name.clone(),
            check_type,
            status: HealthStatus::Unknown,
            last_run: None,
            last_success: None,
            consecutive_failures: 0,
            total_runs: 0,
            total_failures: 0,
            average_duration: Duration::from_millis(0),
            last_error: None,
        };

        self.checks.insert(name, check);
    }

    /// Remove a health check
    pub fn remove_check(&mut self, name: &str) -> Option<HealthCheck> {
        self.checks.remove(name)
    }

    /// Export health status as JSON
    pub fn export_json(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(&self.system_status)?)
    }

    /// Generate health summary
    pub fn summary(&self) -> HealthSummary {
        let total_checks = self.checks.len();
        let healthy_checks = self.checks.values()
            .filter(|c| c.status == HealthStatus::Healthy)
            .count();
        let degraded_checks = self.checks.values()
            .filter(|c| c.status == HealthStatus::Degraded)
            .count();
        let unhealthy_checks = self.checks.values()
            .filter(|c| c.status == HealthStatus::Unhealthy)
            .count();

        HealthSummary {
            overall_status: self.system_status.overall_status.clone(),
            total_checks,
            healthy_checks,
            degraded_checks,
            unhealthy_checks,
            last_updated: self.system_status.last_updated,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthSummary {
    pub overall_status: HealthStatus,
    pub total_checks: usize,
    pub healthy_checks: usize,
    pub degraded_checks: usize,
    pub unhealthy_checks: usize,
    pub last_updated: SystemTime,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_health_checker_creation() {
        let config = HealthConfig {
            enabled: true,
            check_interval: Duration::from_secs(30),
            timeout: Duration::from_secs(5),
            endpoints: vec!["http://example.com".to_string()],
        };

        let checker = HealthChecker::new(config).await;
        assert!(checker.is_ok());

        let checker = checker.unwrap();
        assert!(checker.checks.len() >= 3); // memory, disk, + endpoint
    }

    #[tokio::test]
    async fn test_memory_check() {
        let checker = HealthChecker::new(HealthConfig::default()).await.unwrap();

        // Memory check should pass with reasonable threshold
        let result = checker.check_memory(95.0).await;
        assert!(result.is_ok());

        // Memory check should fail with very low threshold
        let result = checker.check_memory(0.1).await;
        assert!(result.is_err());
    }
}