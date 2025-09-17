/// Comprehensive metrics collection for GhostWire
///
/// Provides Prometheus-compatible metrics for all aspects of the mesh VPN system.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use prometheus::{
    Counter, CounterVec, Gauge, GaugeVec, Histogram, HistogramVec, Registry, Opts, HistogramOpts,
};
use anyhow::Result;
use tracing::{info, warn, error};

use crate::MetricsConfig;

/// Main metrics collection for GhostWire
pub struct GhostWireMetrics {
    registry: Registry,

    // Connection metrics
    connections_total: Counter,
    connections_active: Gauge,
    connection_duration: HistogramVec,
    connection_errors: CounterVec,

    // Network metrics
    bytes_sent_total: Counter,
    bytes_received_total: Counter,
    packets_sent_total: Counter,
    packets_received_total: Counter,
    network_latency: HistogramVec,

    // DERP relay metrics
    derp_connections: GaugeVec,
    derp_bytes_relayed: CounterVec,
    derp_latency: HistogramVec,
    derp_errors: CounterVec,

    // Authentication metrics
    auth_attempts_total: CounterVec,
    auth_tokens_active: Gauge,
    auth_token_duration: Histogram,

    // Machine/Node metrics
    machines_total: Gauge,
    machines_online: Gauge,
    machine_last_seen: GaugeVec,
    machine_routes: GaugeVec,

    // API metrics
    api_requests_total: CounterVec,
    api_request_duration: HistogramVec,
    api_errors_total: CounterVec,

    // System metrics
    cpu_usage_percent: Gauge,
    memory_usage_percent: Gauge,
    memory_usage_bytes: Gauge,
    disk_usage_percent: GaugeVec,
    network_bytes_sent: CounterVec,
    network_bytes_received: CounterVec,
    process_count: Gauge,

    // Performance metrics
    goroutines: Gauge,
    gc_duration: Histogram,
    allocations: Counter,

    // Custom application metrics
    tunnel_setup_duration: Histogram,
    key_rotation_total: Counter,
    policy_evaluations: CounterVec,
    dns_queries: CounterVec,

    // Health metrics
    health_check_status: GaugeVec,
    health_check_duration: HistogramVec,

    // Event metrics
    events_total: CounterVec,

    start_time: Instant,
}

impl GhostWireMetrics {
    /// Create a new metrics instance
    pub fn new(config: &MetricsConfig) -> Result<Self> {
        let registry = Registry::new();

        info!("Initializing GhostWire metrics with {} labels", config.labels.len());

        // Connection metrics
        let connections_total = Counter::with_opts(Opts::new(
            "ghostwire_connections_total",
            "Total number of connections established"
        ))?;

        let connections_active = Gauge::with_opts(Opts::new(
            "ghostwire_connections_active",
            "Current number of active connections"
        ))?;

        let connection_duration = HistogramVec::new(
            HistogramOpts::new(
                "ghostwire_connection_duration_seconds",
                "Duration of connections in seconds"
            ).buckets(vec![0.1, 0.5, 1.0, 5.0, 10.0, 30.0, 60.0, 300.0, 3600.0]),
            &["type"]
        )?;

        let connection_errors = CounterVec::new(
            Opts::new(
                "ghostwire_connection_errors_total",
                "Total connection errors by type"
            ),
            &["error_type", "component"]
        )?;

        // Network metrics
        let bytes_sent_total = Counter::with_opts(Opts::new(
            "ghostwire_bytes_sent_total",
            "Total bytes sent through the network"
        ))?;

        let bytes_received_total = Counter::with_opts(Opts::new(
            "ghostwire_bytes_received_total",
            "Total bytes received through the network"
        ))?;

        let packets_sent_total = Counter::with_opts(Opts::new(
            "ghostwire_packets_sent_total",
            "Total packets sent"
        ))?;

        let packets_received_total = Counter::with_opts(Opts::new(
            "ghostwire_packets_received_total",
            "Total packets received"
        ))?;

        let network_latency = HistogramVec::new(
            HistogramOpts::new(
                "ghostwire_network_latency_seconds",
                "Network latency in seconds"
            ).buckets(vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0]),
            &["destination", "protocol"]
        )?;

        // DERP relay metrics
        let derp_connections = GaugeVec::new(
            Opts::new(
                "ghostwire_derp_connections",
                "Current DERP relay connections"
            ),
            &["region", "relay"]
        )?;

        let derp_bytes_relayed = CounterVec::new(
            Opts::new(
                "ghostwire_derp_bytes_relayed_total",
                "Total bytes relayed through DERP"
            ),
            &["region", "direction"]
        )?;

        let derp_latency = HistogramVec::new(
            HistogramOpts::new(
                "ghostwire_derp_latency_seconds",
                "DERP relay latency"
            ).buckets(vec![0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0]),
            &["region"]
        )?;

        let derp_errors = CounterVec::new(
            Opts::new(
                "ghostwire_derp_errors_total",
                "DERP relay errors"
            ),
            &["region", "error_type"]
        )?;

        // Authentication metrics
        let auth_attempts_total = CounterVec::new(
            Opts::new(
                "ghostwire_auth_attempts_total",
                "Total authentication attempts"
            ),
            &["method", "result"]
        )?;

        let auth_tokens_active = Gauge::with_opts(Opts::new(
            "ghostwire_auth_tokens_active",
            "Currently active authentication tokens"
        ))?;

        let auth_token_duration = Histogram::with_opts(
            HistogramOpts::new(
                "ghostwire_auth_token_duration_seconds",
                "Duration of authentication token validity"
            ).buckets(vec![300.0, 900.0, 1800.0, 3600.0, 7200.0, 86400.0])
        )?;

        // Machine/Node metrics
        let machines_total = Gauge::with_opts(Opts::new(
            "ghostwire_machines_total",
            "Total number of registered machines"
        ))?;

        let machines_online = Gauge::with_opts(Opts::new(
            "ghostwire_machines_online",
            "Number of currently online machines"
        ))?;

        let machine_last_seen = GaugeVec::new(
            Opts::new(
                "ghostwire_machine_last_seen_timestamp",
                "Last seen timestamp for machines"
            ),
            &["machine_id", "user"]
        )?;

        let machine_routes = GaugeVec::new(
            Opts::new(
                "ghostwire_machine_routes",
                "Number of routes advertised by each machine"
            ),
            &["machine_id"]
        )?;

        // API metrics
        let api_requests_total = CounterVec::new(
            Opts::new(
                "ghostwire_api_requests_total",
                "Total API requests"
            ),
            &["method", "endpoint", "status"]
        )?;

        let api_request_duration = HistogramVec::new(
            HistogramOpts::new(
                "ghostwire_api_request_duration_seconds",
                "API request duration"
            ).buckets(vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]),
            &["method", "endpoint"]
        )?;

        let api_errors_total = CounterVec::new(
            Opts::new(
                "ghostwire_api_errors_total",
                "Total API errors"
            ),
            &["method", "endpoint", "error_type"]
        )?;

        // System metrics
        let cpu_usage_percent = Gauge::with_opts(Opts::new(
            "ghostwire_cpu_usage_percent",
            "CPU usage percentage"
        ))?;

        let memory_usage_percent = Gauge::with_opts(Opts::new(
            "ghostwire_memory_usage_percent",
            "Memory usage percentage"
        ))?;

        let memory_usage_bytes = Gauge::with_opts(Opts::new(
            "ghostwire_memory_usage_bytes",
            "Memory usage in bytes"
        ))?;

        let disk_usage_percent = GaugeVec::new(
            Opts::new(
                "ghostwire_disk_usage_percent",
                "Disk usage percentage"
            ),
            &["disk"]
        )?;

        let network_bytes_sent = CounterVec::new(
            Opts::new(
                "ghostwire_system_network_bytes_sent_total",
                "System network bytes sent"
            ),
            &["interface"]
        )?;

        let network_bytes_received = CounterVec::new(
            Opts::new(
                "ghostwire_system_network_bytes_received_total",
                "System network bytes received"
            ),
            &["interface"]
        )?;

        let process_count = Gauge::with_opts(Opts::new(
            "ghostwire_process_count",
            "Number of system processes"
        ))?;

        // Performance metrics
        let goroutines = Gauge::with_opts(Opts::new(
            "ghostwire_goroutines",
            "Number of goroutines (async tasks)"
        ))?;

        let gc_duration = Histogram::with_opts(
            HistogramOpts::new(
                "ghostwire_gc_duration_seconds",
                "Garbage collection duration"
            ).buckets(vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0])
        )?;

        let allocations = Counter::with_opts(Opts::new(
            "ghostwire_allocations_total",
            "Total memory allocations"
        ))?;

        // Custom application metrics
        let tunnel_setup_duration = Histogram::with_opts(
            HistogramOpts::new(
                "ghostwire_tunnel_setup_duration_seconds",
                "Time to establish tunnel connections"
            ).buckets(vec![0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0])
        )?;

        let key_rotation_total = Counter::with_opts(Opts::new(
            "ghostwire_key_rotation_total",
            "Total key rotations performed"
        ))?;

        let policy_evaluations = CounterVec::new(
            Opts::new(
                "ghostwire_policy_evaluations_total",
                "Total policy evaluations"
            ),
            &["policy", "result"]
        )?;

        let dns_queries = CounterVec::new(
            Opts::new(
                "ghostwire_dns_queries_total",
                "Total DNS queries"
            ),
            &["query_type", "result"]
        )?;

        // Health metrics
        let health_check_status = GaugeVec::new(
            Opts::new(
                "ghostwire_health_check_status",
                "Health check status (1 = healthy, 0 = unhealthy)"
            ),
            &["check_name", "component"]
        )?;

        let health_check_duration = HistogramVec::new(
            HistogramOpts::new(
                "ghostwire_health_check_duration_seconds",
                "Health check duration"
            ).buckets(vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 5.0]),
            &["check_name"]
        )?;

        // Event metrics
        let events_total = CounterVec::new(
            Opts::new(
                "ghostwire_events_total",
                "Total events by type"
            ),
            &["event_type", "component"]
        )?;

        // Register all metrics
        let metrics_to_register: Vec<Box<dyn prometheus::core::Collector>> = vec![
            Box::new(connections_total.clone()),
            Box::new(connections_active.clone()),
            Box::new(connection_duration.clone()),
            Box::new(connection_errors.clone()),
            Box::new(bytes_sent_total.clone()),
            Box::new(bytes_received_total.clone()),
            Box::new(packets_sent_total.clone()),
            Box::new(packets_received_total.clone()),
            Box::new(network_latency.clone()),
            Box::new(derp_connections.clone()),
            Box::new(derp_bytes_relayed.clone()),
            Box::new(derp_latency.clone()),
            Box::new(derp_errors.clone()),
            Box::new(auth_attempts_total.clone()),
            Box::new(auth_tokens_active.clone()),
            Box::new(auth_token_duration.clone()),
            Box::new(machines_total.clone()),
            Box::new(machines_online.clone()),
            Box::new(machine_last_seen.clone()),
            Box::new(machine_routes.clone()),
            Box::new(api_requests_total.clone()),
            Box::new(api_request_duration.clone()),
            Box::new(api_errors_total.clone()),
            Box::new(cpu_usage_percent.clone()),
            Box::new(memory_usage_percent.clone()),
            Box::new(memory_usage_bytes.clone()),
            Box::new(disk_usage_percent.clone()),
            Box::new(network_bytes_sent.clone()),
            Box::new(network_bytes_received.clone()),
            Box::new(process_count.clone()),
            Box::new(goroutines.clone()),
            Box::new(gc_duration.clone()),
            Box::new(allocations.clone()),
            Box::new(tunnel_setup_duration.clone()),
            Box::new(key_rotation_total.clone()),
            Box::new(policy_evaluations.clone()),
            Box::new(dns_queries.clone()),
            Box::new(health_check_status.clone()),
            Box::new(health_check_duration.clone()),
            Box::new(events_total.clone()),
        ];

        for metric in metrics_to_register {
            registry.register(metric)?;
        }

        info!("Successfully registered {} metrics", registry.gather().len());

        Ok(Self {
            registry,
            connections_total,
            connections_active,
            connection_duration,
            connection_errors,
            bytes_sent_total,
            bytes_received_total,
            packets_sent_total,
            packets_received_total,
            network_latency,
            derp_connections,
            derp_bytes_relayed,
            derp_latency,
            derp_errors,
            auth_attempts_total,
            auth_tokens_active,
            auth_token_duration,
            machines_total,
            machines_online,
            machine_last_seen,
            machine_routes,
            api_requests_total,
            api_request_duration,
            api_errors_total,
            cpu_usage_percent,
            memory_usage_percent,
            memory_usage_bytes,
            disk_usage_percent,
            network_bytes_sent,
            network_bytes_received,
            process_count,
            goroutines,
            gc_duration,
            allocations,
            tunnel_setup_duration,
            key_rotation_total,
            policy_evaluations,
            dns_queries,
            health_check_status,
            health_check_duration,
            events_total,
            start_time: Instant::now(),
        })
    }

    /// Get the Prometheus registry
    pub fn registry(&self) -> &Registry {
        &self.registry
    }

    // Connection metrics methods
    pub fn increment_connections(&self) {
        self.connections_total.inc();
        self.connections_active.inc();
    }

    pub fn decrement_connections(&self) {
        self.connections_active.dec();
    }

    pub fn record_connection_duration(&self, duration: Duration, conn_type: &str) {
        self.connection_duration
            .with_label_values(&[conn_type])
            .observe(duration.as_secs_f64());
    }

    pub fn record_connection_error(&self, error_type: &str, component: &str) {
        self.connection_errors
            .with_label_values(&[error_type, component])
            .inc();
    }

    // Network metrics methods
    pub fn add_bytes_sent(&self, bytes: u64) {
        self.bytes_sent_total.inc_by(bytes as f64);
    }

    pub fn add_bytes_received(&self, bytes: u64) {
        self.bytes_received_total.inc_by(bytes as f64);
    }

    pub fn add_packets_sent(&self, count: u64) {
        self.packets_sent_total.inc_by(count as f64);
    }

    pub fn add_packets_received(&self, count: u64) {
        self.packets_received_total.inc_by(count as f64);
    }

    pub fn record_latency(&self, latency_ms: f64) {
        self.network_latency
            .with_label_values(&["", ""])
            .observe(latency_ms / 1000.0);
    }

    // System metrics methods
    pub fn set_cpu_usage(&self, usage: f64) {
        self.cpu_usage_percent.set(usage);
    }

    pub fn set_memory_usage(&self, usage: f64) {
        self.memory_usage_percent.set(usage);
    }

    pub fn set_memory_bytes(&self, bytes: u64) {
        self.memory_usage_bytes.set(bytes as f64);
    }

    pub fn set_disk_usage(&self, usage: f64, labels: &[(&str, &str)]) {
        let label_values: Vec<&str> = labels.iter().map(|(_, v)| *v).collect();
        self.disk_usage_percent
            .with_label_values(&label_values)
            .set(usage);
    }

    pub fn add_network_bytes_sent(&self, bytes: u64, labels: &[(&str, &str)]) {
        let label_values: Vec<&str> = labels.iter().map(|(_, v)| *v).collect();
        self.network_bytes_sent
            .with_label_values(&label_values)
            .inc_by(bytes as f64);
    }

    pub fn add_network_bytes_received(&self, bytes: u64, labels: &[(&str, &str)]) {
        let label_values: Vec<&str> = labels.iter().map(|(_, v)| *v).collect();
        self.network_bytes_received
            .with_label_values(&label_values)
            .inc_by(bytes as f64);
    }

    pub fn set_process_count(&self, count: f64) {
        self.process_count.set(count);
    }

    // API metrics methods
    pub fn record_api_request(&self, method: &str, endpoint: &str, status: &str, duration: Duration) {
        self.api_requests_total
            .with_label_values(&[method, endpoint, status])
            .inc();

        self.api_request_duration
            .with_label_values(&[method, endpoint])
            .observe(duration.as_secs_f64());
    }

    pub fn record_api_error(&self, method: &str, endpoint: &str, error_type: &str) {
        self.api_errors_total
            .with_label_values(&[method, endpoint, error_type])
            .inc();
    }

    // Machine metrics methods
    pub fn set_machines_total(&self, count: f64) {
        self.machines_total.set(count);
    }

    pub fn set_machines_online(&self, count: f64) {
        self.machines_online.set(count);
    }

    pub fn update_machine_last_seen(&self, machine_id: &str, user: &str, timestamp: SystemTime) {
        let unix_time = timestamp
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as f64;

        self.machine_last_seen
            .with_label_values(&[machine_id, user])
            .set(unix_time);
    }

    // Event recording
    pub fn record_event(&self, event_type: &str, labels: &[(&str, &str)]) {
        let mut label_values = vec![event_type];
        for (_, value) in labels {
            label_values.push(value);
        }

        // Pad with empty strings if needed
        while label_values.len() < 2 {
            label_values.push("");
        }

        self.events_total
            .with_label_values(&label_values[..2])
            .inc();
    }

    // Health check methods
    pub fn set_health_check_status(&self, check_name: &str, component: &str, healthy: bool) {
        let status = if healthy { 1.0 } else { 0.0 };
        self.health_check_status
            .with_label_values(&[check_name, component])
            .set(status);
    }

    pub fn record_health_check_duration(&self, check_name: &str, duration: Duration) {
        self.health_check_duration
            .with_label_values(&[check_name])
            .observe(duration.as_secs_f64());
    }

    /// Get current uptime in seconds
    pub fn uptime_seconds(&self) -> f64 {
        self.start_time.elapsed().as_secs_f64()
    }

    /// Export all metrics as Prometheus format
    pub fn export(&self) -> Result<String> {
        let encoder = prometheus::TextEncoder::new();
        let metric_families = self.registry.gather();
        Ok(encoder.encode_to_string(&metric_families)?)
    }
}