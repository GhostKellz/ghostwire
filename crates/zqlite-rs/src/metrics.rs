use prometheus::{
    Counter, Histogram, Gauge, Registry, Opts, HistogramOpts,
    register_counter_with_registry, register_histogram_with_registry,
    register_gauge_with_registry,
};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, warn};
use lazy_static::lazy_static;

lazy_static! {
    static ref METRICS_REGISTRY: Registry = Registry::new();
}

pub struct ZQLiteMetrics {
    // Query metrics
    pub queries_total: Counter,
    pub query_duration: Histogram,
    pub query_errors: Counter,

    // Connection metrics
    pub connections_active: Gauge,
    pub connections_idle: Gauge,
    pub connections_created: Counter,
    pub connections_destroyed: Counter,
    pub connection_errors: Counter,

    // Pool metrics
    pub pool_size: Gauge,
    pub pool_timeouts: Counter,
    pub pool_borrows: Counter,
    pub pool_returns: Counter,

    // Transaction metrics
    pub transactions_started: Counter,
    pub transactions_committed: Counter,
    pub transactions_rolled_back: Counter,

    // Post-quantum metrics
    pub post_quantum_operations: Counter,
    pub post_quantum_errors: Counter,

    registry: Arc<Registry>,
}

impl ZQLiteMetrics {
    pub fn new() -> Result<Self, prometheus::Error> {
        let registry = Arc::new(Registry::new());

        let queries_total = register_counter_with_registry!(
            Opts::new("zqlite_queries_total", "Total number of SQL queries executed"),
            registry
        )?;

        let query_duration = register_histogram_with_registry!(
            HistogramOpts::new("zqlite_query_duration_seconds", "Query execution duration")
                .buckets(vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 10.0]),
            registry
        )?;

        let query_errors = register_counter_with_registry!(
            Opts::new("zqlite_query_errors_total", "Total number of query errors"),
            registry
        )?;

        let connections_active = register_gauge_with_registry!(
            Opts::new("zqlite_connections_active", "Number of active connections"),
            registry
        )?;

        let connections_idle = register_gauge_with_registry!(
            Opts::new("zqlite_connections_idle", "Number of idle connections"),
            registry
        )?;

        let connections_created = register_counter_with_registry!(
            Opts::new("zqlite_connections_created_total", "Total connections created"),
            registry
        )?;

        let connections_destroyed = register_counter_with_registry!(
            Opts::new("zqlite_connections_destroyed_total", "Total connections destroyed"),
            registry
        )?;

        let connection_errors = register_counter_with_registry!(
            Opts::new("zqlite_connection_errors_total", "Total connection errors"),
            registry
        )?;

        let pool_size = register_gauge_with_registry!(
            Opts::new("zqlite_pool_size", "Current pool size"),
            registry
        )?;

        let pool_timeouts = register_counter_with_registry!(
            Opts::new("zqlite_pool_timeouts_total", "Total pool timeouts"),
            registry
        )?;

        let pool_borrows = register_counter_with_registry!(
            Opts::new("zqlite_pool_borrows_total", "Total pool borrows"),
            registry
        )?;

        let pool_returns = register_counter_with_registry!(
            Opts::new("zqlite_pool_returns_total", "Total pool returns"),
            registry
        )?;

        let transactions_started = register_counter_with_registry!(
            Opts::new("zqlite_transactions_started_total", "Total transactions started"),
            registry
        )?;

        let transactions_committed = register_counter_with_registry!(
            Opts::new("zqlite_transactions_committed_total", "Total transactions committed"),
            registry
        )?;

        let transactions_rolled_back = register_counter_with_registry!(
            Opts::new("zqlite_transactions_rolled_back_total", "Total transactions rolled back"),
            registry
        )?;

        let post_quantum_operations = register_counter_with_registry!(
            Opts::new("zqlite_post_quantum_operations_total", "Total post-quantum operations"),
            registry
        )?;

        let post_quantum_errors = register_counter_with_registry!(
            Opts::new("zqlite_post_quantum_errors_total", "Total post-quantum errors"),
            registry
        )?;

        Ok(Self {
            queries_total,
            query_duration,
            query_errors,
            connections_active,
            connections_idle,
            connections_created,
            connections_destroyed,
            connection_errors,
            pool_size,
            pool_timeouts,
            pool_borrows,
            pool_returns,
            transactions_started,
            transactions_committed,
            transactions_rolled_back,
            post_quantum_operations,
            post_quantum_errors,
            registry,
        })
    }

    pub fn global() -> &'static ZQLiteMetrics {
        lazy_static! {
            static ref GLOBAL_METRICS: ZQLiteMetrics = ZQLiteMetrics::new()
                .expect("Failed to initialize global metrics");
        }
        &GLOBAL_METRICS
    }

    pub fn registry(&self) -> &Registry {
        &self.registry
    }

    pub fn record_query<F, R>(&self, operation: F) -> R
    where
        F: FnOnce() -> R,
    {
        let start = Instant::now();
        self.queries_total.inc();

        let result = operation();

        let duration = start.elapsed();
        self.query_duration.observe(duration.as_secs_f64());

        debug!(
            duration_ms = duration.as_millis(),
            "Query executed"
        );

        result
    }

    pub fn record_query_error(&self) {
        self.query_errors.inc();
    }

    pub fn record_connection_created(&self) {
        self.connections_created.inc();
    }

    pub fn record_connection_destroyed(&self) {
        self.connections_destroyed.inc();
    }

    pub fn record_connection_error(&self) {
        self.connection_errors.inc();
    }

    pub fn update_pool_stats(
        &self,
        total_size: usize,
        active_connections: usize,
        idle_connections: usize,
    ) {
        self.pool_size.set(total_size as f64);
        self.connections_active.set(active_connections as f64);
        self.connections_idle.set(idle_connections as f64);
    }

    pub fn record_pool_timeout(&self) {
        self.pool_timeouts.inc();
    }

    pub fn record_pool_borrow(&self) {
        self.pool_borrows.inc();
    }

    pub fn record_pool_return(&self) {
        self.pool_returns.inc();
    }

    pub fn record_transaction_started(&self) {
        self.transactions_started.inc();
    }

    pub fn record_transaction_committed(&self) {
        self.transactions_committed.inc();
    }

    pub fn record_transaction_rolled_back(&self) {
        self.transactions_rolled_back.inc();
    }

    pub fn record_post_quantum_operation(&self) {
        self.post_quantum_operations.inc();
    }

    pub fn record_post_quantum_error(&self) {
        self.post_quantum_errors.inc();
    }

    pub fn gather_metrics(&self) -> Vec<prometheus::proto::MetricFamily> {
        self.registry.gather()
    }
}

impl Default for ZQLiteMetrics {
    fn default() -> Self {
        Self::new().expect("Failed to create default metrics")
    }
}

pub struct QueryTimer {
    start: Instant,
    metrics: &'static ZQLiteMetrics,
}

impl QueryTimer {
    pub fn new() -> Self {
        Self {
            start: Instant::now(),
            metrics: ZQLiteMetrics::global(),
        }
    }

    pub fn success(self) {
        let duration = self.start.elapsed();
        self.metrics.queries_total.inc();
        self.metrics.query_duration.observe(duration.as_secs_f64());
    }

    pub fn error(self) {
        let duration = self.start.elapsed();
        self.metrics.queries_total.inc();
        self.metrics.query_duration.observe(duration.as_secs_f64());
        self.metrics.query_errors.inc();
    }
}

impl Default for QueryTimer {
    fn default() -> Self {
        Self::new()
    }
}

// Convenience macros for instrumentation
#[macro_export]
macro_rules! time_query {
    ($expr:expr) => {{
        let timer = $crate::metrics::QueryTimer::new();
        let result = $expr;
        match &result {
            Ok(_) => timer.success(),
            Err(_) => timer.error(),
        }
        result
    }};
}

#[macro_export]
macro_rules! record_connection_event {
    (created) => {
        $crate::metrics::ZQLiteMetrics::global().record_connection_created();
    };
    (destroyed) => {
        $crate::metrics::ZQLiteMetrics::global().record_connection_destroyed();
    };
    (error) => {
        $crate::metrics::ZQLiteMetrics::global().record_connection_error();
    };
}

#[macro_export]
macro_rules! record_pool_event {
    (timeout) => {
        $crate::metrics::ZQLiteMetrics::global().record_pool_timeout();
    };
    (borrow) => {
        $crate::metrics::ZQLiteMetrics::global().record_pool_borrow();
    };
    (return) => {
        $crate::metrics::ZQLiteMetrics::global().record_pool_return();
    };
}

#[macro_export]
macro_rules! record_transaction_event {
    (started) => {
        $crate::metrics::ZQLiteMetrics::global().record_transaction_started();
    };
    (committed) => {
        $crate::metrics::ZQLiteMetrics::global().record_transaction_committed();
    };
    (rolled_back) => {
        $crate::metrics::ZQLiteMetrics::global().record_transaction_rolled_back();
    };
}

// HTTP metrics endpoint handler for Axum
#[cfg(feature = "axum")]
pub async fn metrics_handler() -> Result<String, axum::http::StatusCode> {
    use prometheus::TextEncoder;

    let metrics = ZQLiteMetrics::global();
    let encoder = TextEncoder::new();
    let metric_families = metrics.gather_metrics();

    encoder
        .encode_to_string(&metric_families)
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_creation() {
        let metrics = ZQLiteMetrics::new().unwrap();
        assert_eq!(metrics.queries_total.get(), 0.0);
    }

    #[test]
    fn test_query_timer() {
        let timer = QueryTimer::new();
        std::thread::sleep(Duration::from_millis(1));
        timer.success();

        let metrics = ZQLiteMetrics::global();
        assert!(metrics.queries_total.get() >= 1.0);
    }

    #[test]
    fn test_connection_metrics() {
        let metrics = ZQLiteMetrics::global();
        let initial_created = metrics.connections_created.get();

        metrics.record_connection_created();
        assert_eq!(metrics.connections_created.get(), initial_created + 1.0);
    }
}