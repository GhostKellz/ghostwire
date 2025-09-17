//! Performance tests and benchmarks for GhostWire

pub mod crypto;
pub mod network;
pub mod server;

use crate::{TestConfig, TestResult, TestSuite};
use anyhow::Result;

/// Performance test suite that runs all benchmarks
pub struct PerformanceTestSuite;

#[async_trait::async_trait]
impl TestSuite for PerformanceTestSuite {
    fn name(&self) -> &str {
        "Performance Benchmarks"
    }

    async fn run_tests(&self, config: &TestConfig) -> Result<Vec<TestResult>> {
        let mut results = Vec::new();

        // Run crypto performance tests
        let crypto_suite = crypto::CryptoPerformanceTestSuite;
        let mut crypto_results = crypto_suite.run_tests(config).await?;
        results.append(&mut crypto_results);

        // Run network performance tests
        let network_suite = network::NetworkPerformanceTestSuite;
        let mut network_results = network_suite.run_tests(config).await?;
        results.append(&mut network_results);

        // Run server performance tests
        let server_suite = server::ServerPerformanceTestSuite;
        let mut server_results = server_suite.run_tests(config).await?;
        results.append(&mut server_results);

        Ok(results)
    }
}

/// Benchmark configuration
#[derive(Debug, Clone)]
pub struct BenchmarkConfig {
    /// Number of iterations for timing tests
    pub iterations: usize,
    /// Duration for throughput tests
    pub duration_secs: u64,
    /// Concurrent connections for load tests
    pub concurrency: usize,
    /// Data size for transfer tests
    pub data_size_bytes: usize,
}

impl Default for BenchmarkConfig {
    fn default() -> Self {
        Self {
            iterations: 1000,
            duration_secs: 10,
            concurrency: 50,
            data_size_bytes: 1024 * 1024, // 1MB
        }
    }
}

/// Performance metrics collected during benchmarks
#[derive(Debug, Clone)]
pub struct PerformanceMetrics {
    /// Operations per second
    pub ops_per_sec: f64,
    /// Average latency in milliseconds
    pub avg_latency_ms: f64,
    /// 95th percentile latency in milliseconds
    pub p95_latency_ms: f64,
    /// 99th percentile latency in milliseconds
    pub p99_latency_ms: f64,
    /// Throughput in bytes per second
    pub throughput_bps: f64,
    /// Memory usage in bytes
    pub memory_usage_bytes: u64,
    /// CPU usage percentage
    pub cpu_usage_percent: f64,
}

impl PerformanceMetrics {
    pub fn new() -> Self {
        Self {
            ops_per_sec: 0.0,
            avg_latency_ms: 0.0,
            p95_latency_ms: 0.0,
            p99_latency_ms: 0.0,
            throughput_bps: 0.0,
            memory_usage_bytes: 0,
            cpu_usage_percent: 0.0,
        }
    }

    pub fn from_latencies(latencies: &[std::time::Duration], duration: std::time::Duration) -> Self {
        let mut sorted = latencies.to_vec();
        sorted.sort();

        let ops_per_sec = latencies.len() as f64 / duration.as_secs_f64();
        let avg_latency_ms = sorted.iter().map(|d| d.as_millis() as f64).sum::<f64>() / sorted.len() as f64;

        let p95_index = (sorted.len() as f64 * 0.95) as usize;
        let p99_index = (sorted.len() as f64 * 0.99) as usize;

        let p95_latency_ms = sorted.get(p95_index).map(|d| d.as_millis() as f64).unwrap_or(0.0);
        let p99_latency_ms = sorted.get(p99_index).map(|d| d.as_millis() as f64).unwrap_or(0.0);

        Self {
            ops_per_sec,
            avg_latency_ms,
            p95_latency_ms,
            p99_latency_ms,
            throughput_bps: 0.0,
            memory_usage_bytes: 0,
            cpu_usage_percent: 0.0,
        }
    }
}

/// Utility for measuring system resources during benchmarks
pub struct ResourceMonitor {
    start_memory: u64,
    start_cpu: f64,
}

impl ResourceMonitor {
    pub fn start() -> Self {
        let sys = sysinfo::System::new_all();

        Self {
            start_memory: sys.used_memory(),
            start_cpu: sys.global_cpu_info().cpu_usage() as f64,
        }
    }

    pub fn measure(&self) -> (u64, f64) {
        let sys = sysinfo::System::new_all();
        let memory_delta = sys.used_memory().saturating_sub(self.start_memory);
        let cpu_usage = sys.global_cpu_info().cpu_usage() as f64;

        (memory_delta, cpu_usage)
    }
}

/// Macro for creating performance tests
#[macro_export]
macro_rules! performance_test {
    ($name:ident, $setup:expr, $test:expr, $teardown:expr) => {
        #[tokio::test]
        async fn $name() {
            $crate::init_test_env();

            let config = $crate::performance::BenchmarkConfig::default();
            let monitor = $crate::performance::ResourceMonitor::start();

            let setup_result = $setup().await;
            if let Err(e) = setup_result {
                panic!("Setup failed for {}: {}", stringify!($name), e);
            }

            let start = std::time::Instant::now();
            let test_result = $test(&config).await;
            let duration = start.elapsed();

            let teardown_result = $teardown().await;
            if let Err(e) = teardown_result {
                eprintln!("Teardown failed for {}: {}", stringify!($name), e);
            }

            let (memory_usage, cpu_usage) = monitor.measure();

            match test_result {
                Ok(metrics) => {
                    println!("✅ {} completed in {:?}", stringify!($name), duration);
                    println!("   Ops/sec: {:.2}", metrics.ops_per_sec);
                    println!("   Avg latency: {:.2}ms", metrics.avg_latency_ms);
                    println!("   P95 latency: {:.2}ms", metrics.p95_latency_ms);
                    println!("   Memory usage: {} bytes", memory_usage);
                    println!("   CPU usage: {:.2}%", cpu_usage);
                }
                Err(e) => {
                    println!("❌ {} failed in {:?}: {}", stringify!($name), duration, e);
                    panic!("Performance test {} should pass", stringify!($name));
                }
            }
        }
    };
}