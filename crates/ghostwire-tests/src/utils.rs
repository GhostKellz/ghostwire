//! Test utilities and helpers

use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Test environment manager for setting up complex test scenarios
pub struct TestEnvironment {
    servers: Vec<crate::common::TestServer>,
    clients: HashMap<String, crate::common::TestClient>,
    cleanup_tasks: Vec<Box<dyn FnOnce() -> Result<()> + Send>>,
}

impl TestEnvironment {
    pub fn new() -> Self {
        Self {
            servers: Vec::new(),
            clients: HashMap::new(),
            cleanup_tasks: Vec::new(),
        }
    }

    pub async fn add_server(&mut self, name: impl Into<String>) -> Result<&crate::common::TestServer> {
        let mut server = crate::common::TestServer::new().await?;
        server.start().await?;

        let server_name = name.into();
        let base_url = server.base_url();

        self.clients.insert(server_name.clone(), crate::common::TestClient::new(base_url));
        self.servers.push(server);

        Ok(self.servers.last().unwrap())
    }

    pub fn get_client(&self, name: &str) -> Option<&crate::common::TestClient> {
        self.clients.get(name)
    }

    pub fn add_cleanup_task<F>(&mut self, task: F)
    where
        F: FnOnce() -> Result<()> + Send + 'static,
    {
        self.cleanup_tasks.push(Box::new(task));
    }

    pub async fn cleanup(mut self) -> Result<()> {
        // Stop all servers
        for mut server in self.servers {
            let _ = server.stop().await;
        }

        // Run cleanup tasks
        for task in self.cleanup_tasks {
            if let Err(e) = task() {
                eprintln!("Cleanup task failed: {}", e);
            }
        }

        Ok(())
    }
}

impl Drop for TestEnvironment {
    fn drop(&mut self) {
        // Best effort cleanup in drop
        for task in self.cleanup_tasks.drain(..) {
            let _ = task();
        }
    }
}

/// Test data generator for creating realistic test scenarios
pub struct TestDataGenerator {
    counter: Arc<Mutex<u64>>,
}

impl TestDataGenerator {
    pub fn new() -> Self {
        Self {
            counter: Arc::new(Mutex::new(0)),
        }
    }

    pub async fn next_id(&self) -> u64 {
        let mut counter = self.counter.lock().await;
        *counter += 1;
        *counter
    }

    pub async fn generate_machine_name(&self) -> String {
        let id = self.next_id().await;
        format!("test-machine-{}", id)
    }

    pub async fn generate_ip(&self) -> std::net::Ipv4Addr {
        let id = self.next_id().await;
        let octet = ((id % 254) + 1) as u8;
        std::net::Ipv4Addr::new(192, 168, 1, octet)
    }

    pub async fn generate_auth_token(&self) -> String {
        let id = self.next_id().await;
        format!("test-token-{}", id)
    }
}

impl Default for TestDataGenerator {
    fn default() -> Self {
        Self::new()
    }
}

/// Performance tracking utilities
pub struct PerformanceTracker {
    metrics: Arc<Mutex<HashMap<String, Vec<f64>>>>,
}

impl PerformanceTracker {
    pub fn new() -> Self {
        Self {
            metrics: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn record(&self, metric_name: impl Into<String>, value: f64) {
        let mut metrics = self.metrics.lock().await;
        metrics
            .entry(metric_name.into())
            .or_insert_with(Vec::new)
            .push(value);
    }

    pub async fn get_average(&self, metric_name: &str) -> Option<f64> {
        let metrics = self.metrics.lock().await;
        metrics.get(metric_name).map(|values| {
            let sum: f64 = values.iter().sum();
            sum / values.len() as f64
        })
    }

    pub async fn get_percentile(&self, metric_name: &str, percentile: f64) -> Option<f64> {
        let metrics = self.metrics.lock().await;
        metrics.get(metric_name).map(|values| {
            let mut sorted = values.clone();
            sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
            let index = ((sorted.len() as f64 - 1.0) * percentile / 100.0) as usize;
            sorted[index]
        })
    }

    pub async fn print_summary(&self) {
        let metrics = self.metrics.lock().await;
        println!("Performance Summary:");
        for (name, values) in metrics.iter() {
            if values.is_empty() {
                continue;
            }

            let mut sorted = values.clone();
            sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());

            let avg = sorted.iter().sum::<f64>() / sorted.len() as f64;
            let min = sorted[0];
            let max = sorted[sorted.len() - 1];

            let p50_idx = (sorted.len() as f64 * 0.5) as usize;
            let p95_idx = (sorted.len() as f64 * 0.95) as usize;
            let p99_idx = (sorted.len() as f64 * 0.99) as usize;

            let p50 = sorted.get(p50_idx).copied().unwrap_or(0.0);
            let p95 = sorted.get(p95_idx).copied().unwrap_or(0.0);
            let p99 = sorted.get(p99_idx).copied().unwrap_or(0.0);

            println!(
                "  {}: avg={:.2}, min={:.2}, max={:.2}, p50={:.2}, p95={:.2}, p99={:.2}",
                name, avg, min, max, p50, p95, p99
            );
        }
    }
}

impl Default for PerformanceTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Chaos testing utilities
pub mod chaos {
    use super::*;
    use rand::Rng;
    use std::time::Duration;

    pub struct ChaosConfig {
        pub failure_rate: f64,    // 0.0 to 1.0
        pub delay_rate: f64,      // 0.0 to 1.0
        pub max_delay_ms: u64,
        pub packet_loss_rate: f64, // 0.0 to 1.0
    }

    impl Default for ChaosConfig {
        fn default() -> Self {
            Self {
                failure_rate: 0.01,    // 1% failure rate
                delay_rate: 0.05,      // 5% delay rate
                max_delay_ms: 100,
                packet_loss_rate: 0.001, // 0.1% packet loss
            }
        }
    }

    pub async fn apply_network_chaos<F, T>(config: &ChaosConfig, operation: F) -> Result<T>
    where
        F: std::future::Future<Output = Result<T>>,
    {
        let mut rng = rand::thread_rng();

        // Simulate packet loss
        if rng.gen::<f64>() < config.packet_loss_rate {
            return Err(anyhow::anyhow!("Simulated packet loss"));
        }

        // Simulate network delay
        if rng.gen::<f64>() < config.delay_rate {
            let delay_ms = rng.gen_range(0..config.max_delay_ms);
            tokio::time::sleep(Duration::from_millis(delay_ms)).await;
        }

        // Simulate random failures
        if rng.gen::<f64>() < config.failure_rate {
            return Err(anyhow::anyhow!("Simulated network failure"));
        }

        operation.await
    }

    pub async fn chaos_test<F>(
        name: &str,
        config: ChaosConfig,
        iterations: usize,
        test_fn: F,
    ) -> Result<()>
    where
        F: Fn() -> Box<dyn std::future::Future<Output = Result<()>> + Send + Unpin>,
    {
        println!("Running chaos test: {}", name);

        let mut success_count = 0;
        let mut failure_count = 0;

        for i in 0..iterations {
            let test_future = test_fn();
            let result = apply_network_chaos(&config, test_future).await;

            match result {
                Ok(_) => success_count += 1,
                Err(e) => {
                    failure_count += 1;
                    if failure_count <= 5 {
                        // Only log first few failures to avoid spam
                        eprintln!("Chaos test iteration {} failed: {}", i + 1, e);
                    }
                }
            }
        }

        let success_rate = success_count as f64 / iterations as f64;
        println!(
            "Chaos test {} completed: {}/{} succeeded ({:.2}%)",
            name,
            success_count,
            iterations,
            success_rate * 100.0
        );

        // Require at least 70% success rate under chaos conditions
        if success_rate < 0.7 {
            anyhow::bail!(
                "Chaos test {} failed: success rate {:.2}% below threshold",
                name,
                success_rate * 100.0
            );
        }

        Ok(())
    }
}

/// Load testing utilities
pub mod load {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, Instant};

    pub struct LoadTestConfig {
        pub duration: Duration,
        pub concurrent_users: usize,
        pub ramp_up_duration: Duration,
        pub target_rate: Option<f64>, // requests per second
    }

    impl Default for LoadTestConfig {
        fn default() -> Self {
            Self {
                duration: Duration::from_secs(60),
                concurrent_users: 10,
                ramp_up_duration: Duration::from_secs(10),
                target_rate: None,
            }
        }
    }

    pub struct LoadTestResults {
        pub total_requests: u64,
        pub successful_requests: u64,
        pub failed_requests: u64,
        pub average_response_time: Duration,
        pub requests_per_second: f64,
        pub error_rate: f64,
    }

    pub async fn run_load_test<F, Fut>(
        name: &str,
        config: LoadTestConfig,
        test_fn: F,
    ) -> Result<LoadTestResults>
    where
        F: Fn() -> Fut + Send + Sync + Clone + 'static,
        Fut: std::future::Future<Output = Result<Duration>> + Send + 'static,
    {
        println!("Starting load test: {}", name);

        let total_requests = Arc::new(AtomicU64::new(0));
        let successful_requests = Arc::new(AtomicU64::new(0));
        let failed_requests = Arc::new(AtomicU64::new(0));
        let total_response_time = Arc::new(AtomicU64::new(0));

        let start_time = Instant::now();
        let mut handles = Vec::new();

        // Launch concurrent workers
        for worker_id in 0..config.concurrent_users {
            let test_fn = test_fn.clone();
            let total_requests = total_requests.clone();
            let successful_requests = successful_requests.clone();
            let failed_requests = failed_requests.clone();
            let total_response_time = total_response_time.clone();

            let config = config.clone();
            let start_time = start_time;

            let handle = tokio::spawn(async move {
                // Ramp-up delay
                let ramp_delay = config.ramp_up_duration.as_millis() as u64
                    * worker_id as u64
                    / config.concurrent_users as u64;
                tokio::time::sleep(Duration::from_millis(ramp_delay)).await;

                while start_time.elapsed() < config.duration {
                    let request_start = Instant::now();
                    let result = test_fn().await;
                    let response_time = request_start.elapsed();

                    total_requests.fetch_add(1, Ordering::Relaxed);

                    match result {
                        Ok(_) => {
                            successful_requests.fetch_add(1, Ordering::Relaxed);
                            total_response_time.fetch_add(
                                response_time.as_millis() as u64,
                                Ordering::Relaxed,
                            );
                        }
                        Err(_) => {
                            failed_requests.fetch_add(1, Ordering::Relaxed);
                        }
                    }

                    // Rate limiting if specified
                    if let Some(target_rate) = config.target_rate {
                        let delay_ms = 1000.0 / target_rate / config.concurrent_users as f64;
                        tokio::time::sleep(Duration::from_millis(delay_ms as u64)).await;
                    }
                }
            });

            handles.push(handle);
        }

        // Wait for all workers to complete
        for handle in handles {
            let _ = handle.await;
        }

        let total_duration = start_time.elapsed();

        // Calculate results
        let total_reqs = total_requests.load(Ordering::Relaxed);
        let successful_reqs = successful_requests.load(Ordering::Relaxed);
        let failed_reqs = failed_requests.load(Ordering::Relaxed);
        let total_resp_time = total_response_time.load(Ordering::Relaxed);

        let results = LoadTestResults {
            total_requests: total_reqs,
            successful_requests: successful_reqs,
            failed_requests: failed_reqs,
            average_response_time: if successful_reqs > 0 {
                Duration::from_millis(total_resp_time / successful_reqs)
            } else {
                Duration::from_millis(0)
            },
            requests_per_second: total_reqs as f64 / total_duration.as_secs_f64(),
            error_rate: if total_reqs > 0 {
                failed_reqs as f64 / total_reqs as f64 * 100.0
            } else {
                0.0
            },
        };

        println!("Load test {} completed:", name);
        println!("  Total requests: {}", results.total_requests);
        println!("  Successful: {}", results.successful_requests);
        println!("  Failed: {}", results.failed_requests);
        println!("  Average response time: {:?}", results.average_response_time);
        println!("  Requests/sec: {:.2}", results.requests_per_second);
        println!("  Error rate: {:.2}%", results.error_rate);

        Ok(results)
    }
}

/// Memory and resource monitoring utilities
pub mod monitoring {
    use std::time::{Duration, Instant};

    pub struct ResourceUsage {
        pub memory_mb: f64,
        pub cpu_percent: f64,
        pub timestamp: Instant,
    }

    pub struct ResourceMonitor {
        samples: Vec<ResourceUsage>,
        start_time: Instant,
    }

    impl ResourceMonitor {
        pub fn new() -> Self {
            Self {
                samples: Vec::new(),
                start_time: Instant::now(),
            }
        }

        pub fn sample(&mut self) {
            let sys = sysinfo::System::new_all();

            self.samples.push(ResourceUsage {
                memory_mb: sys.used_memory() as f64 / 1_000_000.0,
                cpu_percent: sys.global_cpu_info().cpu_usage() as f64,
                timestamp: Instant::now(),
            });
        }

        pub async fn monitor_for_duration(&mut self, duration: Duration, interval: Duration) {
            let end_time = self.start_time + duration;

            while Instant::now() < end_time {
                self.sample();
                tokio::time::sleep(interval).await;
            }
        }

        pub fn get_peak_memory(&self) -> Option<f64> {
            self.samples
                .iter()
                .map(|s| s.memory_mb)
                .fold(None, |acc, x| Some(acc.map_or(x, |a| a.max(x))))
        }

        pub fn get_average_cpu(&self) -> Option<f64> {
            if self.samples.is_empty() {
                return None;
            }

            let sum: f64 = self.samples.iter().map(|s| s.cpu_percent).sum();
            Some(sum / self.samples.len() as f64)
        }

        pub fn print_summary(&self) {
            if self.samples.is_empty() {
                println!("No resource samples collected");
                return;
            }

            let peak_memory = self.get_peak_memory().unwrap_or(0.0);
            let avg_cpu = self.get_average_cpu().unwrap_or(0.0);

            println!("Resource usage summary:");
            println!("  Peak memory: {:.1} MB", peak_memory);
            println!("  Average CPU: {:.1}%", avg_cpu);
            println!("  Sample count: {}", self.samples.len());
        }
    }

    impl Default for ResourceMonitor {
        fn default() -> Self {
            Self::new()
        }
    }
}