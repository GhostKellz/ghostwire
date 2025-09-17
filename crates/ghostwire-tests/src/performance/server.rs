//! Server performance benchmarks

use crate::{
    common::{TestClient, TestServer},
    performance::{BenchmarkConfig, PerformanceMetrics},
    performance_test, TestConfig, TestResult, TestSuite,
};
use anyhow::Result;
use std::time::{Duration, Instant};
use tracing::info;

pub struct ServerPerformanceTestSuite;

#[async_trait::async_trait]
impl TestSuite for ServerPerformanceTestSuite {
    fn name(&self) -> &str {
        "Server Performance Tests"
    }

    async fn run_tests(&self, _config: &TestConfig) -> Result<Vec<TestResult>> {
        let mut results = Vec::new();

        // Test server startup time
        let (result, duration) = crate::common::timing::measure_async(
            test_server_startup_time()
        ).await;

        match result {
            Ok(startup_time) => {
                let mut test_result = TestResult::success("server_startup_time", duration.as_millis() as u64);
                test_result = test_result.with_metric("startup_time_ms", startup_time as f64);
                results.push(test_result);
            }
            Err(e) => results.push(TestResult::failure("server_startup_time", duration.as_millis() as u64, e.to_string())),
        }

        // Test memory usage under load
        let (result, duration) = crate::common::timing::measure_async(
            test_memory_usage_under_load()
        ).await;

        match result {
            Ok(memory_usage) => {
                let mut test_result = TestResult::success("memory_usage_load", duration.as_millis() as u64);
                test_result = test_result.with_metric("memory_usage_mb", memory_usage as f64 / 1_000_000.0);
                results.push(test_result);
            }
            Err(e) => results.push(TestResult::failure("memory_usage_load", duration.as_millis() as u64, e.to_string())),
        }

        Ok(results)
    }
}

async fn test_server_startup_time() -> Result<u64> {
    info!("Benchmarking server startup time");

    let iterations = 10;
    let mut startup_times = Vec::new();

    for i in 0..iterations {
        info!("Startup iteration {}/{}", i + 1, iterations);

        let start = Instant::now();
        let mut server = TestServer::new().await?;
        server.start().await?;
        let startup_time = start.elapsed();

        // Verify server is actually ready
        let client = TestClient::new(server.base_url());
        let health = client.health_check().await?;
        if !health {
            anyhow::bail!("Server failed health check after startup");
        }

        server.stop().await?;
        startup_times.push(startup_time.as_millis() as u64);
    }

    let avg_startup = startup_times.iter().sum::<u64>() / startup_times.len() as u64;
    let min_startup = *startup_times.iter().min().unwrap();
    let max_startup = *startup_times.iter().max().unwrap();

    info!("Server startup times - avg: {}ms, min: {}ms, max: {}ms", avg_startup, min_startup, max_startup);

    Ok(avg_startup)
}

async fn test_memory_usage_under_load() -> Result<u64> {
    info!("Benchmarking memory usage under load");

    let mut server = TestServer::new().await?;
    server.start().await?;

    let client = TestClient::new(server.base_url());

    // Get baseline memory usage
    let sys = sysinfo::System::new_all();
    let baseline_memory = sys.used_memory();

    // Generate load for 30 seconds
    let load_duration = Duration::from_secs(30);
    let concurrent_requests = 20;

    let mut handles = Vec::new();
    let base_url = server.base_url();

    for _ in 0..concurrent_requests {
        let url = base_url.clone();
        let handle = tokio::spawn(async move {
            let client = TestClient::new(url);
            let start = Instant::now();

            while start.elapsed() < load_duration {
                let _ = client.get("/api/v1/info").await;
                let _ = client.get("/api/v1/machines").await;
                let _ = client.get("/health").await;
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        });
        handles.push(handle);
    }

    // Wait for load to complete
    for handle in handles {
        let _ = handle.await;
    }

    // Measure memory usage after load
    let sys = sysinfo::System::new_all();
    let peak_memory = sys.used_memory();
    let memory_increase = peak_memory.saturating_sub(baseline_memory);

    server.stop().await?;

    info!("Memory usage under load: {} MB increase", memory_increase / 1_000_000);

    Ok(memory_increase)
}

performance_test!(
    benchmark_request_handling,
    || async { Ok(()) },
    |config: &BenchmarkConfig| async move {
        let mut server = TestServer::new().await?;
        server.start().await?;

        let client = TestClient::new(server.base_url());
        let iterations = config.iterations;
        let mut latencies = Vec::with_capacity(iterations);

        let start = Instant::now();

        for _ in 0..iterations {
            let request_start = Instant::now();

            let response = client.get("/api/v1/info").await?;
            if !response.status().is_success() {
                anyhow::bail!("Request failed: {}", response.status());
            }

            latencies.push(request_start.elapsed());
        }

        let total_duration = start.elapsed();
        server.stop().await?;

        Ok(PerformanceMetrics::from_latencies(&latencies, total_duration))
    },
    || async { Ok(()) }
);

performance_test!(
    benchmark_database_operations,
    || async { Ok(()) },
    |config: &BenchmarkConfig| async move {
        let mut server = TestServer::new().await?;
        server.start().await?;

        let client = TestClient::new(server.base_url());

        // Perform database-heavy operations
        let iterations = config.iterations.min(100); // Limit for database tests
        let mut latencies = Vec::with_capacity(iterations);

        let start = Instant::now();

        for i in 0..iterations {
            let operation_start = Instant::now();

            // Register and then delete a machine (database operations)
            use crate::common::TestFixtures;
            use ghostwire_common::types::{MachineInfo, RegisterRequest};

            let machine_info = MachineInfo {
                machine_key: TestFixtures::machine_key(),
                node_key: TestFixtures::node_key(),
                hostname: format!("bench-machine-{}", i),
                ipv4: format!("192.168.1.{}", 100 + (i % 150)).parse().unwrap(),
                ipv6: None,
                endpoints: vec![format!("192.168.1.{}:41641", 100 + (i % 150)).parse().unwrap()],
                derp_region: 1,
                os: "linux".to_string(),
                tags: vec![],
                capabilities: vec![],
            };

            let register_request = RegisterRequest {
                machine_info: machine_info.clone(),
                auth_token: format!("bench-token-{}", i),
            };

            // Register machine
            let register_response = client.post_json("/api/v1/machines/register", &register_request).await?;
            if !register_response.status().is_success() {
                anyhow::bail!("Failed to register machine: {}", register_response.status());
            }

            // Delete machine
            let delete_response = client.delete(&format!("/api/v1/machines/{}", machine_info.machine_key)).await?;
            if !delete_response.status().is_success() {
                anyhow::bail!("Failed to delete machine: {}", delete_response.status());
            }

            latencies.push(operation_start.elapsed());
        }

        let total_duration = start.elapsed();
        server.stop().await?;

        Ok(PerformanceMetrics::from_latencies(&latencies, total_duration))
    },
    || async { Ok(()) }
);

#[tokio::test]
async fn benchmark_server_resource_usage() {
    crate::init_test_env();

    info!("Benchmarking server resource usage patterns");

    let mut server = TestServer::new().await.expect("Failed to create server");
    server.start().await.expect("Failed to start server");

    let client = TestClient::new(server.base_url());

    // Monitor resource usage over time
    let monitoring_duration = Duration::from_secs(60);
    let sample_interval = Duration::from_secs(5);
    let mut memory_samples = Vec::new();
    let mut cpu_samples = Vec::new();

    let start = Instant::now();

    // Generate background load
    let load_handle = tokio::spawn({
        let client = client.clone();
        async move {
            let mut request_count = 0;
            while start.elapsed() < monitoring_duration {
                let _ = client.get("/api/v1/info").await;
                let _ = client.get("/health").await;
                request_count += 1;

                if request_count % 10 == 0 {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                } else {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
            request_count
        }
    });

    // Sample resource usage
    while start.elapsed() < monitoring_duration {
        let sys = sysinfo::System::new_all();
        memory_samples.push(sys.used_memory() as f64 / 1_000_000.0); // MB
        cpu_samples.push(sys.global_cpu_info().cpu_usage() as f64);

        tokio::time::sleep(sample_interval).await;
    }

    let request_count = load_handle.await.expect("Load task failed");
    server.stop().await.expect("Failed to stop server");

    // Analyze resource usage
    let avg_memory = memory_samples.iter().sum::<f64>() / memory_samples.len() as f64;
    let max_memory = memory_samples.iter().fold(0.0f64, |a, &b| a.max(b));
    let min_memory = memory_samples.iter().fold(f64::INFINITY, |a, &b| a.min(b));

    let avg_cpu = cpu_samples.iter().sum::<f64>() / cpu_samples.len() as f64;
    let max_cpu = cpu_samples.iter().fold(0.0f64, |a, &b| a.max(b));

    info!("Resource usage summary over {}s with {} requests:", monitoring_duration.as_secs(), request_count);
    info!("  Memory: avg {:.1}MB, min {:.1}MB, max {:.1}MB", avg_memory, min_memory, max_memory);
    info!("  CPU: avg {:.1}%, max {:.1}%", avg_cpu, max_cpu);

    // Basic sanity checks
    assert!(avg_memory > 0.0, "Memory usage should be measurable");
    assert!(max_memory < 1000.0, "Memory usage should be reasonable (< 1GB)");
}