//! Network performance benchmarks

use crate::{
    common::{network, TestClient, TestServer},
    performance::{BenchmarkConfig, PerformanceMetrics},
    performance_test, TestConfig, TestResult, TestSuite,
};
use anyhow::Result;
use std::time::{Duration, Instant};
use tokio::time::timeout;
use tracing::info;

pub struct NetworkPerformanceTestSuite;

#[async_trait::async_trait]
impl TestSuite for NetworkPerformanceTestSuite {
    fn name(&self) -> &str {
        "Network Performance Tests"
    }

    async fn run_tests(&self, _config: &TestConfig) -> Result<Vec<TestResult>> {
        let mut results = Vec::new();

        // Test connection establishment performance
        let (result, duration) = crate::common::timing::measure_async(
            test_connection_establishment_performance()
        ).await;

        match result {
            Ok(metrics) => {
                let mut test_result = TestResult::success("connection_establishment", duration.as_millis() as u64);
                test_result = test_result.with_metric("ops_per_sec", metrics.ops_per_sec);
                test_result = test_result.with_metric("avg_latency_ms", metrics.avg_latency_ms);
                results.push(test_result);
            }
            Err(e) => results.push(TestResult::failure("connection_establishment", duration.as_millis() as u64, e.to_string())),
        }

        // Test API throughput
        let (result, duration) = crate::common::timing::measure_async(
            test_api_throughput()
        ).await;

        match result {
            Ok(metrics) => {
                let mut test_result = TestResult::success("api_throughput", duration.as_millis() as u64);
                test_result = test_result.with_metric("ops_per_sec", metrics.ops_per_sec);
                test_result = test_result.with_metric("avg_latency_ms", metrics.avg_latency_ms);
                results.push(test_result);
            }
            Err(e) => results.push(TestResult::failure("api_throughput", duration.as_millis() as u64, e.to_string())),
        }

        Ok(results)
    }
}

async fn test_connection_establishment_performance() -> Result<PerformanceMetrics> {
    info!("Benchmarking connection establishment performance");

    let mut server = TestServer::new().await?;
    server.start().await?;

    let base_url = server.base_url();
    let iterations = 100;
    let mut latencies = Vec::with_capacity(iterations);

    let start = Instant::now();

    for _ in 0..iterations {
        let connect_start = Instant::now();
        let client = TestClient::new(base_url.clone());

        // Measure time to first successful request
        let health = timeout(Duration::from_secs(5), client.health_check()).await
            .map_err(|_| anyhow::anyhow!("Health check timed out"))?
            .map_err(|e| anyhow::anyhow!("Health check failed: {}", e))?;

        if !health {
            anyhow::bail!("Health check returned false");
        }

        latencies.push(connect_start.elapsed());
    }

    let total_duration = start.elapsed();
    server.stop().await?;

    let metrics = PerformanceMetrics::from_latencies(&latencies, total_duration);

    info!("Connection establishment: {:.2} connections/sec, avg {:.2}ms", metrics.ops_per_sec, metrics.avg_latency_ms);

    Ok(metrics)
}

async fn test_api_throughput() -> Result<PerformanceMetrics> {
    info!("Benchmarking API throughput");

    let mut server = TestServer::new().await?;
    server.start().await?;

    let client = TestClient::new(server.base_url());
    let duration = Duration::from_secs(10);
    let mut latencies = Vec::new();

    let start = Instant::now();

    while start.elapsed() < duration {
        let request_start = Instant::now();
        let response = client.get("/api/v1/info").await?;

        if !response.status().is_success() {
            anyhow::bail!("API request failed: {}", response.status());
        }

        latencies.push(request_start.elapsed());
    }

    let total_duration = start.elapsed();
    server.stop().await?;

    let metrics = PerformanceMetrics::from_latencies(&latencies, total_duration);

    info!("API throughput: {:.2} requests/sec, avg {:.2}ms", metrics.ops_per_sec, metrics.avg_latency_ms);

    Ok(metrics)
}

performance_test!(
    benchmark_concurrent_api_requests,
    || async { Ok(()) },
    |config: &BenchmarkConfig| async move {
        let mut server = TestServer::new().await?;
        server.start().await?;

        let base_url = server.base_url();
        let concurrent_clients = config.concurrency;
        let requests_per_client = 100;

        let mut handles = Vec::new();

        let start = Instant::now();

        // Launch concurrent clients
        for _ in 0..concurrent_clients {
            let url = base_url.clone();
            let handle = tokio::spawn(async move {
                let client = TestClient::new(url);
                let mut client_latencies = Vec::new();

                for _ in 0..requests_per_client {
                    let request_start = Instant::now();
                    let result = client.get("/api/v1/info").await;
                    let latency = request_start.elapsed();

                    match result {
                        Ok(response) if response.status().is_success() => {
                            client_latencies.push(latency);
                        }
                        _ => return Err(anyhow::anyhow!("Request failed")),
                    }
                }

                Ok(client_latencies)
            });
            handles.push(handle);
        }

        // Collect results
        let mut all_latencies = Vec::new();
        for handle in handles {
            let client_latencies = handle.await??;
            all_latencies.extend(client_latencies);
        }

        let total_duration = start.elapsed();
        server.stop().await?;

        Ok(PerformanceMetrics::from_latencies(&all_latencies, total_duration))
    },
    || async { Ok(()) }
);

performance_test!(
    benchmark_udp_echo_latency,
    || async { Ok(()) },
    |config: &BenchmarkConfig| async move {
        use tokio::net::UdpSocket;

        let server_addr = "127.0.0.1:0";
        let server_socket = UdpSocket::bind(server_addr).await?;
        let server_addr = server_socket.local_addr()?;

        // Start echo server
        let server_handle = tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            loop {
                match server_socket.recv_from(&mut buf).await {
                    Ok((len, addr)) => {
                        let _ = server_socket.send_to(&buf[..len], addr).await;
                    }
                    Err(_) => break,
                }
            }
        });

        // Client sends echo requests
        let client_socket = UdpSocket::bind("127.0.0.1:0").await?;
        client_socket.connect(server_addr).await?;

        let message = b"ping";
        let iterations = config.iterations;
        let mut latencies = Vec::with_capacity(iterations);

        let start = Instant::now();

        for _ in 0..iterations {
            let send_start = Instant::now();

            client_socket.send(message).await?;

            let mut buf = [0u8; 4];
            let _ = timeout(Duration::from_millis(100), client_socket.recv(&mut buf)).await?;

            latencies.push(send_start.elapsed());
        }

        let total_duration = start.elapsed();

        server_handle.abort();

        Ok(PerformanceMetrics::from_latencies(&latencies, total_duration))
    },
    || async { Ok(()) }
);

#[tokio::test]
async fn benchmark_mesh_connection_scaling() {
    crate::init_test_env();

    let mut server = TestServer::new().await.expect("Failed to create server");
    server.start().await.expect("Failed to start server");

    let client = TestClient::new(server.base_url());
    let node_counts = vec![1, 2, 5, 10, 20];

    info!("Benchmarking mesh connection scaling:");

    for &node_count in &node_counts {
        // Clean up previous nodes
        let machines_response = client.get("/api/v1/machines").await.expect("Failed to get machines");
        let machines: Vec<serde_json::Value> = machines_response.json().await.expect("Failed to parse machines");

        for machine in machines {
            if let Some(key) = machine.get("machine_key").and_then(|k| k.as_str()) {
                let _ = client.delete(&format!("/api/v1/machines/{}", key)).await;
            }
        }

        let start = Instant::now();

        // Register nodes
        for i in 0..node_count {
            use crate::common::TestFixtures;
            use ghostwire_common::types::{MachineInfo, RegisterRequest};

            let machine_info = MachineInfo {
                machine_key: TestFixtures::machine_key(),
                node_key: TestFixtures::node_key(),
                hostname: format!("scale-test-{}", i),
                ipv4: format!("192.168.1.{}", 50 + i).parse().unwrap(),
                ipv6: None,
                endpoints: vec![format!("192.168.1.{}:41641", 50 + i).parse().unwrap()],
                derp_region: 1,
                os: "linux".to_string(),
                tags: vec![],
                capabilities: vec![],
            };

            let register_request = RegisterRequest {
                machine_info,
                auth_token: format!("scale-token-{}", i),
            };

            let response = client.post_json("/api/v1/machines/register", &register_request).await
                .expect("Failed to register machine");

            if !response.status().is_success() {
                panic!("Failed to register machine {}: {}", i, response.status());
            }
        }

        let registration_time = start.elapsed();

        // Measure network map generation time
        let netmap_start = Instant::now();
        let netmap_response = client.get("/api/v1/network/map").await
            .expect("Failed to get network map");

        if !netmap_response.status().is_success() {
            panic!("Failed to get network map for {} nodes: {}", node_count, netmap_response.status());
        }

        let netmap_time = netmap_start.elapsed();

        info!(
            "  {} nodes: registration {:?}, netmap {:?}",
            node_count, registration_time, netmap_time
        );
    }

    server.stop().await.expect("Failed to stop server");
}