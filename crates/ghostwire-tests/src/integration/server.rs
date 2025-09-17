//! Server integration tests

use crate::{
    common::{TestClient, TestServer},
    integration_test, TestConfig, TestResult, TestSuite,
};
use anyhow::Result;
use serial_test::serial;
use std::time::Duration;
use tokio::time::timeout;
use tracing::{info, warn};

pub struct ServerTestSuite;

#[async_trait::async_trait]
impl TestSuite for ServerTestSuite {
    fn name(&self) -> &str {
        "Server Integration Tests"
    }

    async fn run_tests(&self, config: &TestConfig) -> Result<Vec<TestResult>> {
        let mut results = Vec::new();

        // Test server startup and health
        let (result, duration) = crate::common::timing::measure_async(
            test_server_startup_and_health(config)
        ).await;

        match result {
            Ok(_) => results.push(TestResult::success("server_startup_health", duration.as_millis() as u64)),
            Err(e) => results.push(TestResult::failure("server_startup_health", duration.as_millis() as u64, e.to_string())),
        }

        // Test API endpoints
        let (result, duration) = crate::common::timing::measure_async(
            test_api_endpoints(config)
        ).await;

        match result {
            Ok(_) => results.push(TestResult::success("api_endpoints", duration.as_millis() as u64)),
            Err(e) => results.push(TestResult::failure("api_endpoints", duration.as_millis() as u64, e.to_string())),
        }

        // Test concurrent connections
        let (result, duration) = crate::common::timing::measure_async(
            test_concurrent_connections(config)
        ).await;

        match result {
            Ok(_) => results.push(TestResult::success("concurrent_connections", duration.as_millis() as u64)),
            Err(e) => results.push(TestResult::failure("concurrent_connections", duration.as_millis() as u64, e.to_string())),
        }

        Ok(results)
    }
}

async fn test_server_startup_and_health(_config: &TestConfig) -> Result<()> {
    info!("Testing server startup and health");

    let mut server = TestServer::new().await?;
    server.start().await?;

    let client = TestClient::new(server.base_url());

    // Test health endpoint
    let health_response = client.health_check().await?;
    if !health_response {
        anyhow::bail!("Health check failed");
    }

    // Test metrics endpoint
    let metrics_response = client.get("/metrics").await?;
    if !metrics_response.status().is_success() {
        anyhow::bail!("Metrics endpoint failed");
    }

    server.stop().await?;
    info!("Server startup and health test completed successfully");
    Ok(())
}

async fn test_api_endpoints(_config: &TestConfig) -> Result<()> {
    info!("Testing API endpoints");

    let mut server = TestServer::new().await?;
    server.start().await?;

    let client = TestClient::new(server.base_url());

    // Test API info endpoint
    let info_response = client.get("/api/v1/info").await?;
    if !info_response.status().is_success() {
        anyhow::bail!("API info endpoint failed: {}", info_response.status());
    }

    // Test machines endpoint (should be empty initially)
    let machines_response = client.get("/api/v1/machines").await?;
    if !machines_response.status().is_success() {
        anyhow::bail!("Machines endpoint failed: {}", machines_response.status());
    }

    // Test network map endpoint
    let netmap_response = client.get("/api/v1/network/map").await?;
    if !netmap_response.status().is_success() {
        anyhow::bail!("Network map endpoint failed: {}", netmap_response.status());
    }

    server.stop().await?;
    info!("API endpoints test completed successfully");
    Ok(())
}

async fn test_concurrent_connections(_config: &TestConfig) -> Result<()> {
    info!("Testing concurrent connections");

    let mut server = TestServer::new().await?;
    server.start().await?;

    let base_url = server.base_url();
    let concurrent_requests = 50;
    let mut handles = Vec::new();

    // Launch concurrent health check requests
    for i in 0..concurrent_requests {
        let url = base_url.clone();
        let handle = tokio::spawn(async move {
            let client = TestClient::new(url);
            let result = timeout(Duration::from_secs(10), client.health_check()).await;
            match result {
                Ok(Ok(true)) => Ok(()),
                Ok(Ok(false)) => Err(anyhow::anyhow!("Health check {} failed", i)),
                Ok(Err(e)) => Err(e),
                Err(_) => Err(anyhow::anyhow!("Health check {} timed out", i)),
            }
        });
        handles.push(handle);
    }

    // Wait for all requests to complete
    let mut success_count = 0;
    let mut failure_count = 0;

    for handle in handles {
        match handle.await {
            Ok(Ok(())) => success_count += 1,
            Ok(Err(e)) => {
                warn!("Concurrent request failed: {}", e);
                failure_count += 1;
            },
            Err(e) => {
                warn!("Task failed: {}", e);
                failure_count += 1;
            },
        }
    }

    server.stop().await?;

    info!("Concurrent connections test: {}/{} succeeded", success_count, concurrent_requests);

    // Allow some failures but require majority to succeed
    if success_count < (concurrent_requests * 80 / 100) {
        anyhow::bail!("Too many concurrent requests failed: {}/{}", failure_count, concurrent_requests);
    }

    Ok(())
}

// Individual test functions for use in other contexts
integration_test!(
    test_server_health_endpoint,
    || async { Ok(()) },
    || async {
        let mut server = TestServer::new().await?;
        server.start().await?;

        let client = TestClient::new(server.base_url());
        let health = client.health_check().await?;

        server.stop().await?;

        if !health {
            anyhow::bail!("Health check failed");
        }

        Ok(())
    },
    || async { Ok(()) }
);

integration_test!(
    test_server_metrics_endpoint,
    || async { Ok(()) },
    || async {
        let mut server = TestServer::new().await?;
        server.start().await?;

        let client = TestClient::new(server.base_url());
        let response = client.get("/metrics").await?;

        server.stop().await?;

        if !response.status().is_success() {
            anyhow::bail!("Metrics endpoint returned: {}", response.status());
        }

        let content = response.text().await?;
        if !content.contains("# HELP") {
            anyhow::bail!("Metrics content doesn't look like Prometheus format");
        }

        Ok(())
    },
    || async { Ok(()) }
);

#[tokio::test]
#[serial]
async fn test_server_startup_performance() {
    crate::init_test_env();

    let iterations = 5;
    let mut startup_times = Vec::new();

    for i in 0..iterations {
        info!("Server startup performance test iteration {}/{}", i + 1, iterations);

        let start = std::time::Instant::now();
        let mut server = TestServer::new().await.expect("Failed to create server");
        server.start().await.expect("Failed to start server");
        let startup_duration = start.elapsed();

        let client = TestClient::new(server.base_url());
        let health = client.health_check().await.expect("Health check failed");
        assert!(health, "Server should be healthy after startup");

        server.stop().await.expect("Failed to stop server");

        startup_times.push(startup_duration);
        info!("Startup {} took {:?}", i + 1, startup_duration);
    }

    let average_startup = startup_times.iter().sum::<Duration>() / startup_times.len() as u32;
    let max_startup = startup_times.iter().max().unwrap();
    let min_startup = startup_times.iter().min().unwrap();

    info!("Server startup performance summary:");
    info!("  Average: {:?}", average_startup);
    info!("  Min: {:?}", min_startup);
    info!("  Max: {:?}", max_startup);

    // Server should start within reasonable time
    assert!(average_startup < Duration::from_secs(10), "Server startup took too long: {:?}", average_startup);
}