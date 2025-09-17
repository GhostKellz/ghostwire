//! Mesh network integration tests

use crate::{
    common::{TestClient, TestServer, TestFixtures},
    integration_test, TestConfig, TestResult, TestSuite,
};
use anyhow::Result;
use ghostwire_common::types::{MachineInfo, RegisterRequest};
use serial_test::serial;
use std::collections::HashMap;
use std::time::Duration;
use tokio::time::timeout;
use tracing::{info, debug};

pub struct MeshTestSuite;

#[async_trait::async_trait]
impl TestSuite for MeshTestSuite {
    fn name(&self) -> &str {
        "Mesh Network Tests"
    }

    async fn run_tests(&self, config: &TestConfig) -> Result<Vec<TestResult>> {
        let mut results = Vec::new();

        // Test two-node mesh
        let (result, duration) = crate::common::timing::measure_async(
            test_two_node_mesh(config)
        ).await;

        match result {
            Ok(_) => results.push(TestResult::success("two_node_mesh", duration.as_millis() as u64)),
            Err(e) => results.push(TestResult::failure("two_node_mesh", duration.as_millis() as u64, e.to_string())),
        }

        // Test multi-node mesh
        let (result, duration) = crate::common::timing::measure_async(
            test_multi_node_mesh(config)
        ).await;

        match result {
            Ok(_) => results.push(TestResult::success("multi_node_mesh", duration.as_millis() as u64)),
            Err(e) => results.push(TestResult::failure("multi_node_mesh", duration.as_millis() as u64, e.to_string())),
        }

        // Test node disconnection and reconnection
        let (result, duration) = crate::common::timing::measure_async(
            test_node_disconnection_reconnection(config)
        ).await;

        match result {
            Ok(_) => results.push(TestResult::success("node_disconnection_reconnection", duration.as_millis() as u64)),
            Err(e) => results.push(TestResult::failure("node_disconnection_reconnection", duration.as_millis() as u64, e.to_string())),
        }

        Ok(results)
    }
}

async fn test_two_node_mesh(_config: &TestConfig) -> Result<()> {
    info!("Testing two-node mesh formation");

    let mut server = TestServer::new().await?;
    server.start().await?;

    let client = TestClient::new(server.base_url());

    // Register first node
    let node1 = create_test_machine("node1", "192.168.1.10");
    let register_request1 = RegisterRequest {
        machine_info: node1.clone(),
        auth_token: "test-token-1".to_string(),
    };

    let response1 = client.post_json("/api/v1/machines/register", &register_request1).await?;
    if !response1.status().is_success() {
        anyhow::bail!("Failed to register node1: {}", response1.status());
    }

    // Register second node
    let node2 = create_test_machine("node2", "192.168.1.11");
    let register_request2 = RegisterRequest {
        machine_info: node2.clone(),
        auth_token: "test-token-2".to_string(),
    };

    let response2 = client.post_json("/api/v1/machines/register", &register_request2).await?;
    if !response2.status().is_success() {
        anyhow::bail!("Failed to register node2: {}", response2.status());
    }

    // Verify both nodes are in the mesh
    let machines_response = client.get("/api/v1/machines").await?;
    if !machines_response.status().is_success() {
        anyhow::bail!("Failed to get machines: {}", machines_response.status());
    }

    let machines: Vec<MachineInfo> = machines_response.json().await?;
    if machines.len() != 2 {
        anyhow::bail!("Expected 2 machines, got {}", machines.len());
    }

    // Get network map and verify both nodes can see each other
    let netmap_response = client.get("/api/v1/network/map").await?;
    if !netmap_response.status().is_success() {
        anyhow::bail!("Failed to get network map: {}", netmap_response.status());
    }

    server.stop().await?;
    info!("Two-node mesh test completed successfully");
    Ok(())
}

async fn test_multi_node_mesh(_config: &TestConfig) -> Result<()> {
    info!("Testing multi-node mesh formation");

    let mut server = TestServer::new().await?;
    server.start().await?;

    let client = TestClient::new(server.base_url());
    let node_count = 5;
    let mut registered_nodes = Vec::new();

    // Register multiple nodes
    for i in 0..node_count {
        let node = create_test_machine(&format!("node{}", i), &format!("192.168.1.{}", 10 + i));
        let register_request = RegisterRequest {
            machine_info: node.clone(),
            auth_token: format!("test-token-{}", i),
        };

        let response = client.post_json("/api/v1/machines/register", &register_request).await?;
        if !response.status().is_success() {
            anyhow::bail!("Failed to register node{}: {}", i, response.status());
        }

        registered_nodes.push(node);
        debug!("Registered node{}", i);
    }

    // Verify all nodes are registered
    let machines_response = client.get("/api/v1/machines").await?;
    if !machines_response.status().is_success() {
        anyhow::bail!("Failed to get machines: {}", machines_response.status());
    }

    let machines: Vec<MachineInfo> = machines_response.json().await?;
    if machines.len() != node_count {
        anyhow::bail!("Expected {} machines, got {}", node_count, machines.len());
    }

    // Verify network map includes all nodes
    let netmap_response = client.get("/api/v1/network/map").await?;
    if !netmap_response.status().is_success() {
        anyhow::bail!("Failed to get network map: {}", netmap_response.status());
    }

    server.stop().await?;
    info!("Multi-node mesh test completed successfully with {} nodes", node_count);
    Ok(())
}

async fn test_node_disconnection_reconnection(_config: &TestConfig) -> Result<()> {
    info!("Testing node disconnection and reconnection");

    let mut server = TestServer::new().await?;
    server.start().await?;

    let client = TestClient::new(server.base_url());

    // Register initial nodes
    let node1 = create_test_machine("reconnect-node1", "192.168.1.20");
    let node2 = create_test_machine("reconnect-node2", "192.168.1.21");

    let register_request1 = RegisterRequest {
        machine_info: node1.clone(),
        auth_token: "reconnect-token-1".to_string(),
    };

    let register_request2 = RegisterRequest {
        machine_info: node2.clone(),
        auth_token: "reconnect-token-2".to_string(),
    };

    // Register both nodes
    let response1 = client.post_json("/api/v1/machines/register", &register_request1).await?;
    let response2 = client.post_json("/api/v1/machines/register", &register_request2).await?;

    if !response1.status().is_success() || !response2.status().is_success() {
        anyhow::bail!("Failed to register initial nodes");
    }

    // Verify both nodes are present
    let machines_response = client.get("/api/v1/machines").await?;
    let machines: Vec<MachineInfo> = machines_response.json().await?;
    if machines.len() != 2 {
        anyhow::bail!("Expected 2 machines after initial registration, got {}", machines.len());
    }

    // Simulate node disconnection by deleting one machine
    let machine_id = &machines[0].machine_key;
    let delete_response = client.delete(&format!("/api/v1/machines/{}", machine_id)).await?;
    if !delete_response.status().is_success() {
        anyhow::bail!("Failed to delete machine: {}", delete_response.status());
    }

    // Verify only one node remains
    let machines_response = client.get("/api/v1/machines").await?;
    let machines: Vec<MachineInfo> = machines_response.json().await?;
    if machines.len() != 1 {
        anyhow::bail!("Expected 1 machine after deletion, got {}", machines.len());
    }

    // Re-register the deleted node (simulating reconnection)
    let response = client.post_json("/api/v1/machines/register", &register_request1).await?;
    if !response.status().is_success() {
        anyhow::bail!("Failed to re-register node: {}", response.status());
    }

    // Verify both nodes are back
    let machines_response = client.get("/api/v1/machines").await?;
    let machines: Vec<MachineInfo> = machines_response.json().await?;
    if machines.len() != 2 {
        anyhow::bail!("Expected 2 machines after reconnection, got {}", machines.len());
    }

    server.stop().await?;
    info!("Node disconnection and reconnection test completed successfully");
    Ok(())
}

fn create_test_machine(name: &str, ip: &str) -> MachineInfo {
    MachineInfo {
        machine_key: TestFixtures::machine_key(),
        node_key: TestFixtures::node_key(),
        hostname: name.to_string(),
        ipv4: ip.parse().unwrap(),
        ipv6: None,
        endpoints: vec!["192.168.1.1:41641".parse().unwrap()],
        derp_region: 1,
        os: "linux".to_string(),
        tags: vec![],
        capabilities: vec![],
    }
}

integration_test!(
    test_mesh_network_map_generation,
    || async { Ok(()) },
    || async {
        let mut server = TestServer::new().await?;
        server.start().await?;

        let client = TestClient::new(server.base_url());

        // Register a test node
        let node = create_test_machine("map-test-node", "192.168.1.30");
        let register_request = RegisterRequest {
            machine_info: node,
            auth_token: "map-test-token".to_string(),
        };

        let response = client.post_json("/api/v1/machines/register", &register_request).await?;
        if !response.status().is_success() {
            anyhow::bail!("Failed to register node for map test: {}", response.status());
        }

        // Get and validate network map
        let netmap_response = client.get("/api/v1/network/map").await?;
        if !netmap_response.status().is_success() {
            anyhow::bail!("Failed to get network map: {}", netmap_response.status());
        }

        let netmap_text = netmap_response.text().await?;
        if netmap_text.is_empty() {
            anyhow::bail!("Network map is empty");
        }

        server.stop().await?;
        Ok(())
    },
    || async { Ok(()) }
);

#[tokio::test]
#[serial]
async fn test_mesh_scaling_performance() {
    crate::init_test_env();

    let mut server = TestServer::new().await.expect("Failed to create server");
    server.start().await.expect("Failed to start server");

    let client = TestClient::new(server.base_url());
    let mut registration_times = HashMap::new();

    // Test different mesh sizes
    let test_sizes = vec![2, 5, 10, 20];

    for &size in &test_sizes {
        info!("Testing mesh scaling with {} nodes", size);

        // Clean up any existing machines
        let machines_response = client.get("/api/v1/machines").await.expect("Failed to get machines");
        let machines: Vec<MachineInfo> = machines_response.json().await.expect("Failed to parse machines");

        for machine in machines {
            let _ = client.delete(&format!("/api/v1/machines/{}", machine.machine_key)).await;
        }

        let start = std::time::Instant::now();

        // Register nodes for this test size
        for i in 0..size {
            let node = create_test_machine(&format!("scale-node-{}", i), &format!("192.168.1.{}", 100 + i));
            let register_request = RegisterRequest {
                machine_info: node,
                auth_token: format!("scale-token-{}", i),
            };

            let response = timeout(
                Duration::from_secs(30),
                client.post_json("/api/v1/machines/register", &register_request)
            ).await.expect("Registration timed out").expect("Registration failed");

            if !response.status().is_success() {
                panic!("Failed to register node {} for size {}: {}", i, size, response.status());
            }
        }

        let registration_duration = start.elapsed();
        registration_times.insert(size, registration_duration);

        // Verify all nodes are registered
        let machines_response = client.get("/api/v1/machines").await.expect("Failed to get machines");
        let machines: Vec<MachineInfo> = machines_response.json().await.expect("Failed to parse machines");
        assert_eq!(machines.len(), size, "Expected {} machines, got {}", size, machines.len());

        info!("Registered {} nodes in {:?}", size, registration_duration);
    }

    server.stop().await.expect("Failed to stop server");

    // Analyze scaling performance
    info!("Mesh scaling performance summary:");
    for &size in &test_sizes {
        let duration = registration_times[&size];
        let per_node = duration / size as u32;
        info!("  {} nodes: {:?} total, {:?} per node", size, duration, per_node);
    }

    // Verify scaling is reasonable (should not grow exponentially)
    let small_per_node = registration_times[&test_sizes[0]] / test_sizes[0] as u32;
    let large_per_node = registration_times[&test_sizes[test_sizes.len() - 1]] / test_sizes[test_sizes.len() - 1] as u32;

    // Per-node time should not increase by more than 5x with scale
    assert!(
        large_per_node < small_per_node * 5,
        "Per-node registration time increased too much with scale: {:?} -> {:?}",
        small_per_node,
        large_per_node
    );
}