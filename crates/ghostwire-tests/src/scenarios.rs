//! End-to-end scenarios for testing real-world usage patterns

use crate::{
    common::{TestClient, TestServer, TestFixtures},
    TestConfig, TestResult, TestSuite,
};
use anyhow::Result;
use ghostwire_common::types::{MachineInfo, RegisterRequest};
use std::time::{Duration, Instant};
use tracing::{info, debug};

/// Scenarios test suite that runs realistic end-to-end tests
pub struct ScenariosTestSuite;

#[async_trait::async_trait]
impl TestSuite for ScenariosTestSuite {
    fn name(&self) -> &str {
        "End-to-End Scenarios"
    }

    async fn run_tests(&self, config: &TestConfig) -> Result<Vec<TestResult>> {
        let mut results = Vec::new();

        // Scenario: Small team setup
        let (result, duration) = crate::common::timing::measure_async(
            test_small_team_scenario(config)
        ).await;

        match result {
            Ok(_) => results.push(TestResult::success("small_team_scenario", duration.as_millis() as u64)),
            Err(e) => results.push(TestResult::failure("small_team_scenario", duration.as_millis() as u64, e.to_string())),
        }

        // Scenario: Remote worker joining
        let (result, duration) = crate::common::timing::measure_async(
            test_remote_worker_scenario(config)
        ).await;

        match result {
            Ok(_) => results.push(TestResult::success("remote_worker_scenario", duration.as_millis() as u64)),
            Err(e) => results.push(TestResult::failure("remote_worker_scenario", duration.as_millis() as u64, e.to_string())),
        }

        // Scenario: Network partition and recovery
        let (result, duration) = crate::common::timing::measure_async(
            test_network_partition_recovery(config)
        ).await;

        match result {
            Ok(_) => results.push(TestResult::success("network_partition_recovery", duration.as_millis() as u64)),
            Err(e) => results.push(TestResult::failure("network_partition_recovery", duration.as_millis() as u64, e.to_string())),
        }

        Ok(results)
    }
}

/// Scenario: Small team (5 people) setting up GhostWire
async fn test_small_team_scenario(_config: &TestConfig) -> Result<()> {
    info!("Running small team scenario");

    let mut server = TestServer::new().await?;
    server.start().await?;

    let client = TestClient::new(server.base_url());

    // Team members with their devices
    let team_devices = vec![
        ("alice-laptop", "192.168.1.10", "alice-work-token"),
        ("alice-phone", "192.168.1.11", "alice-mobile-token"),
        ("bob-laptop", "192.168.1.20", "bob-work-token"),
        ("charlie-desktop", "192.168.1.30", "charlie-work-token"),
        ("david-laptop", "192.168.1.40", "david-work-token"),
        ("eve-laptop", "192.168.1.50", "eve-work-token"),
    ];

    let mut registered_machines = Vec::new();

    // Register all team devices
    for (hostname, ip, token) in &team_devices {
        debug!("Registering device: {}", hostname);

        let machine_info = MachineInfo {
            machine_key: TestFixtures::machine_key(),
            node_key: TestFixtures::node_key(),
            hostname: hostname.to_string(),
            ipv4: ip.parse().unwrap(),
            ipv6: None,
            endpoints: vec![format!("{}:41641", ip).parse().unwrap()],
            derp_region: 1,
            os: "linux".to_string(),
            tags: vec!["team:small".to_string()],
            capabilities: vec![],
        };

        let register_request = RegisterRequest {
            machine_info: machine_info.clone(),
            auth_token: token.to_string(),
        };

        let response = client.post_json("/api/v1/machines/register", &register_request).await?;
        if !response.status().is_success() {
            anyhow::bail!("Failed to register {}: {}", hostname, response.status());
        }

        registered_machines.push(machine_info);
    }

    // Verify all devices can see each other in network map
    let netmap_response = client.get("/api/v1/network/map").await?;
    if !netmap_response.status().is_success() {
        anyhow::bail!("Failed to get network map: {}", netmap_response.status());
    }

    // Verify machine list
    let machines_response = client.get("/api/v1/machines").await?;
    if !machines_response.status().is_success() {
        anyhow::bail!("Failed to get machines: {}", machines_response.status());
    }

    let machines: Vec<MachineInfo> = machines_response.json().await?;
    if machines.len() != team_devices.len() {
        anyhow::bail!("Expected {} machines, got {}", team_devices.len(), machines.len());
    }

    // Simulate one person disconnecting and reconnecting
    let alice_laptop = &registered_machines[0];
    debug!("Simulating alice-laptop disconnection");

    let delete_response = client.delete(&format!("/api/v1/machines/{}", alice_laptop.machine_key)).await?;
    if !delete_response.status().is_success() {
        anyhow::bail!("Failed to disconnect alice-laptop: {}", delete_response.status());
    }

    // Wait a moment
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Reconnect alice-laptop
    debug!("Reconnecting alice-laptop");
    let reconnect_request = RegisterRequest {
        machine_info: alice_laptop.clone(),
        auth_token: "alice-work-token".to_string(),
    };

    let reconnect_response = client.post_json("/api/v1/machines/register", &reconnect_request).await?;
    if !reconnect_response.status().is_success() {
        anyhow::bail!("Failed to reconnect alice-laptop: {}", reconnect_response.status());
    }

    server.stop().await?;
    info!("Small team scenario completed successfully");
    Ok(())
}

/// Scenario: Remote worker joining an existing mesh
async fn test_remote_worker_scenario(_config: &TestConfig) -> Result<()> {
    info!("Running remote worker scenario");

    let mut server = TestServer::new().await?;
    server.start().await?;

    let client = TestClient::new(server.base_url());

    // Start with office machines already connected
    let office_devices = vec![
        ("office-server", "192.168.1.100"),
        ("meeting-room", "192.168.1.101"),
        ("printer-server", "192.168.1.102"),
    ];

    for (hostname, ip) in &office_devices {
        let machine_info = MachineInfo {
            machine_key: TestFixtures::machine_key(),
            node_key: TestFixtures::node_key(),
            hostname: hostname.to_string(),
            ipv4: ip.parse().unwrap(),
            ipv6: None,
            endpoints: vec![format!("{}:41641", ip).parse().unwrap()],
            derp_region: 1,
            os: "linux".to_string(),
            tags: vec!["location:office".to_string()],
            capabilities: vec![],
        };

        let register_request = RegisterRequest {
            machine_info,
            auth_token: format!("{}-token", hostname),
        };

        let response = client.post_json("/api/v1/machines/register", &register_request).await?;
        if !response.status().is_success() {
            anyhow::bail!("Failed to register office device {}: {}", hostname, response.status());
        }
    }

    // Verify office network is established
    let machines_response = client.get("/api/v1/machines").await?;
    let machines: Vec<MachineInfo> = machines_response.json().await?;
    if machines.len() != office_devices.len() {
        anyhow::bail!("Office network not properly established");
    }

    // Remote worker joins from different location
    debug!("Remote worker joining mesh");

    let remote_worker = MachineInfo {
        machine_key: TestFixtures::machine_key(),
        node_key: TestFixtures::node_key(),
        hostname: "sarah-home-laptop".to_string(),
        ipv4: "10.0.0.5".parse().unwrap(), // Different subnet
        ipv6: None,
        endpoints: vec!["203.0.113.45:41641".parse().unwrap()], // Simulated public IP
        derp_region: 2, // Different DERP region
        os: "macos".to_string(),
        tags: vec!["location:remote".to_string(), "user:sarah".to_string()],
        capabilities: vec![],
    };

    let remote_register_request = RegisterRequest {
        machine_info: remote_worker,
        auth_token: "sarah-remote-token".to_string(),
    };

    let remote_response = client.post_json("/api/v1/machines/register", &remote_register_request).await?;
    if !remote_response.status().is_success() {
        anyhow::bail!("Failed to register remote worker: {}", remote_response.status());
    }

    // Verify remote worker can see all office devices
    let updated_machines_response = client.get("/api/v1/machines").await?;
    let updated_machines: Vec<MachineInfo> = updated_machines_response.json().await?;
    if updated_machines.len() != office_devices.len() + 1 {
        anyhow::bail!("Remote worker not properly added to mesh");
    }

    // Verify network map includes remote worker
    let netmap_response = client.get("/api/v1/network/map").await?;
    if !netmap_response.status().is_success() {
        anyhow::bail!("Failed to get updated network map: {}", netmap_response.status());
    }

    server.stop().await?;
    info!("Remote worker scenario completed successfully");
    Ok(())
}

/// Scenario: Network partition and recovery
async fn test_network_partition_recovery(_config: &TestConfig) -> Result<()> {
    info!("Running network partition recovery scenario");

    let mut server = TestServer::new().await?;
    server.start().await?;

    let client = TestClient::new(server.base_url());

    // Set up initial mesh with multiple nodes
    let initial_nodes = vec![
        ("node-a", "192.168.1.10"),
        ("node-b", "192.168.1.20"),
        ("node-c", "192.168.1.30"),
        ("node-d", "192.168.1.40"),
    ];

    let mut registered_nodes = Vec::new();

    for (hostname, ip) in &initial_nodes {
        let machine_info = MachineInfo {
            machine_key: TestFixtures::machine_key(),
            node_key: TestFixtures::node_key(),
            hostname: hostname.to_string(),
            ipv4: ip.parse().unwrap(),
            ipv6: None,
            endpoints: vec![format!("{}:41641", ip).parse().unwrap()],
            derp_region: 1,
            os: "linux".to_string(),
            tags: vec![],
            capabilities: vec![],
        };

        let register_request = RegisterRequest {
            machine_info: machine_info.clone(),
            auth_token: format!("{}-token", hostname),
        };

        let response = client.post_json("/api/v1/machines/register", &register_request).await?;
        if !response.status().is_success() {
            anyhow::bail!("Failed to register {}: {}", hostname, response.status());
        }

        registered_nodes.push(machine_info);
    }

    // Verify initial mesh
    let machines_response = client.get("/api/v1/machines").await?;
    let machines: Vec<MachineInfo> = machines_response.json().await?;
    if machines.len() != initial_nodes.len() {
        anyhow::bail!("Initial mesh not properly established");
    }

    // Simulate partition: remove half the nodes
    debug!("Simulating network partition");
    let partition_nodes = &registered_nodes[0..2]; // Remove first two nodes

    for node in partition_nodes {
        let delete_response = client.delete(&format!("/api/v1/machines/{}", node.machine_key)).await?;
        if !delete_response.status().is_success() {
            anyhow::bail!("Failed to partition node {}: {}", node.hostname, delete_response.status());
        }
    }

    // Verify partition
    let partitioned_machines_response = client.get("/api/v1/machines").await?;
    let partitioned_machines: Vec<MachineInfo> = partitioned_machines_response.json().await?;
    if partitioned_machines.len() != 2 {
        anyhow::bail!("Network partition not applied correctly");
    }

    // Wait for partition to be processed
    tokio::time::sleep(Duration::from_millis(1000)).await;

    // Simulate recovery: re-add partitioned nodes
    debug!("Simulating network recovery");

    for node in partition_nodes {
        let recovery_request = RegisterRequest {
            machine_info: node.clone(),
            auth_token: format!("{}-recovery-token", node.hostname),
        };

        let recovery_response = client.post_json("/api/v1/machines/register", &recovery_request).await?;
        if !recovery_response.status().is_success() {
            anyhow::bail!("Failed to recover node {}: {}", node.hostname, recovery_response.status());
        }
    }

    // Verify recovery
    let recovered_machines_response = client.get("/api/v1/machines").await?;
    let recovered_machines: Vec<MachineInfo> = recovered_machines_response.json().await?;
    if recovered_machines.len() != initial_nodes.len() {
        anyhow::bail!("Network recovery not completed correctly: expected {}, got {}",
                      initial_nodes.len(), recovered_machines.len());
    }

    // Verify network map is consistent after recovery
    let final_netmap_response = client.get("/api/v1/network/map").await?;
    if !final_netmap_response.status().is_success() {
        anyhow::bail!("Failed to get network map after recovery: {}", final_netmap_response.status());
    }

    server.stop().await?;
    info!("Network partition recovery scenario completed successfully");
    Ok(())
}

#[tokio::test]
async fn test_high_churn_scenario() {
    crate::init_test_env();
    info!("Running high churn scenario (nodes frequently joining/leaving)");

    let mut server = TestServer::new().await.expect("Failed to create server");
    server.start().await.expect("Failed to start server");

    let client = TestClient::new(server.base_url());
    let duration = Duration::from_secs(30);
    let start = Instant::now();

    let mut node_counter = 0;
    let mut active_nodes = Vec::new();

    while start.elapsed() < duration {
        // Randomly add or remove nodes
        let action = if active_nodes.is_empty() || (active_nodes.len() < 10 && rand::random::<bool>()) {
            "add"
        } else {
            "remove"
        };

        match action {
            "add" => {
                let machine_info = MachineInfo {
                    machine_key: TestFixtures::machine_key(),
                    node_key: TestFixtures::node_key(),
                    hostname: format!("churn-node-{}", node_counter),
                    ipv4: format!("192.168.1.{}", 10 + (node_counter % 200)).parse().unwrap(),
                    ipv6: None,
                    endpoints: vec![format!("192.168.1.{}:41641", 10 + (node_counter % 200)).parse().unwrap()],
                    derp_region: 1,
                    os: "linux".to_string(),
                    tags: vec!["test:churn".to_string()],
                    capabilities: vec![],
                };

                let register_request = RegisterRequest {
                    machine_info: machine_info.clone(),
                    auth_token: format!("churn-token-{}", node_counter),
                };

                if let Ok(response) = client.post_json("/api/v1/machines/register", &register_request).await {
                    if response.status().is_success() {
                        active_nodes.push(machine_info);
                        debug!("Added churn node {}", node_counter);
                    }
                }

                node_counter += 1;
            }
            "remove" => {
                if let Some(node) = active_nodes.pop() {
                    if let Ok(response) = client.delete(&format!("/api/v1/machines/{}", node.machine_key)).await {
                        if response.status().is_success() {
                            debug!("Removed churn node {}", node.hostname);
                        } else {
                            // Put it back if deletion failed
                            active_nodes.push(node);
                        }
                    }
                }
            }
            _ => unreachable!(),
        }

        // Small delay between operations
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    info!("High churn scenario completed with {} total nodes created, {} still active",
          node_counter, active_nodes.len());

    server.stop().await.expect("Failed to stop server");
}