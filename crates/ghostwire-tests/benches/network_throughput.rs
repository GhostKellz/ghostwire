use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use ghostwire_tests::{
    common::{TestClient, TestServer, TestFixtures},
    init_test_env,
};
use ghostwire_common::types::{MachineInfo, RegisterRequest};
use std::time::Duration;
use tokio::runtime::Runtime;

fn bench_api_throughput(c: &mut Criterion) {
    init_test_env();

    let rt = Runtime::new().unwrap();

    let mut server = rt.block_on(async {
        let mut server = TestServer::new().await.expect("Failed to create server");
        server.start().await.expect("Failed to start server");
        server
    });

    let client = TestClient::new(server.base_url());

    let mut group = c.benchmark_group("api_throughput");

    // Benchmark different API endpoints
    let endpoints = vec![
        ("/health", "health_check"),
        ("/api/v1/info", "info"),
        ("/api/v1/machines", "machines_list"),
        ("/metrics", "metrics"),
    ];

    for (endpoint, name) in endpoints {
        group.bench_with_input(BenchmarkId::new("get_request", name), endpoint, |b, &endpoint| {
            b.to_async(&rt).iter(|| async {
                let response = client.get(endpoint).await.expect("Request failed");
                assert!(response.status().is_success());
            });
        });
    }

    group.finish();

    rt.block_on(async {
        server.stop().await.expect("Failed to stop server");
    });
}

fn bench_machine_registration(c: &mut Criterion) {
    init_test_env();

    let rt = Runtime::new().unwrap();

    let mut server = rt.block_on(async {
        let mut server = TestServer::new().await.expect("Failed to create server");
        server.start().await.expect("Failed to start server");
        server
    });

    let client = TestClient::new(server.base_url());

    let mut group = c.benchmark_group("machine_registration");
    group.measurement_time(Duration::from_secs(10));

    group.bench_function("register_machine", |b| {
        b.to_async(&rt).iter_batched(
            || {
                // Setup: create a new machine for each iteration
                MachineInfo {
                    machine_key: TestFixtures::machine_key(),
                    node_key: TestFixtures::node_key(),
                    hostname: format!("bench-machine-{}", rand::random::<u32>()),
                    ipv4: format!("192.168.1.{}", (rand::random::<u8>() % 200) + 10).parse().unwrap(),
                    ipv6: None,
                    endpoints: vec!["192.168.1.1:41641".parse().unwrap()],
                    derp_region: 1,
                    os: "linux".to_string(),
                    tags: vec![],
                    capabilities: vec![],
                }
            },
            |machine_info| async {
                let register_request = RegisterRequest {
                    machine_info,
                    auth_token: format!("bench-token-{}", rand::random::<u32>()),
                };

                let response = client.post_json("/api/v1/machines/register", &register_request)
                    .await.expect("Registration failed");
                assert!(response.status().is_success());
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.finish();

    rt.block_on(async {
        server.stop().await.expect("Failed to stop server");
    });
}

fn bench_concurrent_connections(c: &mut Criterion) {
    init_test_env();

    let rt = Runtime::new().unwrap();

    let mut server = rt.block_on(async {
        let mut server = TestServer::new().await.expect("Failed to create server");
        server.start().await.expect("Failed to start server");
        server
    });

    let base_url = server.base_url();

    let mut group = c.benchmark_group("concurrent_connections");
    group.measurement_time(Duration::from_secs(20));

    let concurrency_levels = vec![1, 5, 10, 25, 50];

    for &concurrency in &concurrency_levels {
        group.throughput(Throughput::Elements(concurrency as u64));

        group.bench_with_input(
            BenchmarkId::new("health_checks", concurrency),
            &concurrency,
            |b, &concurrency| {
                b.to_async(&rt).iter(|| async {
                    let mut handles = Vec::new();

                    for _ in 0..concurrency {
                        let url = base_url.clone();
                        let handle = tokio::spawn(async move {
                            let client = TestClient::new(url);
                            let response = client.health_check().await.expect("Health check failed");
                            assert!(response);
                        });
                        handles.push(handle);
                    }

                    for handle in handles {
                        handle.await.expect("Task failed");
                    }
                });
            },
        );
    }

    group.finish();

    rt.block_on(async {
        server.stop().await.expect("Failed to stop server");
    });
}

fn bench_network_map_generation(c: &mut Criterion) {
    init_test_env();

    let rt = Runtime::new().unwrap();

    let mut server = rt.block_on(async {
        let mut server = TestServer::new().await.expect("Failed to create server");
        server.start().await.expect("Failed to start server");
        server
    });

    let client = TestClient::new(server.base_url());

    // Pre-register different numbers of machines
    let node_counts = vec![1, 5, 10, 25, 50];

    for &node_count in &node_counts {
        // Clean up previous machines
        rt.block_on(async {
            let machines_response = client.get("/api/v1/machines").await.expect("Failed to get machines");
            let machines: Vec<serde_json::Value> = machines_response.json().await.expect("Failed to parse machines");

            for machine in machines {
                if let Some(key) = machine.get("machine_key").and_then(|k| k.as_str()) {
                    let _ = client.delete(&format!("/api/v1/machines/{}", key)).await;
                }
            }
        });

        // Register machines for this test
        rt.block_on(async {
            for i in 0..node_count {
                let machine_info = MachineInfo {
                    machine_key: TestFixtures::machine_key(),
                    node_key: TestFixtures::node_key(),
                    hostname: format!("netmap-machine-{}", i),
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
                    auth_token: format!("netmap-token-{}", i),
                };

                let response = client.post_json("/api/v1/machines/register", &register_request)
                    .await.expect("Registration failed");
                assert!(response.status().is_success());
            }
        });

        let mut group = c.benchmark_group("network_map_generation");
        group.throughput(Throughput::Elements(node_count as u64));

        group.bench_with_input(
            BenchmarkId::new("generate_map", node_count),
            &node_count,
            |b, _| {
                b.to_async(&rt).iter(|| async {
                    let response = client.get("/api/v1/network/map").await.expect("Network map request failed");
                    assert!(response.status().is_success());
                    let _map_data = response.text().await.expect("Failed to read map data");
                });
            },
        );

        group.finish();
    }

    rt.block_on(async {
        server.stop().await.expect("Failed to stop server");
    });
}

criterion_group!(
    benches,
    bench_api_throughput,
    bench_machine_registration,
    bench_concurrent_connections,
    bench_network_map_generation
);
criterion_main!(benches);