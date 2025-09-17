use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use ghostwire_tests::{
    common::{TestClient, TestServer, TestFixtures},
    init_test_env,
};
use ghostwire_common::types::{MachineInfo, RegisterRequest};
use std::time::Duration;
use tokio::runtime::Runtime;

fn bench_mesh_registration_scaling(c: &mut Criterion) {
    init_test_env();

    let rt = Runtime::new().unwrap();

    let mut server = rt.block_on(async {
        let mut server = TestServer::new().await.expect("Failed to create server");
        server.start().await.expect("Failed to start server");
        server
    });

    let client = TestClient::new(server.base_url());

    let mut group = c.benchmark_group("mesh_registration_scaling");
    group.measurement_time(Duration::from_secs(60));

    let node_counts = vec![1, 5, 10, 25, 50, 100];

    for &node_count in &node_counts {
        group.throughput(Throughput::Elements(node_count as u64));

        group.bench_with_input(
            BenchmarkId::new("register_nodes", node_count),
            &node_count,
            |b, &node_count| {
                b.to_async(&rt).iter_batched(
                    || {
                        // Setup: clean up any existing machines and prepare new ones
                        let rt = Runtime::new().unwrap();
                        rt.block_on(async {
                            // Clean up existing machines
                            let machines_response = client.get("/api/v1/machines").await.expect("Failed to get machines");
                            let machines: Vec<serde_json::Value> = machines_response.json().await.expect("Failed to parse machines");

                            for machine in machines {
                                if let Some(key) = machine.get("machine_key").and_then(|k| k.as_str()) {
                                    let _ = client.delete(&format!("/api/v1/machines/{}", key)).await;
                                }
                            }
                        });

                        // Generate test machines
                        (0..node_count)
                            .map(|i| {
                                let machine_info = MachineInfo {
                                    machine_key: TestFixtures::machine_key(),
                                    node_key: TestFixtures::node_key(),
                                    hostname: format!("scale-test-{}", i),
                                    ipv4: format!("192.168.1.{}", 10 + (i % 200)).parse().unwrap(),
                                    ipv6: None,
                                    endpoints: vec![format!("192.168.1.{}:41641", 10 + (i % 200)).parse().unwrap()],
                                    derp_region: 1,
                                    os: "linux".to_string(),
                                    tags: vec![format!("scale-test-{}", i)],
                                    capabilities: vec![],
                                };

                                RegisterRequest {
                                    machine_info,
                                    auth_token: format!("scale-token-{}", i),
                                }
                            })
                            .collect::<Vec<_>>()
                    },
                    |register_requests| async {
                        // Register all machines
                        for register_request in register_requests {
                            let response = client
                                .post_json("/api/v1/machines/register", &register_request)
                                .await
                                .expect("Registration failed");
                            assert!(response.status().is_success());
                        }
                    },
                    criterion::BatchSize::LargeInput,
                );
            },
        );
    }

    group.finish();

    rt.block_on(async {
        server.stop().await.expect("Failed to stop server");
    });
}

fn bench_network_map_scaling(c: &mut Criterion) {
    init_test_env();

    let rt = Runtime::new().unwrap();

    let mut server = rt.block_on(async {
        let mut server = TestServer::new().await.expect("Failed to create server");
        server.start().await.expect("Failed to start server");
        server
    });

    let client = TestClient::new(server.base_url());

    let node_counts = vec![1, 5, 10, 25, 50];

    for &node_count in &node_counts {
        // Pre-register machines for this test
        rt.block_on(async {
            // Clean up existing machines
            let machines_response = client.get("/api/v1/machines").await.expect("Failed to get machines");
            let machines: Vec<serde_json::Value> = machines_response.json().await.expect("Failed to parse machines");

            for machine in machines {
                if let Some(key) = machine.get("machine_key").and_then(|k| k.as_str()) {
                    let _ = client.delete(&format!("/api/v1/machines/{}", key)).await;
                }
            }

            // Register test machines
            for i in 0..node_count {
                let machine_info = MachineInfo {
                    machine_key: TestFixtures::machine_key(),
                    node_key: TestFixtures::node_key(),
                    hostname: format!("netmap-scale-{}", i),
                    ipv4: format!("192.168.1.{}", 20 + i).parse().unwrap(),
                    ipv6: None,
                    endpoints: vec![format!("192.168.1.{}:41641", 20 + i).parse().unwrap()],
                    derp_region: 1,
                    os: "linux".to_string(),
                    tags: vec!["netmap-scale".to_string()],
                    capabilities: vec![],
                };

                let register_request = RegisterRequest {
                    machine_info,
                    auth_token: format!("netmap-token-{}", i),
                };

                let response = client
                    .post_json("/api/v1/machines/register", &register_request)
                    .await
                    .expect("Registration failed");
                assert!(response.status().is_success());
            }
        });

        let mut group = c.benchmark_group("network_map_scaling");
        group.throughput(Throughput::Elements(node_count as u64));

        group.bench_with_input(
            BenchmarkId::new("generate_map", node_count),
            &node_count,
            |b, _| {
                b.to_async(&rt).iter(|| async {
                    let response = client
                        .get("/api/v1/network/map")
                        .await
                        .expect("Network map request failed");
                    assert!(response.status().is_success());

                    let map_data = response.text().await.expect("Failed to read map data");
                    assert!(!map_data.is_empty());
                });
            },
        );

        group.finish();
    }

    rt.block_on(async {
        server.stop().await.expect("Failed to stop server");
    });
}

fn bench_concurrent_registration(c: &mut Criterion) {
    init_test_env();

    let rt = Runtime::new().unwrap();

    let mut server = rt.block_on(async {
        let mut server = TestServer::new().await.expect("Failed to create server");
        server.start().await.expect("Failed to start server");
        server
    });

    let base_url = server.base_url();

    let mut group = c.benchmark_group("concurrent_registration");
    let concurrency_levels = vec![1, 5, 10, 25];

    for &concurrency in &concurrency_levels {
        group.throughput(Throughput::Elements(concurrency as u64));

        group.bench_with_input(
            BenchmarkId::new("parallel_register", concurrency),
            &concurrency,
            |b, &concurrency| {
                b.to_async(&rt).iter_batched(
                    || {
                        // Setup: clean existing machines and prepare new registration requests
                        let rt = Runtime::new().unwrap();
                        let client = TestClient::new(base_url.clone());

                        rt.block_on(async {
                            let machines_response = client.get("/api/v1/machines").await.expect("Failed to get machines");
                            let machines: Vec<serde_json::Value> = machines_response.json().await.expect("Failed to parse machines");

                            for machine in machines {
                                if let Some(key) = machine.get("machine_key").and_then(|k| k.as_str()) {
                                    let _ = client.delete(&format!("/api/v1/machines/{}", key)).await;
                                }
                            }
                        });

                        (0..concurrency)
                            .map(|i| {
                                let machine_info = MachineInfo {
                                    machine_key: TestFixtures::machine_key(),
                                    node_key: TestFixtures::node_key(),
                                    hostname: format!("concurrent-{}", i),
                                    ipv4: format!("192.168.1.{}", 100 + i).parse().unwrap(),
                                    ipv6: None,
                                    endpoints: vec![format!("192.168.1.{}:41641", 100 + i).parse().unwrap()],
                                    derp_region: 1,
                                    os: "linux".to_string(),
                                    tags: vec!["concurrent-test".to_string()],
                                    capabilities: vec![],
                                };

                                RegisterRequest {
                                    machine_info,
                                    auth_token: format!("concurrent-token-{}", i),
                                }
                            })
                            .collect::<Vec<_>>()
                    },
                    |register_requests| async {
                        let mut handles = Vec::new();

                        for register_request in register_requests {
                            let url = base_url.clone();
                            let handle = tokio::spawn(async move {
                                let client = TestClient::new(url);
                                let response = client
                                    .post_json("/api/v1/machines/register", &register_request)
                                    .await
                                    .expect("Registration failed");
                                assert!(response.status().is_success());
                            });
                            handles.push(handle);
                        }

                        for handle in handles {
                            handle.await.expect("Registration task failed");
                        }
                    },
                    criterion::BatchSize::SmallInput,
                );
            },
        );
    }

    group.finish();

    rt.block_on(async {
        server.stop().await.expect("Failed to stop server");
    });
}

fn bench_mesh_churn(c: &mut Criterion) {
    init_test_env();

    let rt = Runtime::new().unwrap();

    let mut server = rt.block_on(async {
        let mut server = TestServer::new().await.expect("Failed to create server");
        server.start().await.expect("Failed to start server");
        server
    });

    let client = TestClient::new(server.base_url());

    let mut group = c.benchmark_group("mesh_churn");
    group.measurement_time(Duration::from_secs(30));
    group.sample_size(10);

    // Benchmark rapid join/leave cycles
    group.bench_function("join_leave_cycles", |b| {
        b.to_async(&rt).iter(|| async {
            let cycles = 20;

            for i in 0..cycles {
                // Register a machine
                let machine_info = MachineInfo {
                    machine_key: TestFixtures::machine_key(),
                    node_key: TestFixtures::node_key(),
                    hostname: format!("churn-machine-{}", i),
                    ipv4: format!("192.168.1.{}", 150 + (i % 50)).parse().unwrap(),
                    ipv6: None,
                    endpoints: vec![format!("192.168.1.{}:41641", 150 + (i % 50)).parse().unwrap()],
                    derp_region: 1,
                    os: "linux".to_string(),
                    tags: vec!["churn-test".to_string()],
                    capabilities: vec![],
                };

                let register_request = RegisterRequest {
                    machine_info: machine_info.clone(),
                    auth_token: format!("churn-token-{}", i),
                };

                // Register
                let register_response = client
                    .post_json("/api/v1/machines/register", &register_request)
                    .await
                    .expect("Registration failed");
                assert!(register_response.status().is_success());

                // Immediately unregister
                let delete_response = client
                    .delete(&format!("/api/v1/machines/{}", machine_info.machine_key))
                    .await
                    .expect("Deletion failed");
                assert!(delete_response.status().is_success());
            }
        });
    });

    group.finish();

    rt.block_on(async {
        server.stop().await.expect("Failed to stop server");
    });
}

criterion_group!(
    benches,
    bench_mesh_registration_scaling,
    bench_network_map_scaling,
    bench_concurrent_registration,
    bench_mesh_churn
);
criterion_main!(benches);