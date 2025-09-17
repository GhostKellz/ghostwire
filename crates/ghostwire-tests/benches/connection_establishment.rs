use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use ghostwire_tests::{
    common::{TestClient, TestServer},
    init_test_env,
};
use std::time::Duration;
use tokio::runtime::Runtime;

fn bench_server_startup(c: &mut Criterion) {
    init_test_env();

    let rt = Runtime::new().unwrap();

    let mut group = c.benchmark_group("server_startup");
    group.measurement_time(Duration::from_secs(30));
    group.sample_size(10); // Fewer samples for expensive operations

    group.bench_function("cold_start", |b| {
        b.to_async(&rt).iter(|| async {
            let mut server = TestServer::new().await.expect("Failed to create server");
            server.start().await.expect("Failed to start server");

            // Verify server is ready
            let client = TestClient::new(server.base_url());
            let health = client.health_check().await.expect("Health check failed");
            assert!(health);

            server.stop().await.expect("Failed to stop server");
        });
    });

    group.finish();
}

fn bench_client_connection(c: &mut Criterion) {
    init_test_env();

    let rt = Runtime::new().unwrap();

    let mut server = rt.block_on(async {
        let mut server = TestServer::new().await.expect("Failed to create server");
        server.start().await.expect("Failed to start server");
        server
    });

    let base_url = server.base_url();

    let mut group = c.benchmark_group("client_connection");

    group.bench_function("first_request", |b| {
        b.to_async(&rt).iter(|| async {
            let client = TestClient::new(base_url.clone());
            let response = client.health_check().await.expect("Health check failed");
            assert!(response);
        });
    });

    // Benchmark connection reuse
    let persistent_client = TestClient::new(base_url.clone());

    group.bench_function("persistent_connection", |b| {
        b.to_async(&rt).iter(|| async {
            let response = persistent_client.health_check().await.expect("Health check failed");
            assert!(response);
        });
    });

    group.finish();

    rt.block_on(async {
        server.stop().await.expect("Failed to stop server");
    });
}

fn bench_concurrent_client_connections(c: &mut Criterion) {
    init_test_env();

    let rt = Runtime::new().unwrap();

    let mut server = rt.block_on(async {
        let mut server = TestServer::new().await.expect("Failed to create server");
        server.start().await.expect("Failed to start server");
        server
    });

    let base_url = server.base_url();

    let mut group = c.benchmark_group("concurrent_connections");
    let concurrency_levels = vec![1, 5, 10, 25, 50];

    for &concurrency in &concurrency_levels {
        group.throughput(Throughput::Elements(concurrency as u64));

        group.bench_with_input(
            BenchmarkId::new("new_connections", concurrency),
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

fn bench_request_latency(c: &mut Criterion) {
    init_test_env();

    let rt = Runtime::new().unwrap();

    let mut server = rt.block_on(async {
        let mut server = TestServer::new().await.expect("Failed to create server");
        server.start().await.expect("Failed to start server");
        server
    });

    let client = TestClient::new(server.base_url());

    let mut group = c.benchmark_group("request_latency");

    let endpoints = vec![
        ("/health", "health"),
        ("/metrics", "metrics"),
        ("/api/v1/info", "info"),
        ("/api/v1/machines", "machines"),
    ];

    for (endpoint, name) in endpoints {
        group.bench_with_input(BenchmarkId::new("latency", name), endpoint, |b, &endpoint| {
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

fn bench_connection_pooling(c: &mut Criterion) {
    init_test_env();

    let rt = Runtime::new().unwrap();

    let mut server = rt.block_on(async {
        let mut server = TestServer::new().await.expect("Failed to create server");
        server.start().await.expect("Failed to start server");
        server
    });

    let base_url = server.base_url();

    let mut group = c.benchmark_group("connection_pooling");

    // Benchmark sequential requests with connection reuse
    let client = TestClient::new(base_url.clone());

    group.bench_function("sequential_reuse", |b| {
        b.to_async(&rt).iter(|| async {
            for _ in 0..10 {
                let response = client.get("/health").await.expect("Request failed");
                assert!(response.status().is_success());
            }
        });
    });

    // Benchmark parallel requests sharing connection pool
    group.bench_function("parallel_pool", |b| {
        b.to_async(&rt).iter(|| async {
            let mut handles = Vec::new();

            for _ in 0..10 {
                let client_ref = &client;
                let handle = tokio::spawn(async move {
                    let response = client_ref.get("/health").await.expect("Request failed");
                    assert!(response.status().is_success());
                });
                handles.push(handle);
            }

            for handle in handles {
                handle.await.expect("Task failed");
            }
        });
    });

    group.finish();

    rt.block_on(async {
        server.stop().await.expect("Failed to stop server");
    });
}

fn bench_keepalive_vs_new_connections(c: &mut Criterion) {
    init_test_env();

    let rt = Runtime::new().unwrap();

    let mut server = rt.block_on(async {
        let mut server = TestServer::new().await.expect("Failed to create server");
        server.start().await.expect("Failed to start server");
        server
    });

    let base_url = server.base_url();

    let mut group = c.benchmark_group("keepalive_comparison");

    // Benchmark with connection reuse (keep-alive)
    let persistent_client = TestClient::new(base_url.clone());

    group.bench_function("keepalive_requests", |b| {
        b.to_async(&rt).iter(|| async {
            for _ in 0..20 {
                let response = persistent_client.get("/health").await.expect("Request failed");
                assert!(response.status().is_success());
            }
        });
    });

    // Benchmark with new connections each time
    group.bench_function("new_connections", |b| {
        b.to_async(&rt).iter(|| async {
            for _ in 0..20 {
                let client = TestClient::new(base_url.clone());
                let response = client.get("/health").await.expect("Request failed");
                assert!(response.status().is_success());
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
    bench_server_startup,
    bench_client_connection,
    bench_concurrent_client_connections,
    bench_request_latency,
    bench_connection_pooling,
    bench_keepalive_vs_new_connections
);
criterion_main!(benches);