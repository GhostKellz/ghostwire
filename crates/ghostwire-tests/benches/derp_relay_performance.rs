use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use ghostwire_tests::{
    common::{TestClient, TestServer},
    init_test_env,
};
use std::time::Duration;
use tokio::runtime::Runtime;

fn bench_derp_server_startup(c: &mut Criterion) {
    init_test_env();

    let rt = Runtime::new().unwrap();

    let mut group = c.benchmark_group("derp_server_startup");
    group.measurement_time(Duration::from_secs(20));
    group.sample_size(10);

    group.bench_function("start_with_derp", |b| {
        b.to_async(&rt).iter(|| async {
            let mut server = TestServer::new().await.expect("Failed to create server");
            server.start().await.expect("Failed to start server");

            // Verify DERP is available
            if let Some(derp_addr) = server.derp_addr() {
                // Basic connectivity test - DERP uses custom protocol so we just check the port is open
                let _sock = tokio::net::TcpStream::connect(derp_addr).await
                    .expect("DERP server should be listening");
            }

            server.stop().await.expect("Failed to stop server");
        });
    });

    group.finish();
}

fn bench_derp_connection_handling(c: &mut Criterion) {
    init_test_env();

    let rt = Runtime::new().unwrap();

    let mut server = rt.block_on(async {
        let mut server = TestServer::new().await.expect("Failed to create server");
        server.start().await.expect("Failed to start server");
        server
    });

    let derp_addr = server.derp_addr().expect("DERP server should be configured");

    let mut group = c.benchmark_group("derp_connections");

    group.bench_function("tcp_connection", |b| {
        b.to_async(&rt).iter(|| async {
            let _stream = tokio::net::TcpStream::connect(derp_addr).await
                .expect("Should be able to connect to DERP");
            // Just test connection establishment, actual DERP protocol would need more work
        });
    });

    let concurrency_levels = vec![1, 5, 10, 25];

    for &concurrency in &concurrency_levels {
        group.throughput(Throughput::Elements(concurrency as u64));

        group.bench_with_input(
            BenchmarkId::new("concurrent_connections", concurrency),
            &concurrency,
            |b, &concurrency| {
                b.to_async(&rt).iter(|| async {
                    let mut handles = Vec::new();

                    for _ in 0..concurrency {
                        let handle = tokio::spawn(async move {
                            let _stream = tokio::net::TcpStream::connect(derp_addr).await
                                .expect("Should be able to connect to DERP");
                            // Hold connection briefly
                            tokio::time::sleep(Duration::from_millis(10)).await;
                        });
                        handles.push(handle);
                    }

                    for handle in handles {
                        handle.await.expect("Connection task should complete");
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

fn bench_derp_throughput_simulation(c: &mut Criterion) {
    init_test_env();

    let rt = Runtime::new().unwrap();

    let mut server = rt.block_on(async {
        let mut server = TestServer::new().await.expect("Failed to create server");
        server.start().await.expect("Failed to start server");
        server
    });

    let derp_addr = server.derp_addr().expect("DERP server should be configured");

    let mut group = c.benchmark_group("derp_throughput");

    let data_sizes = vec![1024, 4096, 16384, 65536]; // 1KB to 64KB packets

    for &size in &data_sizes {
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::new("tcp_send", size), &size, |b, &size| {
            b.to_async(&rt).iter(|| async {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};

                let mut stream = tokio::net::TcpStream::connect(derp_addr).await
                    .expect("Should be able to connect to DERP");

                let data = vec![0u8; size];

                // Send data (simulating DERP packet)
                stream.write_all(&data).await.expect("Should be able to write data");

                // Try to read response (will likely fail since this isn't real DERP protocol)
                let mut buf = vec![0u8; 1024];
                let _ = stream.read(&mut buf).await; // Don't assert on this since it's just TCP
            });
        });
    }

    group.finish();

    rt.block_on(async {
        server.stop().await.expect("Failed to stop server");
    });
}

fn bench_derp_server_load(c: &mut Criterion) {
    init_test_env();

    let rt = Runtime::new().unwrap();

    let mut server = rt.block_on(async {
        let mut server = TestServer::new().await.expect("Failed to create server");
        server.start().await.expect("Failed to start server");
        server
    });

    let derp_addr = server.derp_addr().expect("DERP server should be configured");

    let mut group = c.benchmark_group("derp_load");
    group.measurement_time(Duration::from_secs(15));

    group.bench_function("sustained_connections", |b| {
        b.to_async(&rt).iter(|| async {
            let concurrent_connections = 50;
            let duration = Duration::from_secs(5);
            let mut handles = Vec::new();

            for _ in 0..concurrent_connections {
                let handle = tokio::spawn(async move {
                    let start = std::time::Instant::now();

                    while start.elapsed() < duration {
                        if let Ok(_stream) = tokio::net::TcpStream::connect(derp_addr).await {
                            // Hold connection for a short time
                            tokio::time::sleep(Duration::from_millis(100)).await;
                        }
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                });
                handles.push(handle);
            }

            for handle in handles {
                let _ = handle.await;
            }
        });
    });

    group.finish();

    rt.block_on(async {
        server.stop().await.expect("Failed to stop server");
    });
}

fn bench_derp_health_monitoring(c: &mut Criterion) {
    init_test_env();

    let rt = Runtime::new().unwrap();

    let mut server = rt.block_on(async {
        let mut server = TestServer::new().await.expect("Failed to create server");
        server.start().await.expect("Failed to start server");
        server
    });

    let client = TestClient::new(server.base_url());

    let mut group = c.benchmark_group("derp_health");

    // Benchmark DERP health check through server API
    group.bench_function("derp_status_check", |b| {
        b.to_async(&rt).iter(|| async {
            // Check if DERP status is reported in health endpoint
            let response = client.get("/health").await.expect("Health check failed");
            assert!(response.status().is_success());

            let health_text = response.text().await.expect("Should be able to read health response");
            // Basic validation that we got some health data
            assert!(!health_text.is_empty());
        });
    });

    // Benchmark DERP metrics collection
    group.bench_function("derp_metrics_collection", |b| {
        b.to_async(&rt).iter(|| async {
            let response = client.get("/metrics").await.expect("Metrics request failed");
            assert!(response.status().is_success());

            let metrics_text = response.text().await.expect("Should be able to read metrics");
            // Verify we got Prometheus format metrics
            assert!(metrics_text.contains("# HELP") || metrics_text.contains("# TYPE"));
        });
    });

    group.finish();

    rt.block_on(async {
        server.stop().await.expect("Failed to stop server");
    });
}

criterion_group!(
    benches,
    bench_derp_server_startup,
    bench_derp_connection_handling,
    bench_derp_throughput_simulation,
    bench_derp_server_load,
    bench_derp_health_monitoring
);
criterion_main!(benches);