//! Cryptographic performance benchmarks

use crate::{
    common::{crypto, TestFixtures},
    performance::{BenchmarkConfig, PerformanceMetrics},
    performance_test, TestConfig, TestResult, TestSuite,
};
use anyhow::Result;
use std::time::{Duration, Instant};
use tracing::info;

pub struct CryptoPerformanceTestSuite;

#[async_trait::async_trait]
impl TestSuite for CryptoPerformanceTestSuite {
    fn name(&self) -> &str {
        "Crypto Performance Tests"
    }

    async fn run_tests(&self, _config: &TestConfig) -> Result<Vec<TestResult>> {
        let mut results = Vec::new();

        // Test key generation performance
        let (result, duration) = crate::common::timing::measure_async(
            test_key_generation_performance()
        ).await;

        match result {
            Ok(metrics) => {
                let mut test_result = TestResult::success("key_generation", duration.as_millis() as u64);
                test_result = test_result.with_metric("ops_per_sec", metrics.ops_per_sec);
                test_result = test_result.with_metric("avg_latency_ms", metrics.avg_latency_ms);
                results.push(test_result);
            }
            Err(e) => results.push(TestResult::failure("key_generation", duration.as_millis() as u64, e.to_string())),
        }

        // Test encryption performance
        let (result, duration) = crate::common::timing::measure_async(
            test_encryption_performance()
        ).await;

        match result {
            Ok(metrics) => {
                let mut test_result = TestResult::success("encryption", duration.as_millis() as u64);
                test_result = test_result.with_metric("ops_per_sec", metrics.ops_per_sec);
                test_result = test_result.with_metric("throughput_mbps", metrics.throughput_bps / 1_000_000.0);
                results.push(test_result);
            }
            Err(e) => results.push(TestResult::failure("encryption", duration.as_millis() as u64, e.to_string())),
        }

        Ok(results)
    }
}

async fn test_key_generation_performance() -> Result<PerformanceMetrics> {
    info!("Benchmarking key generation performance");

    let iterations = 1000;
    let mut latencies = Vec::with_capacity(iterations);

    let start = Instant::now();

    for _ in 0..iterations {
        let key_start = Instant::now();
        let _keypair = TestFixtures::keypair();
        latencies.push(key_start.elapsed());
    }

    let total_duration = start.elapsed();
    let metrics = PerformanceMetrics::from_latencies(&latencies, total_duration);

    info!("Key generation: {:.2} ops/sec, avg {:.2}ms", metrics.ops_per_sec, metrics.avg_latency_ms);

    Ok(metrics)
}

async fn test_encryption_performance() -> Result<PerformanceMetrics> {
    info!("Benchmarking encryption performance");

    let key = [42u8; 32]; // Test key
    let data_sizes = vec![1024, 4096, 16384, 65536]; // Various data sizes
    let mut all_metrics = Vec::new();

    for data_size in data_sizes {
        let data = crypto::random_data(data_size);
        let iterations = 10000 / (data_size / 1024).max(1); // Fewer iterations for larger data

        let mut latencies = Vec::with_capacity(iterations);
        let start = Instant::now();
        let mut total_bytes = 0u64;

        for _ in 0..iterations {
            let encrypt_start = Instant::now();
            let _encrypted = ghostwire_common::crypto::encrypt_data(&key, &data)
                .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;
            latencies.push(encrypt_start.elapsed());
            total_bytes += data.len() as u64;
        }

        let total_duration = start.elapsed();
        let mut metrics = PerformanceMetrics::from_latencies(&latencies, total_duration);
        metrics.throughput_bps = total_bytes as f64 / total_duration.as_secs_f64();

        info!(
            "Encryption {}B: {:.2} ops/sec, {:.2} MB/s, avg {:.2}ms",
            data_size,
            metrics.ops_per_sec,
            metrics.throughput_bps / 1_000_000.0,
            metrics.avg_latency_ms
        );

        all_metrics.push(metrics);
    }

    // Return metrics for the largest data size as representative
    Ok(all_metrics.into_iter().last().unwrap())
}

performance_test!(
    benchmark_key_exchange,
    || async { Ok(()) },
    |config: &BenchmarkConfig| async move {
        let iterations = config.iterations;
        let mut latencies = Vec::with_capacity(iterations);

        let start = Instant::now();

        for _ in 0..iterations {
            let exchange_start = Instant::now();

            // Simulate key exchange
            let keypair1 = TestFixtures::keypair();
            let keypair2 = TestFixtures::keypair();

            let _shared_secret1 = keypair1.private_key().diffie_hellman(&keypair2.public_key());
            let _shared_secret2 = keypair2.private_key().diffie_hellman(&keypair1.public_key());

            latencies.push(exchange_start.elapsed());
        }

        let total_duration = start.elapsed();
        Ok(PerformanceMetrics::from_latencies(&latencies, total_duration))
    },
    || async { Ok(()) }
);

performance_test!(
    benchmark_hashing,
    || async { Ok(()) },
    |config: &BenchmarkConfig| async move {
        let data = crypto::random_data(config.data_size_bytes);
        let iterations = config.iterations;
        let mut latencies = Vec::with_capacity(iterations);

        let start = Instant::now();
        let mut total_bytes = 0u64;

        for _ in 0..iterations {
            let hash_start = Instant::now();
            let _hash = blake3::hash(&data);
            latencies.push(hash_start.elapsed());
            total_bytes += data.len() as u64;
        }

        let total_duration = start.elapsed();
        let mut metrics = PerformanceMetrics::from_latencies(&latencies, total_duration);
        metrics.throughput_bps = total_bytes as f64 / total_duration.as_secs_f64();

        Ok(metrics)
    },
    || async { Ok(()) }
);

performance_test!(
    benchmark_signature_verification,
    || async { Ok(()) },
    |config: &BenchmarkConfig| async move {
        let keypair = TestFixtures::keypair();
        let message = b"test message for signing";
        let signature = keypair.private_key().sign(message);

        let iterations = config.iterations;
        let mut latencies = Vec::with_capacity(iterations);

        let start = Instant::now();

        for _ in 0..iterations {
            let verify_start = Instant::now();
            let _valid = keypair.public_key().verify(message, &signature).is_ok();
            latencies.push(verify_start.elapsed());
        }

        let total_duration = start.elapsed();
        Ok(PerformanceMetrics::from_latencies(&latencies, total_duration))
    },
    || async { Ok(()) }
);

#[tokio::test]
async fn benchmark_encryption_sizes() {
    crate::init_test_env();

    let key = [42u8; 32];
    let sizes = vec![64, 256, 1024, 4096, 16384, 65536, 262144, 1048576]; // 64B to 1MB

    info!("Benchmarking encryption across different data sizes:");

    for size in sizes {
        let data = crypto::random_data(size);
        let iterations = (1000000 / size).max(10); // Scale iterations with size

        let start = Instant::now();
        let mut total_bytes = 0u64;

        for _ in 0..iterations {
            let _encrypted = ghostwire_common::crypto::encrypt_data(&key, &data)
                .expect("Encryption should succeed");
            total_bytes += data.len() as u64;
        }

        let duration = start.elapsed();
        let throughput_mbps = (total_bytes as f64 / duration.as_secs_f64()) / 1_000_000.0;
        let ops_per_sec = iterations as f64 / duration.as_secs_f64();

        info!("  {} bytes: {:.2} MB/s, {:.2} ops/sec", size, throughput_mbps, ops_per_sec);
    }
}