use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use ghostwire_common::crypto::{encrypt_data, decrypt_data, KeyPair};
use ghostwire_tests::{common::crypto, init_test_env};

fn bench_key_generation(c: &mut Criterion) {
    init_test_env();

    let mut group = c.benchmark_group("key_generation");

    group.bench_function("generate_keypair", |b| {
        b.iter(|| {
            let _keypair = KeyPair::generate();
        });
    });

    group.bench_function("generate_machine_key", |b| {
        b.iter(|| {
            let _key = ghostwire_common::types::MachineKey::generate();
        });
    });

    group.bench_function("generate_node_key", |b| {
        b.iter(|| {
            let _key = ghostwire_common::types::NodeKey::generate();
        });
    });

    group.finish();
}

fn bench_encryption_sizes(c: &mut Criterion) {
    init_test_env();

    let key = [42u8; 32];
    let sizes = vec![64, 256, 1024, 4096, 16384, 65536, 262144, 1048576]; // 64B to 1MB

    let mut group = c.benchmark_group("encryption_by_size");

    for &size in &sizes {
        let data = crypto::random_data(size);

        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::new("encrypt", size), &size, |b, _| {
            b.iter(|| {
                let _encrypted = encrypt_data(&key, &data).expect("Encryption should succeed");
            });
        });

        // Also benchmark decryption
        let encrypted = encrypt_data(&key, &data).expect("Encryption should succeed");
        group.bench_with_input(BenchmarkId::new("decrypt", size), &size, |b, _| {
            b.iter(|| {
                let _decrypted = decrypt_data(&key, &encrypted).expect("Decryption should succeed");
            });
        });
    }

    group.finish();
}

fn bench_key_exchange(c: &mut Criterion) {
    init_test_env();

    let mut group = c.benchmark_group("key_exchange");

    group.bench_function("diffie_hellman", |b| {
        b.iter_batched(
            || {
                // Setup: generate two keypairs
                let keypair1 = KeyPair::generate();
                let keypair2 = KeyPair::generate();
                (keypair1, keypair2)
            },
            |(keypair1, keypair2)| {
                // Perform key exchange
                let _shared1 = keypair1.private_key().diffie_hellman(&keypair2.public_key());
                let _shared2 = keypair2.private_key().diffie_hellman(&keypair1.public_key());
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.finish();
}

fn bench_hashing(c: &mut Criterion) {
    init_test_env();

    let sizes = vec![64, 256, 1024, 4096, 16384, 65536]; // Various data sizes

    let mut group = c.benchmark_group("hashing");

    for &size in &sizes {
        let data = crypto::random_data(size);

        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::new("blake3", size), &size, |b, _| {
            b.iter(|| {
                let _hash = blake3::hash(&data);
            });
        });

        // Compare with other hash functions
        group.bench_with_input(BenchmarkId::new("sha256", size), &size, |b, _| {
            b.iter(|| {
                use sha2::{Sha256, Digest};
                let mut hasher = Sha256::new();
                hasher.update(&data);
                let _hash = hasher.finalize();
            });
        });
    }

    group.finish();
}

fn bench_signature_operations(c: &mut Criterion) {
    init_test_env();

    let keypair = KeyPair::generate();
    let message = b"test message for signing performance benchmark";

    let mut group = c.benchmark_group("signatures");

    group.bench_function("sign", |b| {
        b.iter(|| {
            let _signature = keypair.private_key().sign(message);
        });
    });

    let signature = keypair.private_key().sign(message);
    group.bench_function("verify", |b| {
        b.iter(|| {
            let _valid = keypair.public_key().verify(message, &signature).is_ok();
        });
    });

    // Benchmark batch verification
    let messages: Vec<&[u8]> = (0..100).map(|_| message).collect();
    let signatures: Vec<_> = messages.iter().map(|msg| keypair.private_key().sign(msg)).collect();

    group.bench_function("batch_verify_100", |b| {
        b.iter(|| {
            for (msg, sig) in messages.iter().zip(signatures.iter()) {
                let _valid = keypair.public_key().verify(msg, sig).is_ok();
            }
        });
    });

    group.finish();
}

fn bench_crypto_roundtrip(c: &mut Criterion) {
    init_test_env();

    let key = [42u8; 32];
    let sizes = vec![1024, 4096, 16384, 65536]; // Common data sizes

    let mut group = c.benchmark_group("crypto_roundtrip");

    for &size in &sizes {
        let data = crypto::random_data(size);

        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::new("encrypt_decrypt", size), &size, |b, _| {
            b.iter(|| {
                let encrypted = encrypt_data(&key, &data).expect("Encryption should succeed");
                let _decrypted = decrypt_data(&key, &encrypted).expect("Decryption should succeed");
            });
        });
    }

    group.finish();
}

fn bench_concurrent_encryption(c: &mut Criterion) {
    init_test_env();

    let rt = tokio::runtime::Runtime::new().unwrap();
    let key = [42u8; 32];
    let data = crypto::random_data(4096); // 4KB test data

    let mut group = c.benchmark_group("concurrent_encryption");

    let concurrency_levels = vec![1, 2, 4, 8, 16];

    for &concurrency in &concurrency_levels {
        group.throughput(Throughput::Elements(concurrency as u64));

        group.bench_with_input(
            BenchmarkId::new("parallel_encrypt", concurrency),
            &concurrency,
            |b, &concurrency| {
                b.to_async(&rt).iter(|| async {
                    let mut handles = Vec::new();

                    for _ in 0..concurrency {
                        let data = data.clone();
                        let handle = tokio::task::spawn_blocking(move || {
                            encrypt_data(&key, &data).expect("Encryption should succeed")
                        });
                        handles.push(handle);
                    }

                    for handle in handles {
                        let _ = handle.await.expect("Task should complete");
                    }
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_key_generation,
    bench_encryption_sizes,
    bench_key_exchange,
    bench_hashing,
    bench_signature_operations,
    bench_crypto_roundtrip,
    bench_concurrent_encryption
);
criterion_main!(benches);