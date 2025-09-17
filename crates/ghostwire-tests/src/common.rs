//! Common testing utilities and fixtures

use anyhow::{Context, Result};
use ghostwire_common::{
    config::{DatabaseConfig, ServerConfig},
    crypto::KeyPair,
    types::{MachineKey, NodeKey, NetworkKey},
};
use ghostwire_server::Server;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU16, Ordering};
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio::time::{timeout, Duration};
use tracing::{debug, info};

static PORT_COUNTER: AtomicU16 = AtomicU16::new(8000);

/// Get next available port for testing
pub fn get_test_port() -> u16 {
    PORT_COUNTER.fetch_add(1, Ordering::Relaxed)
}

/// Create a temporary directory for test data
pub fn create_test_dir() -> Result<TempDir> {
    tempfile::tempdir().context("Failed to create test directory")
}

/// Wait for a TCP port to become available
pub async fn wait_for_port(addr: SocketAddr, timeout_secs: u64) -> Result<()> {
    let timeout_duration = Duration::from_secs(timeout_secs);

    timeout(timeout_duration, async {
        loop {
            match TcpListener::bind(addr).await {
                Ok(_) => return Ok(()),
                Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
            }
        }
    })
    .await
    .context("Timeout waiting for port to become available")?
}

/// Wait for a service to become ready on a given address
pub async fn wait_for_service(addr: SocketAddr, timeout_secs: u64) -> Result<()> {
    let timeout_duration = Duration::from_secs(timeout_secs);
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;

    timeout(timeout_duration, async {
        loop {
            match client.get(&format!("http://{}/health", addr)).send().await {
                Ok(response) if response.status().is_success() => {
                    debug!("Service at {} is ready", addr);
                    return Ok(());
                }
                _ => {
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
            }
        }
    })
    .await
    .context("Timeout waiting for service to become ready")?
}

/// Test fixtures for creating test entities
pub struct TestFixtures;

impl TestFixtures {
    /// Create a test server configuration
    pub fn server_config(data_dir: &std::path::Path) -> ServerConfig {
        let port = get_test_port();
        let derp_port = get_test_port();

        ServerConfig {
            listen_addr: format!("127.0.0.1:{}", port).parse().unwrap(),
            derp_addr: Some(format!("127.0.0.1:{}", derp_port).parse().unwrap()),
            database: DatabaseConfig {
                url: format!("sqlite://{}/.test.db", data_dir.display()),
                max_connections: 10,
                acquire_timeout_secs: 30,
                idle_timeout_secs: 600,
                max_lifetime_secs: 3600,
            },
            tls: None,
            metrics_addr: None,
        }
    }

    /// Create a test keypair
    pub fn keypair() -> KeyPair {
        KeyPair::generate()
    }

    /// Create a test machine key
    pub fn machine_key() -> MachineKey {
        MachineKey::generate()
    }

    /// Create a test node key
    pub fn node_key() -> NodeKey {
        NodeKey::generate()
    }

    /// Create a test network key
    pub fn network_key() -> NetworkKey {
        NetworkKey::generate()
    }
}

/// Test server instance for integration testing
pub struct TestServer {
    pub server: Server,
    pub config: ServerConfig,
    pub data_dir: TempDir,
    pub handle: Option<tokio::task::JoinHandle<Result<()>>>,
}

impl TestServer {
    /// Create a new test server instance
    pub async fn new() -> Result<Self> {
        let data_dir = create_test_dir()?;
        let config = TestFixtures::server_config(data_dir.path());

        let server = Server::new(config.clone()).await
            .context("Failed to create test server")?;

        Ok(Self {
            server,
            config,
            data_dir,
            handle: None,
        })
    }

    /// Start the test server
    pub async fn start(&mut self) -> Result<()> {
        info!("Starting test server on {}", self.config.listen_addr);

        let server = self.server.clone();
        let handle = tokio::spawn(async move {
            server.run().await
        });

        self.handle = Some(handle);

        // Wait for server to become ready
        wait_for_service(self.config.listen_addr, 30).await
            .context("Test server failed to start")?;

        info!("Test server ready on {}", self.config.listen_addr);
        Ok(())
    }

    /// Stop the test server
    pub async fn stop(&mut self) -> Result<()> {
        if let Some(handle) = self.handle.take() {
            handle.abort();
            match handle.await {
                Ok(Ok(())) => info!("Test server stopped successfully"),
                Ok(Err(e)) => info!("Test server stopped with error: {}", e),
                Err(_) => info!("Test server was aborted"),
            }
        }
        Ok(())
    }

    /// Get the server's HTTP base URL
    pub fn base_url(&self) -> String {
        format!("http://{}", self.config.listen_addr)
    }

    /// Get the server's DERP address
    pub fn derp_addr(&self) -> Option<SocketAddr> {
        self.config.derp_addr
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
    }
}

/// Client for making HTTP requests to test servers
pub struct TestClient {
    client: reqwest::Client,
    base_url: String,
}

impl TestClient {
    /// Create a new test client
    pub fn new(base_url: impl Into<String>) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");

        Self {
            client,
            base_url: base_url.into(),
        }
    }

    /// Make a GET request
    pub async fn get(&self, path: &str) -> Result<reqwest::Response> {
        let url = format!("{}{}", self.base_url, path);
        self.client.get(&url).send().await
            .context("GET request failed")
    }

    /// Make a POST request with JSON body
    pub async fn post_json<T: serde::Serialize>(&self, path: &str, body: &T) -> Result<reqwest::Response> {
        let url = format!("{}{}", self.base_url, path);
        self.client.post(&url)
            .json(body)
            .send()
            .await
            .context("POST request failed")
    }

    /// Make a PUT request with JSON body
    pub async fn put_json<T: serde::Serialize>(&self, path: &str, body: &T) -> Result<reqwest::Response> {
        let url = format!("{}{}", self.base_url, path);
        self.client.put(&url)
            .json(body)
            .send()
            .await
            .context("PUT request failed")
    }

    /// Make a DELETE request
    pub async fn delete(&self, path: &str) -> Result<reqwest::Response> {
        let url = format!("{}{}", self.base_url, path);
        self.client.delete(&url).send().await
            .context("DELETE request failed")
    }

    /// Check if server is healthy
    pub async fn health_check(&self) -> Result<bool> {
        match self.get("/health").await {
            Ok(response) => Ok(response.status().is_success()),
            Err(_) => Ok(false),
        }
    }
}

/// Network testing utilities
pub mod network {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use tokio::net::UdpSocket;

    /// Find an available UDP port
    pub async fn find_udp_port() -> Result<u16> {
        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        Ok(socket.local_addr()?.port())
    }

    /// Create a test IP address
    pub fn test_ip(last_octet: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(100, 64, 0, last_octet))
    }

    /// Measure network latency between two endpoints
    pub async fn measure_latency(addr: SocketAddr) -> Result<Duration> {
        let start = std::time::Instant::now();
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.connect(addr).await?;
        socket.send(b"ping").await?;

        let mut buf = [0u8; 4];
        socket.recv(&mut buf).await?;

        Ok(start.elapsed())
    }
}

/// Crypto testing utilities
pub mod crypto {
    use super::*;
    use ghostwire_common::crypto::{encrypt_data, decrypt_data};
    use rand::RngCore;

    /// Generate random test data
    pub fn random_data(size: usize) -> Vec<u8> {
        let mut data = vec![0u8; size];
        rand::thread_rng().fill_bytes(&mut data);
        data
    }

    /// Test encryption/decryption round trip
    pub fn test_encryption_roundtrip(key: &[u8; 32], data: &[u8]) -> Result<()> {
        let encrypted = encrypt_data(key, data)?;
        let decrypted = decrypt_data(key, &encrypted)?;

        if data != decrypted {
            anyhow::bail!("Encryption roundtrip failed: data mismatch");
        }

        Ok(())
    }

    /// Benchmark encryption performance
    pub fn benchmark_encryption(key: &[u8; 32], data: &[u8], iterations: usize) -> Duration {
        let start = std::time::Instant::now();

        for _ in 0..iterations {
            let _ = encrypt_data(key, data).expect("Encryption should succeed");
        }

        start.elapsed()
    }
}

/// Time measurement utilities
pub mod timing {
    use std::time::{Duration, Instant};

    /// Measure execution time of an async function
    pub async fn measure_async<F, T>(f: F) -> (T, Duration)
    where
        F: std::future::Future<Output = T>,
    {
        let start = Instant::now();
        let result = f.await;
        let duration = start.elapsed();
        (result, duration)
    }

    /// Measure execution time of a sync function
    pub fn measure_sync<F, T>(f: F) -> (T, Duration)
    where
        F: FnOnce() -> T,
    {
        let start = Instant::now();
        let result = f();
        let duration = start.elapsed();
        (result, duration)
    }

    /// Create a timer for manual timing
    pub struct Timer {
        start: Instant,
    }

    impl Timer {
        pub fn start() -> Self {
            Self {
                start: Instant::now(),
            }
        }

        pub fn elapsed(&self) -> Duration {
            self.start.elapsed()
        }

        pub fn reset(&mut self) {
            self.start = Instant::now();
        }
    }
}