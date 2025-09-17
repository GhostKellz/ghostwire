//! Integration tests and benchmarks for GhostWire
//!
//! This crate provides comprehensive testing infrastructure for the GhostWire
//! mesh VPN system, including:
//!
//! - Integration tests across all components
//! - Performance benchmarks and stress tests
//! - Network topology testing
//! - Security and encryption validation
//! - Chaos engineering tests
//! - End-to-end scenarios

pub mod common;
pub mod integration;
pub mod performance;
pub mod scenarios;
pub mod utils;

// Re-export common testing utilities
pub use common::*;
pub use utils::*;

use anyhow::Result;
use std::sync::Once;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

static INIT: Once = Once::new();

/// Initialize test environment with logging and tracing
pub fn init_test_env() {
    INIT.call_once(|| {
        tracing_subscriber::registry()
            .with(fmt::layer().with_test_writer())
            .with(EnvFilter::from_default_env().add_directive("ghostwire=debug".parse().unwrap()))
            .init();
    });
}

/// Test configuration for controlling test behavior
#[derive(Debug, Clone)]
pub struct TestConfig {
    /// Enable detailed logging during tests
    pub verbose: bool,
    /// Number of parallel test instances
    pub parallelism: usize,
    /// Test timeout in seconds
    pub timeout_secs: u64,
    /// Enable performance profiling
    pub profile: bool,
    /// Test data directory
    pub data_dir: Option<std::path::PathBuf>,
}

impl Default for TestConfig {
    fn default() -> Self {
        Self {
            verbose: std::env::var("GHOSTWIRE_TEST_VERBOSE").is_ok(),
            parallelism: std::env::var("GHOSTWIRE_TEST_PARALLELISM")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or_else(num_cpus::get),
            timeout_secs: std::env::var("GHOSTWIRE_TEST_TIMEOUT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(300),
            profile: std::env::var("GHOSTWIRE_TEST_PROFILE").is_ok(),
            data_dir: std::env::var("GHOSTWIRE_TEST_DATA_DIR")
                .ok()
                .map(std::path::PathBuf::from),
        }
    }
}

/// Test result with performance metrics
#[derive(Debug)]
pub struct TestResult {
    pub name: String,
    pub success: bool,
    pub duration_ms: u64,
    pub error: Option<String>,
    pub metrics: std::collections::HashMap<String, f64>,
}

impl TestResult {
    pub fn success(name: impl Into<String>, duration_ms: u64) -> Self {
        Self {
            name: name.into(),
            success: true,
            duration_ms,
            error: None,
            metrics: std::collections::HashMap::new(),
        }
    }

    pub fn failure(name: impl Into<String>, duration_ms: u64, error: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            success: false,
            duration_ms,
            error: Some(error.into()),
            metrics: std::collections::HashMap::new(),
        }
    }

    pub fn with_metric(mut self, key: impl Into<String>, value: f64) -> Self {
        self.metrics.insert(key.into(), value);
        self
    }
}

/// Test suite trait for organizing related tests
pub trait TestSuite {
    /// Name of the test suite
    fn name(&self) -> &str;

    /// Run all tests in the suite
    async fn run_tests(&self, config: &TestConfig) -> Result<Vec<TestResult>>;

    /// Setup before running tests
    async fn setup(&self, config: &TestConfig) -> Result<()> {
        let _ = config;
        Ok(())
    }

    /// Cleanup after running tests
    async fn teardown(&self, config: &TestConfig) -> Result<()> {
        let _ = config;
        Ok(())
    }
}

/// Macro for creating benchmark tests
#[macro_export]
macro_rules! benchmark_test {
    ($name:ident, $test_fn:expr) => {
        #[tokio::test]
        async fn $name() {
            let start = std::time::Instant::now();
            let result = $test_fn().await;
            let duration = start.elapsed();

            match result {
                Ok(_) => println!("✅ {} completed in {:?}", stringify!($name), duration),
                Err(e) => println!("❌ {} failed in {:?}: {}", stringify!($name), duration, e),
            }

            result.expect(&format!("Test {} should pass", stringify!($name)));
        }
    };
}

/// Macro for creating integration tests with setup/teardown
#[macro_export]
macro_rules! integration_test {
    ($name:ident, $setup:expr, $test:expr, $teardown:expr) => {
        #[tokio::test]
        async fn $name() {
            $crate::init_test_env();

            let setup_result = $setup().await;
            if let Err(e) = setup_result {
                panic!("Setup failed for {}: {}", stringify!($name), e);
            }

            let test_result = $test().await;

            let teardown_result = $teardown().await;
            if let Err(e) = teardown_result {
                eprintln!("Teardown failed for {}: {}", stringify!($name), e);
            }

            test_result.expect(&format!("Test {} should pass", stringify!($name)));
        }
    };
}