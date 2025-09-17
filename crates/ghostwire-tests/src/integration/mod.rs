//! Integration tests for GhostWire components

pub mod auth;
pub mod database;
pub mod derp;
pub mod dns;
pub mod mesh;
pub mod server;

use crate::{TestConfig, TestResult, TestSuite};
use anyhow::Result;

/// Complete integration test suite
pub struct IntegrationTestSuite;

#[async_trait::async_trait]
impl TestSuite for IntegrationTestSuite {
    fn name(&self) -> &str {
        "Integration Tests"
    }

    async fn run_tests(&self, config: &TestConfig) -> Result<Vec<TestResult>> {
        let mut results = Vec::new();

        // Run all integration test suites
        let suites: Vec<Box<dyn TestSuite + Send + Sync>> = vec![
            Box::new(server::ServerTestSuite),
            Box::new(auth::AuthTestSuite),
            Box::new(database::DatabaseTestSuite),
            Box::new(derp::DerpTestSuite),
            Box::new(dns::DnsTestSuite),
            Box::new(mesh::MeshTestSuite),
        ];

        for suite in suites {
            suite.setup(config).await?;
            let mut suite_results = suite.run_tests(config).await?;
            results.append(&mut suite_results);
            suite.teardown(config).await?;
        }

        Ok(results)
    }
}