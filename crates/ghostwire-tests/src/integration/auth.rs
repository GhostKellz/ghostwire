//! Authentication integration tests

use crate::{TestConfig, TestResult, TestSuite, common::{TestClient, TestServer}};
use anyhow::Result;

pub struct AuthTestSuite;

#[async_trait::async_trait]
impl TestSuite for AuthTestSuite {
    fn name(&self) -> &str {
        "Authentication Tests"
    }

    async fn run_tests(&self, _config: &TestConfig) -> Result<Vec<TestResult>> {
        let mut results = Vec::new();

        // Test JWT token validation
        let (result, duration) = crate::common::timing::measure_async(
            test_jwt_token_validation()
        ).await;

        match result {
            Ok(_) => results.push(TestResult::success("jwt_token_validation", duration.as_millis() as u64)),
            Err(e) => results.push(TestResult::failure("jwt_token_validation", duration.as_millis() as u64, e.to_string())),
        }

        Ok(results)
    }
}

async fn test_jwt_token_validation() -> Result<()> {
    let mut server = TestServer::new().await?;
    server.start().await?;

    let client = TestClient::new(server.base_url());

    // Test auth endpoints
    let auth_response = client.get("/api/v1/auth/info").await?;
    if !auth_response.status().is_success() {
        anyhow::bail!("Auth info endpoint failed: {}", auth_response.status());
    }

    server.stop().await?;
    Ok(())
}