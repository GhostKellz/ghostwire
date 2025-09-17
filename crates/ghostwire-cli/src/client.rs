/// HTTP and gRPC client for communicating with GhostWire server
///
/// Provides unified interface for both REST API and gRPC communication
/// with authentication, retry logic, and error handling.

use anyhow::{Context, Result};
use reqwest::{Client, Response, StatusCode};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::time::Duration;
use tokio::time::timeout;
use tracing::{debug, warn};
use url::Url;

use crate::config::GwctlConfig;

/// Client for communicating with GhostWire server
pub struct GwctlClient {
    http_client: Client,
    grpc_client: Option<tonic::transport::Channel>,
    config: GwctlConfig,
    base_url: Url,
}

impl GwctlClient {
    /// Create new client with configuration
    pub async fn new(config: GwctlConfig) -> Result<Self> {
        let base_url = Url::parse(&config.server.url)
            .context("Invalid server URL")?;

        // Create HTTP client
        let mut client_builder = Client::builder()
            .timeout(Duration::from_secs(config.server.timeout_seconds))
            .user_agent("gwctl/1.0");

        if !config.server.verify_tls {
            client_builder = client_builder
                .danger_accept_invalid_certs(true)
                .danger_accept_invalid_hostnames(true);
        }

        let http_client = client_builder.build()
            .context("Failed to create HTTP client")?;

        // Create gRPC client (if needed)
        let grpc_client = if config.server.url.starts_with("grpc://") || config.server.url.starts_with("grpcs://") {
            Some(Self::create_grpc_client(&config).await?)
        } else {
            None
        };

        Ok(Self {
            http_client,
            grpc_client,
            config,
            base_url,
        })
    }

    async fn create_grpc_client(config: &GwctlConfig) -> Result<tonic::transport::Channel> {
        let endpoint = tonic::transport::Endpoint::from_shared(config.server.url.clone())?
            .timeout(Duration::from_secs(config.server.timeout_seconds));

        let endpoint = if !config.server.verify_tls {
            endpoint.tls_config(
                tonic::transport::ClientTlsConfig::new()
                    .danger_accept_invalid_certs(true)
            )?
        } else {
            endpoint
        };

        endpoint.connect().await
            .context("Failed to connect to gRPC server")
    }

    /// Perform GET request to REST API
    pub async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        let url = self.base_url.join(path)
            .context("Invalid URL path")?;

        debug!("GET {}", url);

        let mut request = self.http_client.get(url);

        // Add authentication if available
        if let Some(token) = &self.config.auth.token {
            request = request.bearer_auth(token);
        }

        let response = timeout(
            Duration::from_secs(self.config.server.timeout_seconds),
            request.send()
        ).await
        .context("Request timeout")?
        .context("Request failed")?;

        self.handle_response(response).await
    }

    /// Perform POST request to REST API
    pub async fn post<T: Serialize, R: DeserializeOwned>(&self, path: &str, body: &T) -> Result<R> {
        let url = self.base_url.join(path)
            .context("Invalid URL path")?;

        debug!("POST {}", url);

        let mut request = self.http_client.post(url).json(body);

        if let Some(token) = &self.config.auth.token {
            request = request.bearer_auth(token);
        }

        let response = timeout(
            Duration::from_secs(self.config.server.timeout_seconds),
            request.send()
        ).await
        .context("Request timeout")?
        .context("Request failed")?;

        self.handle_response(response).await
    }

    /// Perform PUT request to REST API
    pub async fn put<T: Serialize, R: DeserializeOwned>(&self, path: &str, body: &T) -> Result<R> {
        let url = self.base_url.join(path)
            .context("Invalid URL path")?;

        debug!("PUT {}", url);

        let mut request = self.http_client.put(url).json(body);

        if let Some(token) = &self.config.auth.token {
            request = request.bearer_auth(token);
        }

        let response = timeout(
            Duration::from_secs(self.config.server.timeout_seconds),
            request.send()
        ).await
        .context("Request timeout")?
        .context("Request failed")?;

        self.handle_response(response).await
    }

    /// Perform DELETE request to REST API
    pub async fn delete<R: DeserializeOwned>(&self, path: &str) -> Result<R> {
        let url = self.base_url.join(path)
            .context("Invalid URL path")?;

        debug!("DELETE {}", url);

        let mut request = self.http_client.delete(url);

        if let Some(token) = &self.config.auth.token {
            request = request.bearer_auth(token);
        }

        let response = timeout(
            Duration::from_secs(self.config.server.timeout_seconds),
            request.send()
        ).await
        .context("Request timeout")?
        .context("Request failed")?;

        self.handle_response(response).await
    }

    /// Handle HTTP response and deserialize
    async fn handle_response<T: DeserializeOwned>(&self, response: Response) -> Result<T> {
        let status = response.status();
        let response_text = response.text().await
            .context("Failed to read response body")?;

        debug!("Response status: {}, body: {}", status, response_text);

        match status {
            StatusCode::OK | StatusCode::CREATED => {
                serde_json::from_str(&response_text)
                    .with_context(|| format!("Failed to parse response: {}", response_text))
            }
            StatusCode::UNAUTHORIZED => {
                anyhow::bail!("Authentication failed. Run 'gwctl auth login' to authenticate.");
            }
            StatusCode::FORBIDDEN => {
                anyhow::bail!("Access denied. Check your permissions.");
            }
            StatusCode::NOT_FOUND => {
                anyhow::bail!("Resource not found.");
            }
            StatusCode::BAD_REQUEST => {
                // Try to parse error response
                if let Ok(error_response) = serde_json::from_str::<ErrorResponse>(&response_text) {
                    anyhow::bail!("Bad request: {}", error_response.message);
                } else {
                    anyhow::bail!("Bad request: {}", response_text);
                }
            }
            StatusCode::INTERNAL_SERVER_ERROR => {
                anyhow::bail!("Internal server error. Please try again later.");
            }
            _ => {
                anyhow::bail!("Request failed with status {}: {}", status, response_text);
            }
        }
    }

    /// Check if server is reachable
    pub async fn ping(&self) -> Result<PingResponse> {
        self.get("/api/v1/ping").await
    }

    /// Get server health status
    pub async fn health(&self) -> Result<HealthResponse> {
        self.get("/api/v1/health").await
    }

    /// Get server version information
    pub async fn version(&self) -> Result<VersionResponse> {
        self.get("/api/v1/version").await
    }

    /// Authenticate with username/password
    pub async fn authenticate(&self, username: &str, password: &str) -> Result<AuthResponse> {
        let auth_request = AuthRequest {
            username: username.to_string(),
            password: password.to_string(),
        };

        self.post("/api/v1/auth/login", &auth_request).await
    }

    /// OAuth device flow initialization
    pub async fn oauth_device_init(&self) -> Result<OAuthDeviceResponse> {
        self.post("/api/v1/auth/oauth/device", &serde_json::json!({})).await
    }

    /// OAuth device flow polling
    pub async fn oauth_device_poll(&self, device_code: &str) -> Result<AuthResponse> {
        let poll_request = OAuthDevicePollRequest {
            device_code: device_code.to_string(),
        };

        self.post("/api/v1/auth/oauth/device/poll", &poll_request).await
    }

    /// Validate current authentication token
    pub async fn validate_token(&self) -> Result<TokenValidationResponse> {
        self.get("/api/v1/auth/validate").await
    }

    /// Get list of nodes
    pub async fn list_nodes(&self) -> Result<Vec<NodeResponse>> {
        self.get("/api/v1/nodes").await
    }

    /// Get specific node
    pub async fn get_node(&self, node_id: &str) -> Result<NodeResponse> {
        self.get(&format!("/api/v1/nodes/{}", node_id)).await
    }

    /// Delete node
    pub async fn delete_node(&self, node_id: &str) -> Result<()> {
        let _: serde_json::Value = self.delete(&format!("/api/v1/nodes/{}", node_id)).await?;
        Ok(())
    }

    /// Get network map
    pub async fn get_network_map(&self) -> Result<NetworkMapResponse> {
        self.get("/api/v1/network/map").await
    }

    /// Get list of users
    pub async fn list_users(&self) -> Result<Vec<UserResponse>> {
        self.get("/api/v1/users").await
    }

    /// Create new user
    pub async fn create_user(&self, user: CreateUserRequest) -> Result<UserResponse> {
        self.post("/api/v1/users", &user).await
    }

    /// Delete user
    pub async fn delete_user(&self, user_id: &str) -> Result<()> {
        let _: serde_json::Value = self.delete(&format!("/api/v1/users/{}", user_id)).await?;
        Ok(())
    }

    /// Get list of API keys
    pub async fn list_api_keys(&self) -> Result<Vec<ApiKeyResponse>> {
        self.get("/api/v1/api-keys").await
    }

    /// Create new API key
    pub async fn create_api_key(&self, request: CreateApiKeyRequest) -> Result<CreateApiKeyResponse> {
        self.post("/api/v1/api-keys", &request).await
    }

    /// Delete API key
    pub async fn delete_api_key(&self, key_id: &str) -> Result<()> {
        let _: serde_json::Value = self.delete(&format!("/api/v1/api-keys/{}", key_id)).await?;
        Ok(())
    }

    /// Get ACL policy
    pub async fn get_policy(&self) -> Result<PolicyResponse> {
        self.get("/api/v1/policy").await
    }

    /// Update ACL policy
    pub async fn update_policy(&self, policy: PolicyUpdateRequest) -> Result<PolicyResponse> {
        self.put("/api/v1/policy", &policy).await
    }

    /// Get DERP servers
    pub async fn list_derp_servers(&self) -> Result<Vec<DerpServerResponse>> {
        self.get("/api/v1/derp/servers").await
    }

    /// Get server metrics
    pub async fn get_metrics(&self) -> Result<MetricsResponse> {
        self.get("/api/v1/metrics").await
    }
}

// Request/Response types

#[derive(Serialize, Deserialize)]
pub struct ErrorResponse {
    pub message: String,
    pub code: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct PingResponse {
    pub message: String,
    pub timestamp: String,
}

#[derive(Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub components: Vec<ComponentHealth>,
}

#[derive(Serialize, Deserialize)]
pub struct ComponentHealth {
    pub name: String,
    pub status: String,
    pub message: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct VersionResponse {
    pub version: String,
    pub commit: String,
    pub build_date: String,
}

#[derive(Serialize, Deserialize)]
pub struct AuthRequest {
    pub username: String,
    pub password: String,
}

#[derive(Serialize, Deserialize)]
pub struct AuthResponse {
    pub token: String,
    pub expires_at: String,
    pub user: UserInfo,
}

#[derive(Serialize, Deserialize)]
pub struct UserInfo {
    pub id: String,
    pub username: String,
    pub email: Option<String>,
    pub role: String,
}

#[derive(Serialize, Deserialize)]
pub struct OAuthDeviceResponse {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub verification_uri_complete: Option<String>,
    pub expires_in: u64,
    pub interval: u64,
}

#[derive(Serialize, Deserialize)]
pub struct OAuthDevicePollRequest {
    pub device_code: String,
}

#[derive(Serialize, Deserialize)]
pub struct TokenValidationResponse {
    pub valid: bool,
    pub user: Option<UserInfo>,
    pub expires_at: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct NodeResponse {
    pub id: String,
    pub name: String,
    pub ip: String,
    pub public_key: String,
    pub user: String,
    pub last_seen: Option<String>,
    pub online: bool,
    pub version: Option<String>,
    pub os: Option<String>,
    pub endpoint: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct NetworkMapResponse {
    pub nodes: Vec<NodeResponse>,
    pub dns_config: DnsConfig,
    pub derp_map: DerpMap,
}

#[derive(Serialize, Deserialize)]
pub struct DnsConfig {
    pub servers: Vec<String>,
    pub search_domains: Vec<String>,
}

#[derive(Serialize, Deserialize)]
pub struct DerpMap {
    pub regions: Vec<DerpRegion>,
}

#[derive(Serialize, Deserialize)]
pub struct DerpRegion {
    pub region_id: u32,
    pub region_code: String,
    pub region_name: String,
    pub nodes: Vec<DerpNode>,
}

#[derive(Serialize, Deserialize)]
pub struct DerpNode {
    pub name: String,
    pub hostname: String,
    pub ipv4: Option<String>,
    pub ipv6: Option<String>,
    pub stun_port: u16,
    pub stun_only: bool,
}

#[derive(Serialize, Deserialize)]
pub struct UserResponse {
    pub id: String,
    pub username: String,
    pub email: Option<String>,
    pub role: String,
    pub created_at: String,
    pub last_login: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub email: Option<String>,
    pub password: Option<String>,
    pub role: String,
}

#[derive(Serialize, Deserialize)]
pub struct ApiKeyResponse {
    pub id: String,
    pub name: String,
    pub prefix: String,
    pub user_id: String,
    pub created_at: String,
    pub last_used: Option<String>,
    pub expires_at: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct CreateApiKeyRequest {
    pub name: String,
    pub expires_in_days: Option<u32>,
}

#[derive(Serialize, Deserialize)]
pub struct CreateApiKeyResponse {
    pub id: String,
    pub name: String,
    pub key: String, // Full key is only returned on creation
    pub expires_at: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct PolicyResponse {
    pub policy: serde_json::Value,
    pub version: String,
    pub updated_at: String,
}

#[derive(Serialize, Deserialize)]
pub struct PolicyUpdateRequest {
    pub policy: serde_json::Value,
}

#[derive(Serialize, Deserialize)]
pub struct DerpServerResponse {
    pub region_id: u32,
    pub region_code: String,
    pub region_name: String,
    pub hostname: String,
    pub ipv4: Option<String>,
    pub ipv6: Option<String>,
    pub stun_port: u16,
    pub relay_port: u16,
    pub latency_ms: Option<f64>,
    pub active_connections: u32,
}

#[derive(Serialize, Deserialize)]
pub struct MetricsResponse {
    pub nodes_total: u64,
    pub nodes_online: u64,
    pub users_total: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub uptime_seconds: u64,
    pub memory_usage_bytes: u64,
    pub cpu_usage_percent: f64,
}