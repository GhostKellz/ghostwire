use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};
use url::Url;

use crate::config::{AuthConfig, OidcConfig};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthInfo {
    pub node_key: String,
    pub machine_key: String,
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub expires_at: Option<SystemTime>,
    pub user_info: Option<UserInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfo {
    pub id: String,
    pub email: String,
    pub name: String,
    pub groups: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreAuthKey {
    pub key: String,
    pub expires_at: Option<SystemTime>,
    pub reusable: bool,
    pub ephemeral: bool,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone)]
pub enum AuthMethod {
    WebFlow {
        auth_url: String,
        registration_id: String,
    },
    PreAuthKey {
        key: String,
    },
    OAuth {
        provider_url: String,
        client_id: String,
        scopes: Vec<String>,
    },
    CommandLine {
        username: String,
        namespace: String,
    },
}

#[derive(Debug, Clone)]
pub enum AuthState {
    Unauthenticated,
    Pending {
        method: AuthMethod,
        started_at: SystemTime,
    },
    Authenticated {
        info: AuthInfo,
        authenticated_at: SystemTime,
    },
    Failed {
        error: String,
        failed_at: SystemTime,
    },
}

pub struct AuthManager {
    config: AuthConfig,
    state: Arc<RwLock<AuthState>>,
    client: reqwest::Client,
    keyring: Option<keyring::Entry>,
}

impl AuthManager {
    pub fn new(config: AuthConfig) -> Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("GhostWire-Client/1.0")
            .build()
            .context("failed to create HTTP client")?;

        let keyring = if config.store_credentials {
            match keyring::Entry::new("ghostwire", &config.machine_name) {
                Ok(entry) => Some(entry),
                Err(e) => {
                    warn!("Failed to initialize keyring: {}", e);
                    None
                }
            }
        } else {
            None
        };

        Ok(Self {
            config,
            state: Arc::new(RwLock::new(AuthState::Unauthenticated)),
            client,
            keyring,
        })
    }

    pub async fn get_state(&self) -> AuthState {
        self.state.read().await.clone()
    }

    pub async fn authenticate(&self, method: AuthMethod) -> Result<()> {
        info!("Starting authentication with method: {:?}", method);

        {
            let mut state = self.state.write().await;
            *state = AuthState::Pending {
                method: method.clone(),
                started_at: SystemTime::now(),
            };
        }

        let result = match method {
            AuthMethod::WebFlow { auth_url, registration_id } => {
                self.authenticate_web_flow(&auth_url, &registration_id).await
            }
            AuthMethod::PreAuthKey { key } => {
                self.authenticate_preauth_key(&key).await
            }
            AuthMethod::OAuth { provider_url, client_id, scopes } => {
                self.authenticate_oauth(&provider_url, &client_id, &scopes).await
            }
            AuthMethod::CommandLine { username, namespace } => {
                self.authenticate_command_line(&username, &namespace).await
            }
        };

        match result {
            Ok(auth_info) => {
                info!("Authentication successful");
                let mut state = self.state.write().await;
                *state = AuthState::Authenticated {
                    info: auth_info.clone(),
                    authenticated_at: SystemTime::now(),
                };

                if let Some(keyring) = &self.keyring {
                    if let Err(e) = self.store_credentials(&auth_info, keyring).await {
                        warn!("Failed to store credentials in keyring: {}", e);
                    }
                }

                Ok(())
            }
            Err(e) => {
                error!("Authentication failed: {}", e);
                let mut state = self.state.write().await;
                *state = AuthState::Failed {
                    error: e.to_string(),
                    failed_at: SystemTime::now(),
                };
                Err(e)
            }
        }
    }

    pub async fn restore_credentials(&self) -> Result<bool> {
        if let Some(keyring) = &self.keyring {
            match keyring.get_password() {
                Ok(credentials_json) => {
                    match serde_json::from_str::<AuthInfo>(&credentials_json) {
                        Ok(auth_info) => {
                            if self.is_auth_info_valid(&auth_info) {
                                info!("Restored authentication from keyring");
                                let mut state = self.state.write().await;
                                *state = AuthState::Authenticated {
                                    info: auth_info,
                                    authenticated_at: SystemTime::now(),
                                };
                                return Ok(true);
                            } else {
                                info!("Stored credentials are expired or invalid");
                                self.clear_stored_credentials().await?;
                            }
                        }
                        Err(e) => {
                            warn!("Failed to parse stored credentials: {}", e);
                            self.clear_stored_credentials().await?;
                        }
                    }
                }
                Err(keyring::Error::NoEntry) => {
                    debug!("No stored credentials found");
                }
                Err(e) => {
                    warn!("Failed to access keyring: {}", e);
                }
            }
        }
        Ok(false)
    }

    pub async fn refresh_token(&self) -> Result<()> {
        let current_state = self.state.read().await.clone();

        if let AuthState::Authenticated { info, .. } = current_state {
            if let Some(refresh_token) = &info.refresh_token {
                match self.perform_token_refresh(refresh_token).await {
                    Ok(new_auth_info) => {
                        info!("Token refreshed successfully");
                        let mut state = self.state.write().await;
                        *state = AuthState::Authenticated {
                            info: new_auth_info,
                            authenticated_at: SystemTime::now(),
                        };
                        Ok(())
                    }
                    Err(e) => {
                        warn!("Token refresh failed: {}", e);
                        self.clear_authentication().await;
                        Err(e)
                    }
                }
            } else {
                Err(anyhow::anyhow!("No refresh token available"))
            }
        } else {
            Err(anyhow::anyhow!("Not authenticated"))
        }
    }

    pub async fn logout(&self) -> Result<()> {
        info!("Logging out");
        self.clear_authentication().await;
        self.clear_stored_credentials().await?;
        Ok(())
    }

    async fn authenticate_web_flow(&self, auth_url: &str, registration_id: &str) -> Result<AuthInfo> {
        info!("Starting web authentication flow");

        // Open browser for user authentication
        if let Err(e) = open::that(auth_url) {
            warn!("Failed to open browser: {}", e);
            println!("Please open this URL in your browser: {}", auth_url);
        } else {
            println!("Opening browser for authentication...");
        }

        // Poll for completion
        self.poll_registration_completion(registration_id).await
    }

    async fn authenticate_preauth_key(&self, key: &str) -> Result<AuthInfo> {
        info!("Authenticating with pre-auth key");

        let request_body = serde_json::json!({
            "authKey": key,
            "nodeKey": self.generate_node_key()?,
            "machineKey": self.generate_machine_key()?,
            "hostname": self.config.machine_name,
            "os": std::env::consts::OS,
            "arch": std::env::consts::ARCH,
        });

        let response = self.client
            .post(&format!("{}/api/v1/node/register", self.config.server_url))
            .json(&request_body)
            .send()
            .await
            .context("failed to register with pre-auth key")?;

        if response.status().is_success() {
            let auth_info: AuthInfo = response.json().await
                .context("failed to parse registration response")?;
            Ok(auth_info)
        } else {
            let error_text = response.text().await.unwrap_or_default();
            Err(anyhow::anyhow!("Registration failed: {}", error_text))
        }
    }

    async fn authenticate_oauth(&self, provider_url: &str, client_id: &str, scopes: &[String]) -> Result<AuthInfo> {
        info!("Starting OAuth flow");

        let redirect_uri = format!("http://localhost:{}/oauth/callback", self.config.oauth_port);
        let state = uuid::Uuid::new_v4().to_string();
        let nonce = uuid::Uuid::new_v4().to_string();

        let mut auth_url = Url::parse(&format!("{}/auth", provider_url))?;
        auth_url.query_pairs_mut()
            .append_pair("client_id", client_id)
            .append_pair("redirect_uri", &redirect_uri)
            .append_pair("response_type", "code")
            .append_pair("scope", &scopes.join(" "))
            .append_pair("state", &state)
            .append_pair("nonce", &nonce);

        // Start local callback server
        let callback_result = self.start_oauth_callback_server(&state).await?;

        // Open browser
        if let Err(e) = open::that(auth_url.as_str()) {
            warn!("Failed to open browser: {}", e);
            println!("Please open this URL in your browser: {}", auth_url);
        }

        // Wait for callback
        let auth_code = callback_result.await?;

        // Exchange code for token
        self.exchange_oauth_code(&auth_code, provider_url, client_id, &redirect_uri).await
    }

    async fn authenticate_command_line(&self, username: &str, namespace: &str) -> Result<AuthInfo> {
        info!("Authenticating via command line for user: {} in namespace: {}", username, namespace);

        let request_body = serde_json::json!({
            "user": username,
            "namespace": namespace,
            "nodeKey": self.generate_node_key()?,
            "machineKey": self.generate_machine_key()?,
            "hostname": self.config.machine_name,
            "os": std::env::consts::OS,
            "arch": std::env::consts::ARCH,
        });

        let response = self.client
            .post(&format!("{}/api/v1/node/register/cli", self.config.server_url))
            .json(&request_body)
            .send()
            .await
            .context("failed to register via command line")?;

        if response.status().is_success() {
            let auth_info: AuthInfo = response.json().await
                .context("failed to parse CLI registration response")?;
            Ok(auth_info)
        } else {
            let error_text = response.text().await.unwrap_or_default();
            Err(anyhow::anyhow!("CLI registration failed: {}", error_text))
        }
    }

    async fn poll_registration_completion(&self, registration_id: &str) -> Result<AuthInfo> {
        let poll_url = format!("{}/api/v1/register/{}", self.config.server_url, registration_id);
        let mut interval = tokio::time::interval(Duration::from_secs(2));
        let timeout = SystemTime::now() + Duration::from_secs(300); // 5 minute timeout

        loop {
            interval.tick().await;

            if SystemTime::now() > timeout {
                return Err(anyhow::anyhow!("Registration timeout"));
            }

            let response = self.client
                .get(&poll_url)
                .send()
                .await
                .context("failed to poll registration status")?;

            match response.status() {
                reqwest::StatusCode::OK => {
                    let auth_info: AuthInfo = response.json().await
                        .context("failed to parse registration completion response")?;
                    return Ok(auth_info);
                }
                reqwest::StatusCode::NOT_FOUND => {
                    return Err(anyhow::anyhow!("Registration not found"));
                }
                reqwest::StatusCode::ACCEPTED => {
                    // Still pending, continue polling
                    continue;
                }
                _ => {
                    let error_text = response.text().await.unwrap_or_default();
                    return Err(anyhow::anyhow!("Registration polling failed: {}", error_text));
                }
            }
        }
    }

    async fn start_oauth_callback_server(&self, expected_state: &str) -> Result<tokio::task::JoinHandle<Result<String>>> {
        use tokio::net::TcpListener;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = TcpListener::bind(format!("127.0.0.1:{}", self.config.oauth_port)).await
            .context("failed to bind OAuth callback server")?;

        let expected_state = expected_state.to_string();

        Ok(tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;

            let mut buffer = [0; 1024];
            let n = stream.read(&mut buffer).await?;
            let request = String::from_utf8_lossy(&buffer[..n]);

            // Parse HTTP request for auth code
            if let Some(first_line) = request.lines().next() {
                if let Some(query_part) = first_line.split_whitespace().nth(1) {
                    if let Some(query) = query_part.split('?').nth(1) {
                        let params: HashMap<String, String> = query
                            .split('&')
                            .filter_map(|param| {
                                let mut parts = param.splitn(2, '=');
                                Some((parts.next()?.to_string(), parts.next()?.to_string()))
                            })
                            .collect();

                        if let (Some(state), Some(code)) = (params.get("state"), params.get("code")) {
                            if state == &expected_state {
                                let response = "HTTP/1.1 200 OK\r\n\r\nAuthentication successful! You can close this window.";
                                stream.write_all(response.as_bytes()).await?;
                                return Ok(code.clone());
                            }
                        }
                    }
                }
            }

            let error_response = "HTTP/1.1 400 Bad Request\r\n\r\nAuthentication failed.";
            stream.write_all(error_response.as_bytes()).await?;
            Err(anyhow::anyhow!("Invalid OAuth callback"))
        }))
    }

    async fn exchange_oauth_code(&self, code: &str, provider_url: &str, client_id: &str, redirect_uri: &str) -> Result<AuthInfo> {
        let token_url = format!("{}/token", provider_url);

        let token_request = serde_json::json!({
            "grant_type": "authorization_code",
            "code": code,
            "client_id": client_id,
            "redirect_uri": redirect_uri,
        });

        let response = self.client
            .post(&token_url)
            .json(&token_request)
            .send()
            .await
            .context("failed to exchange OAuth code")?;

        if response.status().is_success() {
            let token_response: serde_json::Value = response.json().await
                .context("failed to parse token response")?;

            let access_token = token_response["access_token"].as_str()
                .ok_or_else(|| anyhow::anyhow!("missing access_token in response"))?;

            // Get user info
            let user_info = self.get_user_info(provider_url, access_token).await?;

            Ok(AuthInfo {
                node_key: self.generate_node_key()?,
                machine_key: self.generate_machine_key()?,
                access_token: Some(access_token.to_string()),
                refresh_token: token_response["refresh_token"].as_str().map(|s| s.to_string()),
                expires_at: token_response["expires_in"].as_u64().map(|exp| {
                    SystemTime::now() + Duration::from_secs(exp)
                }),
                user_info: Some(user_info),
            })
        } else {
            let error_text = response.text().await.unwrap_or_default();
            Err(anyhow::anyhow!("Token exchange failed: {}", error_text))
        }
    }

    async fn get_user_info(&self, provider_url: &str, access_token: &str) -> Result<UserInfo> {
        let userinfo_url = format!("{}/userinfo", provider_url);

        let response = self.client
            .get(&userinfo_url)
            .bearer_auth(access_token)
            .send()
            .await
            .context("failed to get user info")?;

        if response.status().is_success() {
            let user_data: serde_json::Value = response.json().await
                .context("failed to parse user info")?;

            Ok(UserInfo {
                id: user_data["sub"].as_str().unwrap_or_default().to_string(),
                email: user_data["email"].as_str().unwrap_or_default().to_string(),
                name: user_data["name"].as_str().unwrap_or_default().to_string(),
                groups: user_data["groups"].as_array()
                    .map(|arr| arr.iter().filter_map(|v| v.as_str()).map(|s| s.to_string()).collect())
                    .unwrap_or_default(),
            })
        } else {
            Err(anyhow::anyhow!("Failed to get user info"))
        }
    }

    async fn perform_token_refresh(&self, refresh_token: &str) -> Result<AuthInfo> {
        if let Some(oidc_config) = &self.config.oidc {
            let token_url = format!("{}/token", oidc_config.issuer_url);

            let refresh_request = serde_json::json!({
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": oidc_config.client_id,
            });

            let response = self.client
                .post(&token_url)
                .json(&refresh_request)
                .send()
                .await
                .context("failed to refresh token")?;

            if response.status().is_success() {
                let token_response: serde_json::Value = response.json().await
                    .context("failed to parse refresh response")?;

                let access_token = token_response["access_token"].as_str()
                    .ok_or_else(|| anyhow::anyhow!("missing access_token in refresh response"))?;

                let user_info = self.get_user_info(&oidc_config.issuer_url, access_token).await?;

                Ok(AuthInfo {
                    node_key: self.generate_node_key()?,
                    machine_key: self.generate_machine_key()?,
                    access_token: Some(access_token.to_string()),
                    refresh_token: token_response["refresh_token"].as_str().map(|s| s.to_string()),
                    expires_at: token_response["expires_in"].as_u64().map(|exp| {
                        SystemTime::now() + Duration::from_secs(exp)
                    }),
                    user_info: Some(user_info),
                })
            } else {
                Err(anyhow::anyhow!("Token refresh failed"))
            }
        } else {
            Err(anyhow::anyhow!("OIDC not configured"))
        }
    }

    async fn store_credentials(&self, auth_info: &AuthInfo, keyring: &keyring::Entry) -> Result<()> {
        let credentials_json = serde_json::to_string(auth_info)
            .context("failed to serialize auth info")?;

        keyring.set_password(&credentials_json)
            .context("failed to store credentials in keyring")?;

        Ok(())
    }

    async fn clear_stored_credentials(&self) -> Result<()> {
        if let Some(keyring) = &self.keyring {
            match keyring.delete_password() {
                Ok(_) => debug!("Cleared stored credentials"),
                Err(keyring::Error::NoEntry) => debug!("No stored credentials to clear"),
                Err(e) => warn!("Failed to clear stored credentials: {}", e),
            }
        }
        Ok(())
    }

    async fn clear_authentication(&self) {
        let mut state = self.state.write().await;
        *state = AuthState::Unauthenticated;
    }

    fn is_auth_info_valid(&self, auth_info: &AuthInfo) -> bool {
        if let Some(expires_at) = auth_info.expires_at {
            SystemTime::now() < expires_at
        } else {
            true // No expiration set, assume valid
        }
    }

    fn generate_node_key(&self) -> Result<String> {
        // Generate a new node key - in real implementation this would use Tailscale's key generation
        Ok(format!("nodekey_{}", uuid::Uuid::new_v4().simple()))
    }

    fn generate_machine_key(&self) -> Result<String> {
        // Generate a new machine key - in real implementation this would use Tailscale's key generation
        Ok(format!("machinekey_{}", uuid::Uuid::new_v4().simple()))
    }

    pub async fn get_auth_header(&self) -> Option<String> {
        let state = self.state.read().await;
        if let AuthState::Authenticated { info, .. } = &*state {
            info.access_token.as_ref().map(|token| format!("Bearer {}", token))
        } else {
            None
        }
    }

    pub async fn is_authenticated(&self) -> bool {
        matches!(*self.state.read().await, AuthState::Authenticated { .. })
    }
}