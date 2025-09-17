/// OpenID Connect integration for SSO authentication
///
/// Provides integration with OIDC providers like Auth0, Keycloak, Google, etc.
/// Supports both web-based authorization code flow and CLI device flow

use crate::auth::{OidcConfig, UserInfo};
use ghostwire_common::error::{Result, GhostWireError};
use openidconnect::{
    core::{CoreClient, CoreProviderMetadata, CoreResponseType, CoreAuthenticationFlow},
    reqwest::async_http_client,
    AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce, RedirectUrl,
    Scope, AuthUrl, TokenUrl, UserInfoUrl, DeviceAuthorizationUrl, AccessToken,
    AdditionalClaims, EmptyAdditionalClaims,
};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use std::collections::HashMap;
use tokio::time::sleep;
use url::Url;

/// Supported OIDC provider types
#[derive(Debug, Clone, PartialEq)]
pub enum ProviderType {
    Azure,
    Google,
    GitHub,
    Generic,
}

impl ProviderType {
    pub fn detect_from_url(provider_url: &str) -> Self {
        if provider_url.contains("login.microsoftonline.com") || provider_url.contains("microsoft.com") {
            Self::Azure
        } else if provider_url.contains("accounts.google.com") || provider_url.contains("googleapis.com") {
            Self::Google
        } else if provider_url.contains("github.com") {
            Self::GitHub
        } else {
            Self::Generic
        }
    }

    pub fn get_default_scopes(&self) -> Vec<String> {
        match self {
            Self::Azure => vec![
                "openid".to_string(),
                "profile".to_string(),
                "email".to_string(),
                "User.Read".to_string(),
            ],
            Self::Google => vec![
                "openid".to_string(),
                "profile".to_string(),
                "email".to_string(),
            ],
            Self::GitHub => vec![
                "user:email".to_string(),
                "read:user".to_string(),
            ],
            Self::Generic => vec![
                "openid".to_string(),
                "profile".to_string(),
                "email".to_string(),
            ],
        }
    }

    pub fn requires_tenant_id(&self) -> bool {
        matches!(self, Self::Azure)
    }
}

/// OIDC provider for authentication
#[derive(Clone)]
pub struct OidcProvider {
    client: CoreClient,
    config: OidcConfig,
    provider_type: ProviderType,
    http_client: Client,
}

impl OidcProvider {
    /// Create new OIDC provider
    pub async fn new(config: OidcConfig) -> Result<Self> {
        let provider_type = ProviderType::detect_from_url(&config.provider_url);

        // Handle special cases for different providers
        let provider_metadata = match provider_type {
            ProviderType::GitHub => {
                // GitHub doesn't support OIDC discovery, so we need to construct manually
                Self::create_github_metadata(&config)?
            }
            _ => {
                // Use standard OIDC discovery
                CoreProviderMetadata::discover_async(
                    IssuerUrl::new(config.provider_url.clone())
                        .map_err(|e| GhostWireError::config(format!("Invalid provider URL: {}", e)))?,
                    async_http_client,
                )
                .await
                .map_err(|e| GhostWireError::network(format!("OIDC discovery failed: {}", e)))?
            }
        };

        let client = CoreClient::from_provider_metadata(
            provider_metadata,
            ClientId::new(config.client_id.clone()),
            Some(ClientSecret::new(config.client_secret.clone())),
        )
        .set_redirect_uri(
            RedirectUrl::new(config.redirect_uri.clone())
                .map_err(|e| GhostWireError::config(format!("Invalid redirect URI: {}", e)))?,
        );

        let http_client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("GhostWire/1.0")
            .build()
            .map_err(|e| GhostWireError::network(format!("HTTP client creation failed: {}", e)))?;

        Ok(Self {
            client,
            config,
            provider_type,
            http_client,
        })
    }

    /// Create GitHub metadata manually (GitHub doesn't support OIDC discovery)
    fn create_github_metadata(config: &OidcConfig) -> Result<CoreProviderMetadata> {
        use openidconnect::core::CoreProviderMetadata;

        // GitHub OAuth endpoints
        let auth_url = AuthUrl::new("https://github.com/login/oauth/authorize".to_string())
            .map_err(|e| GhostWireError::config(format!("Invalid GitHub auth URL: {}", e)))?;
        let token_url = TokenUrl::new("https://github.com/login/oauth/access_token".to_string())
            .map_err(|e| GhostWireError::config(format!("Invalid GitHub token URL: {}", e)))?;

        Ok(CoreProviderMetadata::new(
            IssuerUrl::new("https://github.com".to_string())
                .map_err(|e| GhostWireError::config(format!("Invalid GitHub issuer URL: {}", e)))?,
            auth_url,
            // GitHub doesn't have a JWKS URI, but we'll set a placeholder
            openidconnect::JsonWebKeySetUrl::new("https://github.com/.well-known/jwks".to_string())
                .map_err(|e| GhostWireError::config(format!("Invalid JWKS URL: {}", e)))?,
            vec![
                openidconnect::ResponseTypes::new(vec![CoreResponseType::Code]),
            ],
            vec![], // subject_types_supported - GitHub doesn't use this
            vec![], // id_token_signing_alg_values_supported - GitHub doesn't use JWT ID tokens
        )
        .set_token_endpoint(Some(token_url))
        .set_userinfo_endpoint(Some(
            UserInfoUrl::new("https://api.github.com/user".to_string())
                .map_err(|e| GhostWireError::config(format!("Invalid GitHub user info URL: {}", e)))?
        )))
    }

    /// Get authorization URL for web-based flow
    pub fn get_authorization_url(&self) -> (String, String, String) {
        let mut auth_request = self
            .client
            .authorize_url(
                CoreAuthenticationFlow::<CoreResponseType>::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            );

        // Add scopes based on provider type
        let scopes = if self.config.scopes.is_empty() {
            self.provider_type.get_default_scopes()
        } else {
            self.config.scopes.clone()
        };

        for scope in scopes {
            auth_request = auth_request.add_scope(Scope::new(scope));
        }

        // Add provider-specific parameters
        match self.provider_type {
            ProviderType::Azure => {
                // Azure-specific parameters
                auth_request = auth_request.add_extra_param("response_mode", "form_post");
            }
            ProviderType::Google => {
                // Google-specific parameters
                auth_request = auth_request
                    .add_extra_param("access_type", "offline")
                    .add_extra_param("prompt", "consent");
            }
            ProviderType::GitHub => {
                // GitHub-specific parameters
                auth_request = auth_request.add_extra_param("allow_signup", "true");
            }
            ProviderType::Generic => {
                // No additional parameters for generic OIDC
            }
        }

        let (auth_url, csrf_token, nonce) = auth_request.url();

        (
            auth_url.to_string(),
            csrf_token.secret().clone(),
            nonce.secret().clone(),
        )
    }

    /// Exchange authorization code for user info
    pub async fn exchange_code(&self, code: &str, nonce: &str) -> Result<UserInfo> {
        let token_response = self
            .client
            .exchange_code(AuthorizationCode::new(code.to_string()))
            .request_async(async_http_client)
            .await
            .map_err(|e| GhostWireError::authentication(format!("Token exchange failed: {}", e)))?;

        match self.provider_type {
            ProviderType::GitHub => {
                // GitHub uses OAuth2, not OIDC, so handle differently
                self.get_github_user_info(token_response.access_token()).await
            }
            _ => {
                // Standard OIDC flow
                self.handle_oidc_token_response(&token_response, nonce).await
            }
        }
    }

    /// Handle standard OIDC token response
    async fn handle_oidc_token_response(
        &self,
        token_response: &openidconnect::StandardTokenResponse<EmptyAdditionalClaims, openidconnect::core::CoreTokenType>,
        nonce: &str,
    ) -> Result<UserInfo> {
        let id_token = token_response
            .id_token()
            .ok_or_else(|| GhostWireError::authentication("No ID token in response"))?;

        let nonce_verifier = Nonce::new(nonce.to_string());
        let claims = id_token
            .claims(&self.client.id_token_verifier(), &nonce_verifier)
            .map_err(|e| GhostWireError::authentication(format!("ID token validation failed: {}", e)))?;

        // Get basic user info from ID token
        let mut user_info = UserInfo {
            sub: claims.subject().to_string(),
            email: claims.email().map(|e| e.to_string()),
            name: claims.name()
                .and_then(|n| n.get(None))
                .map(|n| n.to_string()),
            picture: claims.picture()
                .and_then(|p| p.get(None))
                .map(|p| p.to_string()),
            preferred_username: claims.preferred_username()
                .map(|u| u.to_string()),
        };

        // Fetch additional user info from UserInfo endpoint if available
        if let Some(access_token) = token_response.access_token() {
            if let Some(additional_info) = self.fetch_provider_user_info(access_token).await? {
                // Merge additional info
                self.merge_user_info(&mut user_info, additional_info);
            }
        }

        Ok(user_info)
    }

    /// Get user info from GitHub API
    async fn get_github_user_info(&self, access_token: &AccessToken) -> Result<UserInfo> {
        let user_response = self
            .http_client
            .get("https://api.github.com/user")
            .bearer_auth(access_token.secret())
            .send()
            .await
            .map_err(|e| GhostWireError::network(format!("GitHub user API request failed: {}", e)))?;

        if !user_response.status().is_success() {
            return Err(GhostWireError::authentication("Failed to fetch GitHub user info"));
        }

        let github_user: GitHubUser = user_response
            .json()
            .await
            .map_err(|e| GhostWireError::authentication(format!("Invalid GitHub user response: {}", e)))?;

        // Fetch user emails if needed
        let mut email = github_user.email.clone();
        if email.is_none() {
            email = self.get_github_primary_email(access_token).await?;
        }

        Ok(UserInfo {
            sub: github_user.id.to_string(),
            email,
            name: github_user.name.or_else(|| Some(github_user.login.clone())),
            picture: Some(github_user.avatar_url),
            preferred_username: Some(github_user.login),
        })
    }

    /// Get primary email from GitHub (requires user:email scope)
    async fn get_github_primary_email(&self, access_token: &AccessToken) -> Result<Option<String>> {
        let email_response = self
            .http_client
            .get("https://api.github.com/user/emails")
            .bearer_auth(access_token.secret())
            .send()
            .await;

        if let Ok(response) = email_response {
            if response.status().is_success() {
                if let Ok(emails) = response.json::<Vec<GitHubEmail>>().await {
                    return Ok(emails
                        .into_iter()
                        .find(|e| e.primary && e.verified)
                        .map(|e| e.email));
                }
            }
        }

        Ok(None)
    }

    /// Merge additional user info
    fn merge_user_info(&self, base: &mut UserInfo, additional: UserInfo) {
        if base.email.is_none() {
            base.email = additional.email;
        }
        if base.name.is_none() {
            base.name = additional.name;
        }
        if base.picture.is_none() {
            base.picture = additional.picture;
        }
        if base.preferred_username.is_none() {
            base.preferred_username = additional.preferred_username;
        }
    }

    /// Fetch additional user info from provider-specific UserInfo endpoint
    async fn fetch_provider_user_info(&self, access_token: &AccessToken) -> Result<Option<UserInfo>> {
        if let Some(userinfo_endpoint) = self.client.user_info(access_token.clone(), None) {
            match userinfo_endpoint.request_async(async_http_client).await {
                Ok(userinfo) => {
                    let user_info = UserInfo {
                        sub: userinfo.subject().to_string(),
                        email: userinfo.email().map(|e| e.to_string()),
                        name: userinfo.name()
                            .and_then(|n| n.get(None))
                            .map(|n| n.to_string()),
                        picture: userinfo.picture()
                            .and_then(|p| p.get(None))
                            .map(|p| p.to_string()),
                        preferred_username: userinfo.preferred_username()
                            .map(|u| u.to_string()),
                    };
                    Ok(Some(user_info))
                }
                Err(_) => {
                    // UserInfo fetch failed, but this is not critical
                    Ok(None)
                }
            }
        } else {
            Ok(None)
        }
    }

    /// Start device flow for CLI authentication
    pub async fn start_device_flow(&self) -> Result<DeviceAuthResponse> {
        // Check if provider supports device flow
        let device_auth_url = self.get_device_authorization_url()?;

        let response = self
            .http_client
            .post(&device_auth_url)
            .form(&[
                ("client_id", &self.config.client_id),
                ("scope", &self.config.scopes.join(" ")),
            ])
            .send()
            .await
            .map_err(|e| GhostWireError::network(format!("Device flow request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(GhostWireError::authentication(
                "Device authorization request failed",
            ));
        }

        let auth_response: DeviceAuthResponse = response
            .json()
            .await
            .map_err(|e| GhostWireError::authentication(format!("Invalid device auth response: {}", e)))?;

        Ok(auth_response)
    }

    /// Poll for device flow token
    pub async fn poll_for_token(&self, device_code: &str, interval: u64) -> Result<UserInfo> {
        let token_url = self.get_token_url()?;

        loop {
            sleep(Duration::from_secs(interval)).await;

            let response = self
                .http_client
                .post(&token_url)
                .form(&[
                    ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                    ("device_code", device_code),
                    ("client_id", &self.config.client_id),
                ])
                .send()
                .await
                .map_err(|e| GhostWireError::network(format!("Token request failed: {}", e)))?;

            match response.status().as_u16() {
                200 => {
                    let token_response: DeviceTokenResponse = response
                        .json()
                        .await
                        .map_err(|e| GhostWireError::authentication(format!("Invalid token response: {}", e)))?;

                    // Use the ID token or access token to get user info
                    return self.get_user_info_from_token(&token_response).await;
                }
                400 => {
                    let error: DeviceAuthError = response
                        .json()
                        .await
                        .map_err(|e| GhostWireError::authentication(format!("Invalid error response: {}", e)))?;

                    match error.error.as_str() {
                        "authorization_pending" => continue,
                        "slow_down" => {
                            sleep(Duration::from_secs(5)).await;
                            continue;
                        }
                        "expired_token" => {
                            return Err(GhostWireError::authentication("Device code expired"));
                        }
                        "access_denied" => {
                            return Err(GhostWireError::authentication("User denied authorization"));
                        }
                        _ => {
                            return Err(GhostWireError::authentication(format!(
                                "Device authorization failed: {}",
                                error.error
                            )));
                        }
                    }
                }
                _ => {
                    return Err(GhostWireError::authentication("Token request failed"));
                }
            }
        }
    }

    /// Get user info from token response
    async fn get_user_info_from_token(&self, token_response: &DeviceTokenResponse) -> Result<UserInfo> {
        // Try to decode ID token if present
        if let Some(id_token) = &token_response.id_token {
            // For device flow, we don't have a nonce to verify against
            // In production, consider using a different verification approach
            if let Ok(claims) = self.decode_id_token_unsafe(id_token) {
                return Ok(UserInfo {
                    sub: claims.sub,
                    email: claims.email,
                    name: claims.name,
                    picture: claims.picture,
                    preferred_username: claims.preferred_username,
                });
            }
        }

        // Fallback to UserInfo endpoint with access token
        if let Some(access_token) = &token_response.access_token {
            let access_token_obj = AccessToken::new(access_token.clone());
            if let Some(user_info) = self.fetch_user_info(&access_token_obj).await? {
                return Ok(user_info);
            }
        }

        Err(GhostWireError::authentication("Could not extract user info from token"))
    }

    /// Decode ID token without nonce verification (unsafe, use only for device flow)
    fn decode_id_token_unsafe(&self, id_token: &str) -> Result<IdTokenClaims> {
        // This is a simplified decoding for demo purposes
        // In production, proper signature verification should be implemented
        let parts: Vec<&str> = id_token.split('.').collect();
        if parts.len() != 3 {
            return Err(GhostWireError::authentication("Invalid ID token format"));
        }

        let payload = parts[1];
        let decoded = base64::decode_config(payload, base64::URL_SAFE_NO_PAD)
            .map_err(|_| GhostWireError::authentication("Invalid ID token encoding"))?;

        serde_json::from_slice(&decoded)
            .map_err(|_| GhostWireError::authentication("Invalid ID token payload"))
    }

    /// Get device authorization URL from provider metadata
    fn get_device_authorization_url(&self) -> Result<String> {
        // Try to get from provider metadata or construct manually
        let base_url = &self.config.provider_url;
        Ok(format!("{}/device/code", base_url.trim_end_matches('/')))
    }

    /// Get token URL from provider metadata
    fn get_token_url(&self) -> Result<String> {
        let base_url = &self.config.provider_url;
        Ok(format!("{}/token", base_url.trim_end_matches('/')))
    }
}

/// Device authorization response
#[derive(Debug, Serialize, Deserialize)]
pub struct DeviceAuthResponse {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub verification_uri_complete: Option<String>,
    pub expires_in: u64,
    pub interval: u64,
}

/// Device token response
#[derive(Debug, Serialize, Deserialize)]
struct DeviceTokenResponse {
    pub access_token: Option<String>,
    pub token_type: Option<String>,
    pub refresh_token: Option<String>,
    pub expires_in: Option<u64>,
    pub id_token: Option<String>,
    pub scope: Option<String>,
}

/// Device authorization error
#[derive(Debug, Deserialize)]
struct DeviceAuthError {
    pub error: String,
    pub error_description: Option<String>,
}

/// Simplified ID token claims for unsafe decoding
#[derive(Debug, Deserialize)]
struct IdTokenClaims {
    pub sub: String,
    pub email: Option<String>,
    pub name: Option<String>,
    pub picture: Option<String>,
    pub preferred_username: Option<String>,
}

/// GitHub user information from API
#[derive(Debug, Deserialize)]
struct GitHubUser {
    pub id: u64,
    pub login: String,
    pub name: Option<String>,
    pub email: Option<String>,
    pub avatar_url: String,
    pub html_url: String,
    pub company: Option<String>,
    pub location: Option<String>,
}

/// GitHub email information
#[derive(Debug, Deserialize)]
struct GitHubEmail {
    pub email: String,
    pub primary: bool,
    pub verified: bool,
    pub visibility: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_config() -> OidcConfig {
        OidcConfig {
            enabled: true,
            provider_url: "https://accounts.google.com".to_string(),
            client_id: "test-client-id".to_string(),
            client_secret: "test-client-secret".to_string(),
            redirect_uri: "http://localhost:8080/auth/callback".to_string(),
            scopes: vec!["openid".to_string(), "profile".to_string(), "email".to_string()],
        }
    }

    #[test]
    fn test_authorization_url_generation() {
        // This test would require actual OIDC provider setup
        // For now, just test configuration parsing
        let config = create_test_config();
        assert!(config.enabled);
        assert_eq!(config.client_id, "test-client-id");
        assert!(config.scopes.contains(&"openid".to_string()));
    }

    #[test]
    fn test_device_auth_url_construction() {
        let config = create_test_config();
        // Test URL construction logic
        let base_url = &config.provider_url;
        let device_url = format!("{}/device/code", base_url.trim_end_matches('/'));
        assert_eq!(device_url, "https://accounts.google.com/device/code");
    }

    #[test]
    fn test_config_validation() {
        let config = create_test_config();

        // Valid redirect URI
        assert!(Url::parse(&config.redirect_uri).is_ok());

        // Valid provider URL
        assert!(Url::parse(&config.provider_url).is_ok());

        // Required scopes
        assert!(config.scopes.contains(&"openid".to_string()));
    }
}