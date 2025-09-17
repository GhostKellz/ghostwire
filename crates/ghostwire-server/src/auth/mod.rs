/// Authentication and authorization system for GhostWire
///
/// This module provides comprehensive authentication support including:
/// - OIDC integration for SSO
/// - JWT token management
/// - Session token generation for nodes
/// - API key management for administrative access
/// - Multi-level authorization with permissions

pub mod oidc;
pub mod jwt;
pub mod session;
pub mod api_keys;
pub mod permissions;
pub mod middleware;
pub mod device_flow;

use crate::coordinator::Coordinator;
use ghostwire_common::{
    types::*,
    error::{Result, GhostWireError},
};
use std::sync::Arc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Authentication context for requests
#[derive(Debug, Clone)]
pub enum AuthContext {
    /// Authenticated node with session token
    Node {
        node_id: NodeId,
        user_id: UserId,
        session_token: String,
    },
    /// Authenticated user with JWT token
    User {
        user_id: UserId,
        username: String,
        permissions: Vec<String>,
        token: String,
        is_admin: bool,
    },
    /// Administrative access with API key
    Admin {
        api_key_id: String,
        permissions: Vec<String>,
        created_by: Option<UserId>,
    },
    /// Unauthenticated request
    Anonymous,
}

/// Authentication levels for endpoint protection
#[derive(Debug, Clone, Copy)]
pub enum AuthLevel {
    Anonymous,
    Node,
    User,
    Admin,
}

/// User information from OIDC provider
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfo {
    pub sub: String,
    pub email: Option<String>,
    pub name: Option<String>,
    pub picture: Option<String>,
    pub preferred_username: Option<String>,
}

/// API key information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyInfo {
    pub id: String,
    pub name: String,
    pub permissions: Vec<String>,
    pub created_by: Option<UserId>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub last_used_at: Option<chrono::DateTime<chrono::Utc>>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Authentication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    pub oidc: Option<OidcConfig>,
    pub jwt: JwtConfig,
    pub session: SessionConfig,
    pub api_keys: ApiKeyConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcConfig {
    pub enabled: bool,
    pub provider_url: String,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtConfig {
    pub secret: String,
    pub expiration_hours: u64,
    pub refresh_expiration_hours: u64,
    pub issuer: String,
    pub audience: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionConfig {
    pub timeout_hours: u64,
    pub cleanup_interval_hours: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyConfig {
    pub default_expiration_days: Option<u32>,
    pub max_keys_per_user: u32,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            oidc: None,
            jwt: JwtConfig {
                secret: "change-me-in-production".to_string(),
                expiration_hours: 24,
                refresh_expiration_hours: 24 * 7, // 7 days
                issuer: "ghostwire-server".to_string(),
                audience: "ghostwire-api".to_string(),
            },
            session: SessionConfig {
                timeout_hours: 24,
                cleanup_interval_hours: 1,
            },
            api_keys: ApiKeyConfig {
                default_expiration_days: Some(365),
                max_keys_per_user: 10,
            },
        }
    }
}

/// Main authentication service
pub struct AuthService {
    config: AuthConfig,
    coordinator: Arc<Coordinator>,
    oidc_provider: Option<oidc::OidcProvider>,
    jwt_service: jwt::JwtService,
    session_service: session::SessionService,
    api_key_service: api_keys::ApiKeyService,
}

impl AuthService {
    /// Create new authentication service
    pub async fn new(
        config: AuthConfig,
        coordinator: Arc<Coordinator>,
    ) -> Result<Self> {
        // Initialize OIDC provider if enabled
        let oidc_provider = if let Some(oidc_config) = &config.oidc {
            if oidc_config.enabled {
                Some(oidc::OidcProvider::new(oidc_config.clone()).await?)
            } else {
                None
            }
        } else {
            None
        };

        // Initialize JWT service
        let jwt_service = jwt::JwtService::new(config.jwt.clone());

        // Initialize session service
        let session_service = session::SessionService::new(
            config.session.clone(),
            coordinator.clone(),
        );

        // Initialize API key service
        let api_key_service = api_keys::ApiKeyService::new(
            config.api_keys.clone(),
            coordinator.clone(),
        );

        Ok(Self {
            config,
            coordinator,
            oidc_provider,
            jwt_service,
            session_service,
            api_key_service,
        })
    }

    /// Authenticate a request and return auth context
    pub async fn authenticate(&self, headers: &HashMap<String, String>) -> Result<AuthContext> {
        // Check for API key first (highest priority)
        if let Some(api_key) = headers.get("x-api-key") {
            return self.authenticate_api_key(api_key).await;
        }

        // Check for bearer token (user authentication)
        if let Some(auth_header) = headers.get("authorization") {
            if let Some(token) = auth_header.strip_prefix("Bearer ") {
                return self.authenticate_jwt_token(token).await;
            }
        }

        // Check for session token (node authentication)
        if let Some(session_token) = headers.get("x-session-token") {
            return self.authenticate_session_token(session_token).await;
        }

        Ok(AuthContext::Anonymous)
    }

    /// Authenticate using API key
    pub async fn authenticate_api_key(&self, api_key: &str) -> Result<AuthContext> {
        let api_key_info = self.api_key_service.validate_api_key(api_key).await?;

        match api_key_info {
            Some(info) => Ok(AuthContext::Admin {
                api_key_id: info.id,
                permissions: info.permissions,
                created_by: info.created_by,
            }),
            None => Ok(AuthContext::Anonymous),
        }
    }

    /// Authenticate using JWT token
    pub async fn authenticate_jwt_token(&self, token: &str) -> Result<AuthContext> {
        let claims = self.jwt_service.validate_token(token)?;

        Ok(AuthContext::User {
            user_id: UserId::parse(&claims.user_id)
                .map_err(|_| GhostWireError::authentication("Invalid user ID in token"))?,
            username: claims.username,
            permissions: claims.permissions,
            token: token.to_string(),
            is_admin: claims.is_admin,
        })
    }

    /// Authenticate using session token
    pub async fn authenticate_session_token(&self, token: &str) -> Result<AuthContext> {
        let session_info = self.session_service.validate_session(token).await?;

        match session_info {
            Some(info) => Ok(AuthContext::Node {
                node_id: info.node_id,
                user_id: info.user_id,
                session_token: token.to_string(),
            }),
            None => Ok(AuthContext::Anonymous),
        }
    }

    /// Check if auth context has required permission
    pub fn check_permission(
        &self,
        context: &AuthContext,
        permission: &str,
        resource_owner: Option<&UserId>,
    ) -> bool {
        permissions::check_permission(context, permission, resource_owner)
    }

    /// Require specific authentication level
    pub fn require_auth_level(&self, context: &AuthContext, required_level: AuthLevel) -> Result<()> {
        match required_level {
            AuthLevel::Anonymous => Ok(()),
            AuthLevel::Node => match context {
                AuthContext::Node { .. } | AuthContext::User { .. } | AuthContext::Admin { .. } => Ok(()),
                AuthContext::Anonymous => Err(GhostWireError::authentication("Authentication required")),
            },
            AuthLevel::User => match context {
                AuthContext::User { .. } | AuthContext::Admin { .. } => Ok(()),
                _ => Err(GhostWireError::authentication("User authentication required")),
            },
            AuthLevel::Admin => match context {
                AuthContext::Admin { .. } => Ok(()),
                AuthContext::User { is_admin: true, .. } => Ok(()),
                _ => Err(GhostWireError::authentication("Admin authentication required")),
            },
        }
    }

    /// Generate session token for node
    pub async fn generate_session_token(
        &self,
        node_id: &NodeId,
        user_id: &UserId,
        public_key: &PublicKey,
    ) -> Result<String> {
        self.session_service.create_session(node_id, user_id, public_key).await
    }

    /// Generate JWT token for user
    pub async fn generate_user_token(&self, user_id: &UserId) -> Result<String> {
        // Get user information from coordinator
        let user = self.coordinator.get_user_by_id(user_id).await?;
        self.jwt_service.generate_token(&user).await
    }

    /// Create API key
    pub async fn create_api_key(
        &self,
        name: &str,
        permissions: Vec<String>,
        created_by: &UserId,
        expires_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<(String, ApiKeyInfo)> {
        self.api_key_service.create_api_key(name, permissions, created_by, expires_at).await
    }

    /// Get OIDC authorization URL
    pub fn get_oidc_auth_url(&self) -> Result<(String, String, String)> {
        if let Some(provider) = &self.oidc_provider {
            Ok(provider.get_authorization_url())
        } else {
            Err(GhostWireError::config("OIDC not configured"))
        }
    }

    /// Handle OIDC callback
    pub async fn handle_oidc_callback(
        &self,
        code: &str,
        state: &str,
        stored_nonce: &str,
    ) -> Result<String> {
        if let Some(provider) = &self.oidc_provider {
            let user_info = provider.exchange_code(code, stored_nonce).await?;

            // Create or update user from OIDC info
            let user = self.coordinator.upsert_user_from_oidc(&user_info).await?;

            // Generate JWT token
            self.jwt_service.generate_token(&user).await
        } else {
            Err(GhostWireError::config("OIDC not configured"))
        }
    }

    /// Start device flow for CLI authentication
    pub async fn start_device_flow(&self) -> Result<device_flow::DeviceAuthResponse> {
        if let Some(provider) = &self.oidc_provider {
            provider.start_device_flow().await
        } else {
            Err(GhostWireError::config("OIDC not configured"))
        }
    }

    /// Poll for device flow token
    pub async fn poll_device_token(
        &self,
        device_code: &str,
        interval: u64,
    ) -> Result<String> {
        if let Some(provider) = &self.oidc_provider {
            let user_info = provider.poll_for_token(device_code, interval).await?;

            // Create or update user
            let user = self.coordinator.upsert_user_from_oidc(&user_info).await?;

            // Generate JWT token
            self.jwt_service.generate_token(&user).await
        } else {
            Err(GhostWireError::config("OIDC not configured"))
        }
    }

    /// Start background cleanup tasks
    pub async fn start_cleanup_tasks(&self) {
        // Start session cleanup
        let session_service = self.session_service.clone();
        tokio::spawn(async move {
            session_service.cleanup_expired_sessions().await;
        });

        // Start API key cleanup
        let api_key_service = self.api_key_service.clone();
        tokio::spawn(async move {
            api_key_service.cleanup_expired_keys().await;
        });
    }
}

// Re-export key types and functions
pub use jwt::{JwtClaims, JwtService};
pub use session::{SessionInfo, SessionService};
pub use api_keys::{ApiKeyService};
pub use oidc::OidcProvider;
pub use permissions::check_permission;
pub use middleware::{auth_middleware, require_permission};
pub use device_flow::{DeviceAuthResponse, DeviceAuthFlow};