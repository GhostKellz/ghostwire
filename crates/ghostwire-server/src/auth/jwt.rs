/// JWT token management for user authentication
///
/// Provides secure, stateless authentication using JSON Web Tokens
/// with support for refresh tokens and permission-based authorization

use crate::auth::{JwtConfig, UserInfo};
use ghostwire_common::{
    types::*,
    error::{Result, GhostWireError},
};
use jsonwebtoken::{encode, decode, Header, Validation, EncodingKey, DecodingKey, Algorithm};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

/// JWT claims structure
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct JwtClaims {
    /// Subject (user ID)
    pub sub: String,
    /// Issuer
    pub iss: String,
    /// Audience
    pub aud: String,
    /// Expiration time (Unix timestamp)
    pub exp: usize,
    /// Issued at (Unix timestamp)
    pub iat: usize,
    /// JWT ID (unique token identifier)
    pub jti: String,
    /// User permissions
    pub permissions: Vec<String>,
    /// User ID (for convenience)
    pub user_id: String,
    /// Username
    pub username: String,
    /// Admin flag
    pub is_admin: bool,
    /// Email (optional)
    pub email: Option<String>,
    /// Token type (access or refresh)
    pub token_type: String,
}

/// Refresh token claims
#[derive(Debug, Serialize, Deserialize)]
pub struct RefreshClaims {
    pub sub: String,
    pub iss: String,
    pub aud: String,
    pub exp: usize,
    pub iat: usize,
    pub jti: String,
    pub user_id: String,
    pub token_type: String,
}

/// User representation for token generation
#[derive(Debug, Clone)]
pub struct User {
    pub id: UserId,
    pub name: String,
    pub email: Option<String>,
    pub is_admin: bool,
    pub permissions: Vec<String>,
    pub created_at: SystemTime,
}

impl User {
    /// Get user permissions based on role and explicit permissions
    pub fn get_permissions(&self) -> Vec<String> {
        let mut permissions = self.permissions.clone();

        if self.is_admin {
            permissions.push("admin".to_string());
        }

        // Add default user permissions
        permissions.extend(vec![
            "node:read".to_string(),
            "node:write".to_string(),
            "user:read".to_string(),
        ]);

        permissions.sort();
        permissions.dedup();
        permissions
    }
}

/// JWT service for token management
#[derive(Clone)]
pub struct JwtService {
    config: JwtConfig,
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    validation: Validation,
}

impl JwtService {
    /// Create new JWT service
    pub fn new(config: JwtConfig) -> Self {
        let encoding_key = EncodingKey::from_secret(config.secret.as_bytes());
        let decoding_key = DecodingKey::from_secret(config.secret.as_bytes());

        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_issuer(&[&config.issuer]);
        validation.set_audience(&[&config.audience]);

        Self {
            config,
            encoding_key,
            decoding_key,
            validation,
        }
    }

    /// Generate access token for user
    pub async fn generate_token(&self, user: &User) -> Result<String> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| GhostWireError::internal("Invalid system time"))?
            .as_secs();

        let expiration = now + (self.config.expiration_hours * 3600);

        let claims = JwtClaims {
            sub: format!("user_{}", user.id),
            iss: self.config.issuer.clone(),
            aud: self.config.audience.clone(),
            exp: expiration as usize,
            iat: now as usize,
            jti: format!("jwt_{}", Uuid::new_v4()),
            permissions: user.get_permissions(),
            user_id: user.id.to_string(),
            username: user.name.clone(),
            is_admin: user.is_admin,
            email: user.email.clone(),
            token_type: "access".to_string(),
        };

        encode(&Header::default(), &claims, &self.encoding_key)
            .map_err(|e| GhostWireError::crypto(format!("JWT encoding failed: {}", e)))
    }

    /// Generate refresh token for user
    pub async fn generate_refresh_token(&self, user: &User) -> Result<String> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| GhostWireError::internal("Invalid system time"))?
            .as_secs();

        let expiration = now + (self.config.refresh_expiration_hours * 3600);

        let claims = RefreshClaims {
            sub: format!("user_{}", user.id),
            iss: self.config.issuer.clone(),
            aud: self.config.audience.clone(),
            exp: expiration as usize,
            iat: now as usize,
            jti: format!("refresh_{}", Uuid::new_v4()),
            user_id: user.id.to_string(),
            token_type: "refresh".to_string(),
        };

        encode(&Header::default(), &claims, &self.encoding_key)
            .map_err(|e| GhostWireError::crypto(format!("JWT encoding failed: {}", e)))
    }

    /// Validate and decode access token
    pub fn validate_token(&self, token: &str) -> Result<JwtClaims> {
        let token_data = decode::<JwtClaims>(token, &self.decoding_key, &self.validation)
            .map_err(|e| match e.kind() {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
                    GhostWireError::authentication("Token expired")
                }
                jsonwebtoken::errors::ErrorKind::InvalidToken => {
                    GhostWireError::authentication("Invalid token")
                }
                jsonwebtoken::errors::ErrorKind::InvalidSignature => {
                    GhostWireError::authentication("Invalid token signature")
                }
                _ => GhostWireError::authentication("Token validation failed"),
            })?;

        // Verify token type
        if token_data.claims.token_type != "access" {
            return Err(GhostWireError::authentication("Invalid token type"));
        }

        Ok(token_data.claims)
    }

    /// Validate refresh token
    pub fn validate_refresh_token(&self, token: &str) -> Result<RefreshClaims> {
        let token_data = decode::<RefreshClaims>(token, &self.decoding_key, &self.validation)
            .map_err(|e| match e.kind() {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
                    GhostWireError::authentication("Refresh token expired")
                }
                jsonwebtoken::errors::ErrorKind::InvalidToken => {
                    GhostWireError::authentication("Invalid refresh token")
                }
                jsonwebtoken::errors::ErrorKind::InvalidSignature => {
                    GhostWireError::authentication("Invalid refresh token signature")
                }
                _ => GhostWireError::authentication("Refresh token validation failed"),
            })?;

        // Verify token type
        if token_data.claims.token_type != "refresh" {
            return Err(GhostWireError::authentication("Invalid token type"));
        }

        Ok(token_data.claims)
    }

    /// Refresh access token using refresh token
    pub async fn refresh_token(&self, refresh_token: &str, user: &User) -> Result<String> {
        // Validate refresh token
        let refresh_claims = self.validate_refresh_token(refresh_token)?;

        // Verify user ID matches
        if refresh_claims.user_id != user.id.to_string() {
            return Err(GhostWireError::authentication("Invalid refresh token for user"));
        }

        // Generate new access token
        self.generate_token(user).await
    }

    /// Extract user ID from token without full validation (for quick lookups)
    pub fn extract_user_id(&self, token: &str) -> Result<UserId> {
        // This is a less secure method for quick user ID extraction
        // Should only be used when full validation is not required
        let token_data = decode::<JwtClaims>(
            token,
            &self.decoding_key,
            &Validation::new(Algorithm::HS256)
        )?;

        UserId::parse(&token_data.claims.user_id)
            .map_err(|_| GhostWireError::authentication("Invalid user ID in token"))
    }

    /// Check if token is expired (without signature validation)
    pub fn is_token_expired(&self, token: &str) -> bool {
        if let Ok(token_data) = decode::<JwtClaims>(
            token,
            &DecodingKey::from_secret("dummy".as_bytes()),
            &Validation::new(Algorithm::HS256),
        ) {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as usize;

            token_data.claims.exp < now
        } else {
            true // If we can't decode, consider it expired
        }
    }

    /// Generate token pair (access + refresh)
    pub async fn generate_token_pair(&self, user: &User) -> Result<TokenPair> {
        let access_token = self.generate_token(user).await?;
        let refresh_token = self.generate_refresh_token(user).await?;

        Ok(TokenPair {
            access_token,
            refresh_token,
            token_type: "Bearer".to_string(),
            expires_in: self.config.expiration_hours * 3600,
        })
    }

    /// Create user from OIDC user info
    pub fn user_from_oidc(&self, user_info: &UserInfo, existing_user: Option<&User>) -> User {
        let now = SystemTime::now();

        if let Some(existing) = existing_user {
            // Update existing user with new OIDC info
            User {
                id: existing.id,
                name: user_info.preferred_username
                    .clone()
                    .or_else(|| user_info.name.clone())
                    .unwrap_or_else(|| existing.name.clone()),
                email: user_info.email.clone().or_else(|| existing.email.clone()),
                is_admin: existing.is_admin,
                permissions: existing.permissions.clone(),
                created_at: existing.created_at,
            }
        } else {
            // Create new user from OIDC info
            User {
                id: Uuid::new_v4(),
                name: user_info.preferred_username
                    .clone()
                    .or_else(|| user_info.name.clone())
                    .unwrap_or_else(|| "Unknown User".to_string()),
                email: user_info.email.clone(),
                is_admin: false, // New users are not admin by default
                permissions: vec![], // Default permissions only
                created_at: now,
            }
        }
    }
}

/// Token pair response
#[derive(Debug, Serialize, Deserialize)]
pub struct TokenPair {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: u64,
}

/// Token refresh request
#[derive(Debug, Deserialize)]
pub struct RefreshTokenRequest {
    pub refresh_token: String,
}

/// Token refresh response
#[derive(Debug, Serialize)]
pub struct RefreshTokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_config() -> JwtConfig {
        JwtConfig {
            secret: "test-secret-key-that-is-long-enough".to_string(),
            expiration_hours: 1,
            refresh_expiration_hours: 24,
            issuer: "test-issuer".to_string(),
            audience: "test-audience".to_string(),
        }
    }

    fn create_test_user() -> User {
        User {
            id: Uuid::new_v4(),
            name: "testuser".to_string(),
            email: Some("test@example.com".to_string()),
            is_admin: false,
            permissions: vec!["test:permission".to_string()],
            created_at: SystemTime::now(),
        }
    }

    #[tokio::test]
    async fn test_token_generation_and_validation() {
        let config = create_test_config();
        let jwt_service = JwtService::new(config);
        let user = create_test_user();

        // Generate token
        let token = jwt_service.generate_token(&user).await.unwrap();
        assert!(!token.is_empty());

        // Validate token
        let claims = jwt_service.validate_token(&token).unwrap();
        assert_eq!(claims.user_id, user.id.to_string());
        assert_eq!(claims.username, user.name);
        assert_eq!(claims.is_admin, user.is_admin);
        assert!(claims.permissions.contains(&"node:read".to_string()));
    }

    #[tokio::test]
    async fn test_refresh_token_flow() {
        let config = create_test_config();
        let jwt_service = JwtService::new(config);
        let user = create_test_user();

        // Generate token pair
        let token_pair = jwt_service.generate_token_pair(&user).await.unwrap();

        // Validate refresh token
        let refresh_claims = jwt_service
            .validate_refresh_token(&token_pair.refresh_token)
            .unwrap();
        assert_eq!(refresh_claims.user_id, user.id.to_string());

        // Use refresh token to get new access token
        let new_access_token = jwt_service
            .refresh_token(&token_pair.refresh_token, &user)
            .await
            .unwrap();

        // Validate new access token
        let claims = jwt_service.validate_token(&new_access_token).unwrap();
        assert_eq!(claims.user_id, user.id.to_string());
    }

    #[test]
    fn test_invalid_token_validation() {
        let config = create_test_config();
        let jwt_service = JwtService::new(config);

        // Test invalid token
        let result = jwt_service.validate_token("invalid.token.here");
        assert!(result.is_err());

        // Test empty token
        let result = jwt_service.validate_token("");
        assert!(result.is_err());
    }

    #[test]
    fn test_user_permissions() {
        let mut user = create_test_user();
        user.is_admin = true;

        let permissions = user.get_permissions();
        assert!(permissions.contains(&"admin".to_string()));
        assert!(permissions.contains(&"node:read".to_string()));
        assert!(permissions.contains(&"test:permission".to_string()));
    }

    #[test]
    fn test_user_from_oidc() {
        let config = create_test_config();
        let jwt_service = JwtService::new(config);

        let oidc_info = UserInfo {
            sub: "oidc_sub_123".to_string(),
            email: Some("oidc@example.com".to_string()),
            name: Some("OIDC User".to_string()),
            picture: None,
            preferred_username: Some("oidcuser".to_string()),
        };

        // Test creating new user from OIDC
        let user = jwt_service.user_from_oidc(&oidc_info, None);
        assert_eq!(user.name, "oidcuser");
        assert_eq!(user.email, Some("oidc@example.com".to_string()));
        assert!(!user.is_admin);

        // Test updating existing user from OIDC
        let existing_user = create_test_user();
        let updated_user = jwt_service.user_from_oidc(&oidc_info, Some(&existing_user));
        assert_eq!(updated_user.id, existing_user.id);
        assert_eq!(updated_user.name, "oidcuser");
        assert_eq!(updated_user.is_admin, existing_user.is_admin);
    }
}