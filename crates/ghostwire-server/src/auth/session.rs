/// Session token management for node authentication
///
/// Provides secure, temporary authentication tokens for node-to-server communication
/// with automatic cleanup and expiration management

use crate::auth::SessionConfig;
use crate::coordinator::Coordinator;
use ghostwire_common::{
    types::*,
    error::{Result, GhostWireError},
    crypto::SessionTokens,
};
use std::sync::Arc;
use std::time::{SystemTime, Duration};
use tokio::time::{sleep, interval};
use tracing::{info, warn, debug};
use serde::{Serialize, Deserialize};
use uuid::Uuid;

/// Session information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    pub session_id: String,
    pub node_id: NodeId,
    pub user_id: UserId,
    pub token_hash: String,
    pub created_at: SystemTime,
    pub last_used_at: SystemTime,
    pub expires_at: SystemTime,
    pub is_active: bool,
}

/// In-memory session cache for performance
#[derive(Debug, Clone)]
struct CachedSession {
    info: SessionInfo,
    cached_at: SystemTime,
}

/// Session service for managing node authentication tokens
#[derive(Clone)]
pub struct SessionService {
    config: SessionConfig,
    coordinator: Arc<Coordinator>,
}

impl SessionService {
    /// Create new session service
    pub fn new(config: SessionConfig, coordinator: Arc<Coordinator>) -> Self {
        Self { config, coordinator }
    }

    /// Create a new session for a node
    pub async fn create_session(
        &self,
        node_id: &NodeId,
        user_id: &UserId,
        public_key: &PublicKey,
    ) -> Result<String> {
        let session_id = format!("sess_{}", Uuid::new_v4());
        let now = SystemTime::now();
        let expires_at = now + Duration::from_secs(self.config.timeout_hours * 3600);

        // Generate session token
        let token = SessionTokens::generate(public_key, &user_id.to_string())?;

        // Hash token for storage (we don't store the actual token)
        let token_hash = blake3::hash(token.as_bytes()).to_hex().to_string();

        let session_info = SessionInfo {
            session_id: session_id.clone(),
            node_id: *node_id,
            user_id: *user_id,
            token_hash: token_hash.clone(),
            created_at: now,
            last_used_at: now,
            expires_at,
            is_active: true,
        };

        // Store session in database
        self.store_session(&session_info).await?;

        debug!(
            node_id = %node_id,
            user_id = %user_id,
            session_id = %session_id,
            expires_at = ?expires_at,
            "Created new session"
        );

        Ok(token)
    }

    /// Validate a session token
    pub async fn validate_session(&self, token: &str) -> Result<Option<SessionInfo>> {
        if !token.starts_with("sess_") {
            return Ok(None);
        }

        // Hash the provided token
        let token_hash = blake3::hash(token.as_bytes()).to_hex().to_string();

        // Look up session by token hash
        let session = self.get_session_by_token_hash(&token_hash).await?;

        match session {
            Some(mut session_info) => {
                // Check if session is expired
                if session_info.expires_at < SystemTime::now() {
                    // Clean up expired session
                    self.deactivate_session(&session_info.session_id).await?;
                    return Ok(None);
                }

                // Check if session is active
                if !session_info.is_active {
                    return Ok(None);
                }

                // Update last used timestamp
                session_info.last_used_at = SystemTime::now();
                self.update_session_last_used(&session_info.session_id, session_info.last_used_at).await?;

                debug!(
                    session_id = %session_info.session_id,
                    node_id = %session_info.node_id,
                    "Validated session"
                );

                Ok(Some(session_info))
            }
            None => Ok(None),
        }
    }

    /// Invalidate a session
    pub async fn invalidate_session(&self, token: &str) -> Result<()> {
        let token_hash = blake3::hash(token.as_bytes()).to_hex().to_string();

        if let Some(session) = self.get_session_by_token_hash(&token_hash).await? {
            self.deactivate_session(&session.session_id).await?;

            info!(
                session_id = %session.session_id,
                node_id = %session.node_id,
                "Invalidated session"
            );
        }

        Ok(())
    }

    /// Get all active sessions for a node
    pub async fn get_node_sessions(&self, node_id: &NodeId) -> Result<Vec<SessionInfo>> {
        self.coordinator.database
            .query_sessions_by_node(node_id)
            .await
    }

    /// Get all active sessions for a user
    pub async fn get_user_sessions(&self, user_id: &UserId) -> Result<Vec<SessionInfo>> {
        self.coordinator.database
            .query_sessions_by_user(user_id)
            .await
    }

    /// Revoke all sessions for a node
    pub async fn revoke_node_sessions(&self, node_id: &NodeId) -> Result<u32> {
        let sessions = self.get_node_sessions(node_id).await?;
        let count = sessions.len() as u32;

        for session in sessions {
            self.deactivate_session(&session.session_id).await?;
        }

        info!(
            node_id = %node_id,
            count = count,
            "Revoked all sessions for node"
        );

        Ok(count)
    }

    /// Revoke all sessions for a user
    pub async fn revoke_user_sessions(&self, user_id: &UserId) -> Result<u32> {
        let sessions = self.get_user_sessions(user_id).await?;
        let count = sessions.len() as u32;

        for session in sessions {
            self.deactivate_session(&session.session_id).await?;
        }

        info!(
            user_id = %user_id,
            count = count,
            "Revoked all sessions for user"
        );

        Ok(count)
    }

    /// Clean up expired sessions (background task)
    pub async fn cleanup_expired_sessions(&self) {
        let mut cleanup_interval = interval(Duration::from_secs(
            self.config.cleanup_interval_hours * 3600
        ));

        loop {
            cleanup_interval.tick().await;

            match self.perform_cleanup().await {
                Ok(count) => {
                    if count > 0 {
                        info!(count = count, "Cleaned up expired sessions");
                    }
                }
                Err(e) => {
                    warn!(error = %e, "Failed to clean up expired sessions");
                }
            }
        }
    }

    /// Perform cleanup of expired sessions
    async fn perform_cleanup(&self) -> Result<u32> {
        let now = SystemTime::now();
        let count = self.coordinator.database
            .delete_expired_sessions(now)
            .await?;

        Ok(count)
    }

    /// Store session in database
    async fn store_session(&self, session: &SessionInfo) -> Result<()> {
        self.coordinator.database
            .insert_session(session)
            .await
    }

    /// Get session by token hash
    async fn get_session_by_token_hash(&self, token_hash: &str) -> Result<Option<SessionInfo>> {
        self.coordinator.database
            .query_session_by_token_hash(token_hash)
            .await
    }

    /// Update session last used timestamp
    async fn update_session_last_used(
        &self,
        session_id: &str,
        last_used_at: SystemTime,
    ) -> Result<()> {
        self.coordinator.database
            .update_session_last_used(session_id, last_used_at)
            .await
    }

    /// Deactivate a session
    async fn deactivate_session(&self, session_id: &str) -> Result<()> {
        self.coordinator.database
            .deactivate_session(session_id)
            .await
    }

    /// Get session statistics
    pub async fn get_session_stats(&self) -> Result<SessionStats> {
        let now = SystemTime::now();
        let active_count = self.coordinator.database
            .count_active_sessions()
            .await?;

        let expired_count = self.coordinator.database
            .count_expired_sessions(now)
            .await?;

        let total_count = active_count + expired_count;

        Ok(SessionStats {
            total_sessions: total_count,
            active_sessions: active_count,
            expired_sessions: expired_count,
        })
    }

    /// Create session for testing
    #[cfg(test)]
    pub async fn create_test_session(&self, node_id: NodeId, user_id: UserId) -> Result<String> {
        let public_key = PublicKey([1u8; 32]); // Test key
        self.create_session(&node_id, &user_id, &public_key).await
    }
}

/// Session statistics
#[derive(Debug, Serialize)]
pub struct SessionStats {
    pub total_sessions: u32,
    pub active_sessions: u32,
    pub expired_sessions: u32,
}

// Database operations would be implemented in the database module
// These are placeholder trait definitions

pub trait SessionDatabase {
    async fn insert_session(&self, session: &SessionInfo) -> Result<()>;
    async fn query_session_by_token_hash(&self, token_hash: &str) -> Result<Option<SessionInfo>>;
    async fn query_sessions_by_node(&self, node_id: &NodeId) -> Result<Vec<SessionInfo>>;
    async fn query_sessions_by_user(&self, user_id: &UserId) -> Result<Vec<SessionInfo>>;
    async fn update_session_last_used(&self, session_id: &str, last_used_at: SystemTime) -> Result<()>;
    async fn deactivate_session(&self, session_id: &str) -> Result<()>;
    async fn delete_expired_sessions(&self, now: SystemTime) -> Result<u32>;
    async fn count_active_sessions(&self) -> Result<u32>;
    async fn count_expired_sessions(&self, now: SystemTime) -> Result<u32>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    // Mock coordinator for testing
    struct MockCoordinator;

    impl MockCoordinator {
        fn new() -> Arc<Self> {
            Arc::new(Self)
        }
    }

    fn create_test_config() -> SessionConfig {
        SessionConfig {
            timeout_hours: 24,
            cleanup_interval_hours: 1,
        }
    }

    fn create_test_session_info() -> SessionInfo {
        let now = SystemTime::now();
        SessionInfo {
            session_id: "sess_test_123".to_string(),
            node_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            token_hash: "test_hash".to_string(),
            created_at: now,
            last_used_at: now,
            expires_at: now + Duration::from_secs(3600),
            is_active: true,
        }
    }

    #[test]
    fn test_session_info_creation() {
        let session = create_test_session_info();
        assert!(session.is_active);
        assert!(session.expires_at > session.created_at);
        assert_eq!(session.last_used_at, session.created_at);
    }

    #[test]
    fn test_token_hash_generation() {
        let token = "sess_test_token_12345";
        let hash1 = blake3::hash(token.as_bytes()).to_hex().to_string();
        let hash2 = blake3::hash(token.as_bytes()).to_hex().to_string();

        // Same token should produce same hash
        assert_eq!(hash1, hash2);

        // Different token should produce different hash
        let different_token = "sess_test_token_67890";
        let hash3 = blake3::hash(different_token.as_bytes()).to_hex().to_string();
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_session_expiration() {
        let mut session = create_test_session_info();
        let now = SystemTime::now();

        // Session should not be expired initially
        assert!(session.expires_at > now);

        // Set expiration in the past
        session.expires_at = now - Duration::from_secs(3600);
        assert!(session.expires_at < now);
    }

    #[test]
    fn test_session_token_prefix() {
        let token = "sess_abc123";
        assert!(token.starts_with("sess_"));

        let invalid_token = "invalid_token";
        assert!(!invalid_token.starts_with("sess_"));
    }
}