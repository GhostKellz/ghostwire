/// Session management for authenticated nodes
///
/// Handles session tokens, validation, and cleanup with:
/// - JWT-like token generation
/// - Session expiration tracking
/// - Node authentication
/// - Session invalidation

use ghostwire_common::{
    config::ServerConfig,
    error::{Result, GhostWireError},
    types::*,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::RwLock;
use tracing::{debug, warn};

/// Session information
#[derive(Debug, Clone)]
pub struct Session {
    pub token: String,
    pub node_id: NodeId,
    pub user_id: UserId,
    pub created_at: SystemTime,
    pub expires_at: SystemTime,
    pub last_seen: SystemTime,
}

/// Session manager
pub struct SessionManager {
    config: Arc<ServerConfig>,
    sessions: Arc<RwLock<HashMap<String, Session>>>,
    node_sessions: Arc<RwLock<HashMap<NodeId, String>>>, // node_id -> token
}

impl SessionManager {
    /// Create new session manager
    pub fn new(config: Arc<ServerConfig>) -> Self {
        Self {
            config,
            sessions: Arc::new(RwLock::new(HashMap::new())),
            node_sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create a new session for a node
    pub async fn create_session(&self, node: &Node) -> Result<Session> {
        // Generate secure session token
        let token = self.generate_session_token(node)?;

        let now = SystemTime::now();
        let session = Session {
            token: token.clone(),
            node_id: node.id,
            user_id: node.user_id,
            created_at: now,
            expires_at: now + self.config.auth.session_timeout,
            last_seen: now,
        };

        // Store session
        self.sessions.write().await.insert(token.clone(), session.clone());
        self.node_sessions.write().await.insert(node.id, token.clone());

        debug!("Created session for node {} ({})", node.id, node.name);

        Ok(session)
    }

    /// Validate and retrieve session
    pub async fn validate_session(&self, token: &str) -> Result<Session> {
        let mut sessions = self.sessions.write().await;

        match sessions.get_mut(token) {
            Some(session) => {
                // Check if expired
                if SystemTime::now() > session.expires_at {
                    // Remove expired session
                    let node_id = session.node_id;
                    sessions.remove(token);
                    self.node_sessions.write().await.remove(&node_id);

                    return Err(GhostWireError::authentication("Session expired"));
                }

                // Update last seen
                session.last_seen = SystemTime::now();
                Ok(session.clone())
            }
            None => Err(GhostWireError::authentication("Invalid session token")),
        }
    }

    /// Refresh session expiration
    pub async fn refresh_session(&self, token: &str) -> Result<()> {
        let mut sessions = self.sessions.write().await;

        if let Some(session) = sessions.get_mut(token) {
            session.expires_at = SystemTime::now() + self.config.auth.session_timeout;
            session.last_seen = SystemTime::now();
            debug!("Refreshed session for node {}", session.node_id);
        }

        Ok(())
    }

    /// Invalidate a session
    pub async fn invalidate_session(&self, token: &str) -> Result<()> {
        let mut sessions = self.sessions.write().await;

        if let Some(session) = sessions.remove(token) {
            self.node_sessions.write().await.remove(&session.node_id);
            debug!("Invalidated session for node {}", session.node_id);
        }

        Ok(())
    }

    /// Invalidate all sessions for a node
    pub async fn invalidate_node_sessions(&self, node_id: &NodeId) -> Result<()> {
        let mut node_sessions = self.node_sessions.write().await;

        if let Some(token) = node_sessions.remove(node_id) {
            self.sessions.write().await.remove(&token);
            debug!("Invalidated all sessions for node {}", node_id);
        }

        Ok(())
    }

    /// Get session by node ID
    pub async fn get_node_session(&self, node_id: &NodeId) -> Option<Session> {
        let node_sessions = self.node_sessions.read().await;
        let sessions = self.sessions.read().await;

        if let Some(token) = node_sessions.get(node_id) {
            sessions.get(token).cloned()
        } else {
            None
        }
    }

    /// Clean up expired sessions (should be called periodically)
    pub async fn cleanup_expired_sessions(&self) -> usize {
        let now = SystemTime::now();
        let mut sessions = self.sessions.write().await;
        let mut node_sessions = self.node_sessions.write().await;

        let mut expired = Vec::new();

        // Find expired sessions
        for (token, session) in sessions.iter() {
            if now > session.expires_at {
                expired.push((token.clone(), session.node_id));
            }
        }

        // Remove expired sessions
        for (token, node_id) in &expired {
            sessions.remove(token);
            node_sessions.remove(node_id);
        }

        let count = expired.len();
        if count > 0 {
            debug!("Cleaned up {} expired sessions", count);
        }

        count
    }

    /// Get session count
    pub async fn session_count(&self) -> usize {
        self.sessions.read().await.len()
    }

    /// Generate secure session token
    fn generate_session_token(&self, node: &Node) -> Result<String> {
        use blake3::Hasher;
        use std::time::{SystemTime, UNIX_EPOCH};

        // Create token payload
        let mut hasher = Hasher::new();
        hasher.update(node.id.as_bytes());
        hasher.update(node.public_key.0.as_slice());
        hasher.update(&SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
            .to_le_bytes());

        // Add some randomness
        let random_bytes: [u8; 16] = rand::random();
        hasher.update(&random_bytes);

        // Generate token
        let hash = hasher.finalize();
        Ok(base64::encode_config(hash.as_bytes(), base64::URL_SAFE_NO_PAD))
    }

    /// Start cleanup task
    pub async fn start_cleanup_task(&self) {
        let sessions_clone = Arc::clone(&self.sessions);
        let node_sessions_clone = Arc::clone(&self.node_sessions);

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(300)); // 5 minutes

            loop {
                interval.tick().await;

                let now = SystemTime::now();
                let mut sessions = sessions_clone.write().await;
                let mut node_sessions = node_sessions_clone.write().await;

                let mut expired = Vec::new();

                // Find expired sessions
                for (token, session) in sessions.iter() {
                    if now > session.expires_at {
                        expired.push((token.clone(), session.node_id));
                    }
                }

                // Remove expired sessions
                for (token, node_id) in expired {
                    sessions.remove(&token);
                    node_sessions.remove(&node_id);
                }
            }
        });
    }
}

/// Session validation middleware data
#[derive(Debug, Clone)]
pub struct SessionContext {
    pub session: Session,
    pub node_id: NodeId,
    pub user_id: UserId,
}