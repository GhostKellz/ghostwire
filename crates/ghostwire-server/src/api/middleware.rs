/// Middleware for API authentication, rate limiting, and request processing
///
/// Provides common middleware components for both gRPC and REST APIs:
/// - Authentication and authorization
/// - Rate limiting and abuse prevention
/// - Request logging and metrics
/// - CORS and security headers

use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};
use tokio::time::sleep;
use tracing::{debug, warn, error};

use ghostwire_common::{
    types::*,
    error::{Result, GhostWireError},
};

/// Authentication context for API requests
#[derive(Debug, Clone)]
pub enum AuthContext {
    /// Authenticated node with session token
    Node {
        node_id: NodeId,
        user_id: UserId,
        session_token: String,
    },
    /// Authenticated user with bearer token
    User {
        user_id: UserId,
        bearer_token: String,
        permissions: Vec<String>,
    },
    /// Administrative access with API key
    Admin {
        api_key: String,
        permissions: Vec<String>,
    },
    /// Unauthenticated request
    Anonymous,
}

/// Rate limiting configuration
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Maximum requests per window
    pub max_requests: u32,
    /// Time window duration
    pub window_duration: Duration,
    /// Burst allowance (additional requests allowed temporarily)
    pub burst_size: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_requests: 100,
            window_duration: Duration::from_secs(60),
            burst_size: 10,
        }
    }
}

/// Rate limit bucket for tracking client requests
#[derive(Debug)]
struct RateLimitBucket {
    tokens: u32,
    last_refill: Instant,
    requests_in_window: u32,
    window_start: Instant,
}

impl RateLimitBucket {
    fn new(config: &RateLimitConfig) -> Self {
        let now = Instant::now();
        Self {
            tokens: config.burst_size,
            last_refill: now,
            requests_in_window: 0,
            window_start: now,
        }
    }

    fn check_and_consume(&mut self, config: &RateLimitConfig) -> bool {
        let now = Instant::now();

        // Reset window if needed
        if now.duration_since(self.window_start) >= config.window_duration {
            self.window_start = now;
            self.requests_in_window = 0;
        }

        // Check window limit
        if self.requests_in_window >= config.max_requests {
            return false;
        }

        // Refill tokens (burst capacity)
        let time_since_refill = now.duration_since(self.last_refill);
        let tokens_to_add = (time_since_refill.as_millis() as u32 * config.burst_size)
            / config.window_duration.as_millis() as u32;

        if tokens_to_add > 0 {
            self.tokens = (self.tokens + tokens_to_add).min(config.burst_size);
            self.last_refill = now;
        }

        // Check burst capacity
        if self.tokens == 0 {
            return false;
        }

        // Consume token and increment window counter
        self.tokens -= 1;
        self.requests_in_window += 1;
        true
    }
}

/// Rate limiter implementation
pub struct RateLimiter {
    buckets: Arc<RwLock<HashMap<IpAddr, RateLimitBucket>>>,
    config: RateLimitConfig,
}

impl RateLimiter {
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            buckets: Arc::new(RwLock::new(HashMap::new())),
            config,
        }
    }

    /// Check if request should be rate limited
    pub async fn check_rate_limit(&self, client_ip: IpAddr) -> Result<()> {
        let mut buckets = self.buckets.write().unwrap();

        let bucket = buckets
            .entry(client_ip)
            .or_insert_with(|| RateLimitBucket::new(&self.config));

        if !bucket.check_and_consume(&self.config) {
            return Err(GhostWireError::ResourceExhausted(
                "Rate limit exceeded".to_string()
            ));
        }

        Ok(())
    }

    /// Clean up old buckets periodically
    pub async fn cleanup_task(&self) {
        let cleanup_interval = Duration::from_secs(300); // 5 minutes

        loop {
            sleep(cleanup_interval).await;

            let mut buckets = self.buckets.write().unwrap();
            let now = Instant::now();

            buckets.retain(|_, bucket| {
                // Keep buckets that have been active recently
                now.duration_since(bucket.window_start) < self.config.window_duration * 2
            });

            debug!("Cleaned up rate limit buckets, {} remaining", buckets.len());
        }
    }
}

/// Authentication middleware
pub struct AuthMiddleware {
    // TODO: Add authentication backend configuration
}

impl AuthMiddleware {
    pub fn new() -> Self {
        Self {}
    }

    /// Extract authentication context from request headers
    pub fn extract_auth_context(&self, headers: &HashMap<String, String>) -> AuthContext {
        // Check for API key (admin access)
        if let Some(api_key) = headers.get("x-api-key") {
            return AuthContext::Admin {
                api_key: api_key.clone(),
                permissions: vec!["admin".to_string()], // TODO: Lookup actual permissions
            };
        }

        // Check for Bearer token (user access)
        if let Some(auth_header) = headers.get("authorization") {
            if let Some(token) = auth_header.strip_prefix("Bearer ") {
                // TODO: Validate and decode JWT token
                return AuthContext::User {
                    user_id: UserId::new(), // TODO: Extract from token
                    bearer_token: token.to_string(),
                    permissions: vec![], // TODO: Extract from token
                };
            }
        }

        // Check for session token (node access)
        if let Some(session_token) = headers.get("x-session-token") {
            // TODO: Validate session token and extract node/user info
            return AuthContext::Node {
                node_id: NodeId::new(), // TODO: Extract from token
                user_id: UserId::new(), // TODO: Extract from token
                session_token: session_token.clone(),
            };
        }

        AuthContext::Anonymous
    }

    /// Check if authentication context has required permission
    pub fn check_permission(&self, context: &AuthContext, permission: &str) -> bool {
        match context {
            AuthContext::Admin { permissions, .. } => {
                permissions.contains(&"admin".to_string()) || permissions.contains(&permission.to_string())
            }
            AuthContext::User { permissions, .. } => {
                permissions.contains(&permission.to_string())
            }
            AuthContext::Node { .. } => {
                // Nodes have limited permissions - only for their own operations
                matches!(permission, "node:heartbeat" | "node:network-map" | "node:unregister")
            }
            AuthContext::Anonymous => false,
        }
    }

    /// Require specific authentication level
    pub fn require_auth(&self, context: &AuthContext, required_level: AuthLevel) -> Result<()> {
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
                _ => Err(GhostWireError::authentication("Admin authentication required")),
            },
        }
    }
}

/// Authentication levels
#[derive(Debug, Clone, Copy)]
pub enum AuthLevel {
    Anonymous,
    Node,
    User,
    Admin,
}

/// Request metrics collector
pub struct MetricsCollector {
    // TODO: Add metrics backend (Prometheus, etc.)
}

impl MetricsCollector {
    pub fn new() -> Self {
        Self {}
    }

    /// Record API request metrics
    pub fn record_request(
        &self,
        method: &str,
        path: &str,
        status_code: u16,
        duration: Duration,
        auth_context: &AuthContext,
    ) {
        let auth_type = match auth_context {
            AuthContext::Admin { .. } => "admin",
            AuthContext::User { .. } => "user",
            AuthContext::Node { .. } => "node",
            AuthContext::Anonymous => "anonymous",
        };

        debug!(
            method = method,
            path = path,
            status_code = status_code,
            duration_ms = duration.as_millis(),
            auth_type = auth_type,
            "API request completed"
        );

        // TODO: Send metrics to backend (Prometheus, etc.)
    }

    /// Record rate limit hit
    pub fn record_rate_limit(&self, client_ip: IpAddr, endpoint: &str) {
        warn!(
            client_ip = %client_ip,
            endpoint = endpoint,
            "Rate limit exceeded"
        );

        // TODO: Send metrics to backend
    }

    /// Record authentication failure
    pub fn record_auth_failure(&self, reason: &str, client_ip: IpAddr) {
        warn!(
            client_ip = %client_ip,
            reason = reason,
            "Authentication failed"
        );

        // TODO: Send metrics to backend
    }
}

/// Security headers middleware
pub struct SecurityHeaders;

impl SecurityHeaders {
    /// Get recommended security headers for REST API responses
    pub fn get_headers() -> HashMap<String, String> {
        let mut headers = HashMap::new();

        headers.insert("X-Content-Type-Options".to_string(), "nosniff".to_string());
        headers.insert("X-Frame-Options".to_string(), "DENY".to_string());
        headers.insert("X-XSS-Protection".to_string(), "1; mode=block".to_string());
        headers.insert("Referrer-Policy".to_string(), "strict-origin-when-cross-origin".to_string());
        headers.insert("Cache-Control".to_string(), "no-cache, no-store, must-revalidate".to_string());
        headers.insert("Pragma".to_string(), "no-cache".to_string());
        headers.insert("Expires".to_string(), "0".to_string());

        // CORS headers (configured per environment)
        headers.insert("Access-Control-Allow-Origin".to_string(), "*".to_string()); // TODO: Configure properly
        headers.insert("Access-Control-Allow-Methods".to_string(), "GET, POST, PUT, DELETE, OPTIONS".to_string());
        headers.insert("Access-Control-Allow-Headers".to_string(), "Content-Type, Authorization, X-API-Key, X-Session-Token".to_string());

        headers
    }
}

/// Request validation middleware
pub struct RequestValidator;

impl RequestValidator {
    /// Validate request size limits
    pub fn validate_request_size(&self, size: usize) -> Result<()> {
        const MAX_REQUEST_SIZE: usize = 10 * 1024 * 1024; // 10MB

        if size > MAX_REQUEST_SIZE {
            return Err(GhostWireError::validation("Request too large"));
        }

        Ok(())
    }

    /// Validate content type
    pub fn validate_content_type(&self, content_type: &str, expected: &str) -> Result<()> {
        if !content_type.starts_with(expected) {
            return Err(GhostWireError::validation(format!(
                "Invalid content type: expected {}, got {}",
                expected,
                content_type
            )));
        }

        Ok(())
    }

    /// Sanitize user input
    pub fn sanitize_string(&self, input: &str) -> String {
        input
            .chars()
            .filter(|c| c.is_ascii() && !c.is_control())
            .take(1000) // Limit length
            .collect()
    }
}