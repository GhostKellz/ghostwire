/// Access Control List (ACL) policy engine
///
/// Provides flexible, JSON-based policy evaluation for controlling access
/// to nodes, resources, and operations within the GhostWire mesh network.
/// Supports HuJSON (Human JSON) format for readable policy definitions.

pub mod engine;
pub mod parser;
pub mod evaluator;
pub mod types;

pub use engine::PolicyEngine;
pub use parser::HuJsonParser;
pub use evaluator::PolicyEvaluator;
pub use types::*;

use ghostwire_common::{
    types::*,
    error::{Result, GhostWireError},
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::SystemTime;

/// Policy configuration
#[derive(Debug, Clone, Deserialize)]
pub struct PolicyConfig {
    /// Policy file paths
    pub policy_files: Vec<String>,

    /// Policy directory for auto-loading
    pub policy_directory: Option<String>,

    /// Policy reload interval in seconds
    pub reload_interval_seconds: u64,

    /// Default policy (allow/deny)
    pub default_action: PolicyAction,

    /// Enable policy caching
    pub enable_cache: bool,

    /// Cache TTL in seconds
    pub cache_ttl_seconds: u64,

    /// Enable policy validation on reload
    pub validate_on_reload: bool,

    /// Enable audit logging for policy decisions
    pub audit_logging: bool,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            policy_files: vec!["policies/default.hujson".to_string()],
            policy_directory: Some("policies/".to_string()),
            reload_interval_seconds: 300, // 5 minutes
            default_action: PolicyAction::Deny,
            enable_cache: true,
            cache_ttl_seconds: 3600, // 1 hour
            validate_on_reload: true,
            audit_logging: true,
        }
    }
}

/// Policy evaluation request
#[derive(Debug, Clone)]
pub struct PolicyRequest {
    /// Source user/node making the request
    pub source: PolicyPrincipal,

    /// Target resource being accessed
    pub target: PolicyResource,

    /// Action being performed
    pub action: String,

    /// Additional context
    pub context: PolicyContext,

    /// Request timestamp
    pub timestamp: SystemTime,
}

/// Policy evaluation response
#[derive(Debug, Clone, PartialEq)]
pub struct PolicyResponse {
    /// Final decision
    pub decision: PolicyDecision,

    /// Matching policy rule
    pub matched_rule: Option<String>,

    /// Reason for the decision
    pub reason: String,

    /// Additional metadata
    pub metadata: HashMap<String, String>,

    /// Evaluation duration
    pub evaluation_time_ms: u64,
}

/// Policy evaluation statistics
#[derive(Debug, Clone, Serialize)]
pub struct PolicyStats {
    pub total_evaluations: u64,
    pub allowed_decisions: u64,
    pub denied_decisions: u64,
    pub average_evaluation_time_ms: f64,
    pub cache_hit_rate: f64,
    pub policy_reload_count: u64,
    pub last_reload_time: Option<SystemTime>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_config_default() {
        let config = PolicyConfig::default();
        assert_eq!(config.default_action, PolicyAction::Deny);
        assert!(config.enable_cache);
        assert!(config.validate_on_reload);
    }

    #[test]
    fn test_policy_request_creation() {
        let request = PolicyRequest {
            source: PolicyPrincipal::User {
                id: UserId::new_v4(),
                name: "testuser".to_string(),
                groups: vec!["users".to_string()],
                attributes: HashMap::new(),
            },
            target: PolicyResource::Node {
                id: NodeId::new_v4(),
                name: "test-node".to_string(),
                tags: vec!["production".to_string()],
                owner: UserId::new_v4(),
            },
            action: "connect".to_string(),
            context: PolicyContext::new(),
            timestamp: SystemTime::now(),
        };

        assert_eq!(request.action, "connect");
        assert!(matches!(request.source, PolicyPrincipal::User { .. }));
        assert!(matches!(request.target, PolicyResource::Node { .. }));
    }

    #[test]
    fn test_policy_response_decision() {
        let response = PolicyResponse {
            decision: PolicyDecision::Allow,
            matched_rule: Some("allow-users-to-prod".to_string()),
            reason: "User in production group".to_string(),
            metadata: HashMap::new(),
            evaluation_time_ms: 5,
        };

        assert_eq!(response.decision, PolicyDecision::Allow);
        assert_eq!(response.matched_rule.unwrap(), "allow-users-to-prod");
    }
}