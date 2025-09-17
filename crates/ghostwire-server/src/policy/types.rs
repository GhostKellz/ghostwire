/// Core types for the ACL policy system
///
/// Defines the fundamental data structures used throughout the policy engine
/// for representing principals, resources, actions, and policy decisions.

use ghostwire_common::types::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::SystemTime;
use uuid::Uuid;

/// Policy action (allow/deny)
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicyAction {
    Allow,
    Deny,
}

/// Policy decision result
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicyDecision {
    Allow,
    Deny,
    /// Policy evaluation was inconclusive
    Undecided,
}

/// Principal making a request (user or node)
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum PolicyPrincipal {
    User {
        id: UserId,
        name: String,
        email: Option<String>,
        groups: Vec<String>,
        roles: Vec<String>,
        attributes: HashMap<String, String>,
    },
    Node {
        id: NodeId,
        name: String,
        tags: Vec<String>,
        owner: UserId,
        machine_key: String,
        attributes: HashMap<String, String>,
    },
    Service {
        name: String,
        namespace: String,
        labels: HashMap<String, String>,
    },
}

impl PolicyPrincipal {
    /// Get the principal ID as a string
    pub fn id(&self) -> String {
        match self {
            PolicyPrincipal::User { id, .. } => id.to_string(),
            PolicyPrincipal::Node { id, .. } => id.to_string(),
            PolicyPrincipal::Service { name, namespace, .. } => {
                format!("{}/{}", namespace, name)
            }
        }
    }

    /// Get the principal name
    pub fn name(&self) -> &str {
        match self {
            PolicyPrincipal::User { name, .. } => name,
            PolicyPrincipal::Node { name, .. } => name,
            PolicyPrincipal::Service { name, .. } => name,
        }
    }

    /// Get all groups/tags/labels for the principal
    pub fn groups(&self) -> Vec<&str> {
        match self {
            PolicyPrincipal::User { groups, .. } => groups.iter().map(|s| s.as_str()).collect(),
            PolicyPrincipal::Node { tags, .. } => tags.iter().map(|s| s.as_str()).collect(),
            PolicyPrincipal::Service { labels, .. } => labels.keys().map(|s| s.as_str()).collect(),
        }
    }

    /// Check if principal has a specific group/tag/label
    pub fn has_group(&self, group: &str) -> bool {
        self.groups().contains(&group)
    }

    /// Get attribute value
    pub fn get_attribute(&self, key: &str) -> Option<&str> {
        match self {
            PolicyPrincipal::User { attributes, .. } => attributes.get(key).map(|s| s.as_str()),
            PolicyPrincipal::Node { attributes, .. } => attributes.get(key).map(|s| s.as_str()),
            PolicyPrincipal::Service { labels, .. } => labels.get(key).map(|s| s.as_str()),
        }
    }
}

/// Resource being accessed
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum PolicyResource {
    Node {
        id: NodeId,
        name: String,
        tags: Vec<String>,
        owner: UserId,
        subnet: Option<String>,
        routes: Vec<String>,
    },
    Network {
        id: String,
        name: String,
        cidr: String,
        tags: Vec<String>,
        owner: UserId,
    },
    Route {
        destination: String,
        node_id: NodeId,
        advertised: bool,
        primary: bool,
    },
    User {
        id: UserId,
        name: String,
        email: Option<String>,
        groups: Vec<String>,
    },
    Admin {
        scope: String,
        resource_type: String,
    },
    Api {
        endpoint: String,
        method: String,
        version: String,
    },
}

impl PolicyResource {
    /// Get the resource ID as a string
    pub fn id(&self) -> String {
        match self {
            PolicyResource::Node { id, .. } => id.to_string(),
            PolicyResource::Network { id, .. } => id.clone(),
            PolicyResource::Route { destination, .. } => destination.clone(),
            PolicyResource::User { id, .. } => id.to_string(),
            PolicyResource::Admin { scope, .. } => scope.clone(),
            PolicyResource::Api { endpoint, .. } => endpoint.clone(),
        }
    }

    /// Get the resource name
    pub fn name(&self) -> String {
        match self {
            PolicyResource::Node { name, .. } => name.clone(),
            PolicyResource::Network { name, .. } => name.clone(),
            PolicyResource::Route { destination, .. } => destination.clone(),
            PolicyResource::User { name, .. } => name.clone(),
            PolicyResource::Admin { scope, .. } => scope.clone(),
            PolicyResource::Api { endpoint, .. } => endpoint.clone(),
        }
    }

    /// Get all tags for the resource
    pub fn tags(&self) -> Vec<&str> {
        match self {
            PolicyResource::Node { tags, .. } => tags.iter().map(|s| s.as_str()).collect(),
            PolicyResource::Network { tags, .. } => tags.iter().map(|s| s.as_str()).collect(),
            PolicyResource::User { groups, .. } => groups.iter().map(|s| s.as_str()).collect(),
            _ => vec![],
        }
    }

    /// Check if resource has a specific tag
    pub fn has_tag(&self, tag: &str) -> bool {
        self.tags().contains(&tag)
    }

    /// Get the resource owner
    pub fn owner(&self) -> Option<UserId> {
        match self {
            PolicyResource::Node { owner, .. } => Some(*owner),
            PolicyResource::Network { owner, .. } => Some(*owner),
            PolicyResource::User { id, .. } => Some(*id),
            _ => None,
        }
    }
}

/// Policy evaluation context
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct PolicyContext {
    /// Source IP address
    pub source_ip: Option<String>,

    /// Time of day constraints
    pub time_of_day: Option<String>,

    /// Geographic location
    pub location: Option<String>,

    /// Network constraints
    pub network: Option<NetworkContext>,

    /// Device information
    pub device: Option<DeviceContext>,

    /// Custom attributes
    pub attributes: HashMap<String, String>,
}

impl PolicyContext {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_source_ip(mut self, ip: String) -> Self {
        self.source_ip = Some(ip);
        self
    }

    pub fn with_location(mut self, location: String) -> Self {
        self.location = Some(location);
        self
    }

    pub fn with_attribute(mut self, key: String, value: String) -> Self {
        self.attributes.insert(key, value);
        self
    }

    pub fn get_attribute(&self, key: &str) -> Option<&str> {
        self.attributes.get(key).map(|s| s.as_str())
    }
}

/// Network context for policy evaluation
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NetworkContext {
    pub subnet: String,
    pub is_exit_node: bool,
    pub routes_advertised: Vec<String>,
    pub dns_config: Option<String>,
}

/// Device context for policy evaluation
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DeviceContext {
    pub os: String,
    pub hostname: String,
    pub is_managed: bool,
    pub compliance_status: Option<String>,
    pub last_seen: SystemTime,
}

/// Policy rule definition
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PolicyRule {
    /// Rule identifier
    pub id: String,

    /// Human-readable description
    pub description: String,

    /// Rule priority (higher = more important)
    pub priority: i32,

    /// When this rule is active
    pub enabled: bool,

    /// Source principal matches
    pub source: Option<PrincipalMatcher>,

    /// Target resource matches
    pub target: Option<ResourceMatcher>,

    /// Action pattern
    pub action: Option<ActionMatcher>,

    /// Context constraints
    pub context: Option<ContextMatcher>,

    /// Rule effect
    pub effect: PolicyAction,

    /// Additional conditions (custom logic)
    pub conditions: Vec<Condition>,

    /// Rule metadata
    pub metadata: HashMap<String, String>,
}

/// Principal matching criteria
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PrincipalMatcher {
    /// Principal type filter
    pub principal_type: Option<String>,

    /// ID patterns
    pub ids: Option<Vec<String>>,

    /// Name patterns (supports wildcards)
    pub names: Option<Vec<String>>,

    /// Group membership requirements
    pub groups: Option<GroupMatcher>,

    /// Attribute requirements
    pub attributes: Option<HashMap<String, AttributeMatcher>>,

    /// Owner requirements
    pub owners: Option<Vec<String>>,
}

/// Resource matching criteria
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ResourceMatcher {
    /// Resource type filter
    pub resource_type: Option<String>,

    /// ID patterns
    pub ids: Option<Vec<String>>,

    /// Name patterns (supports wildcards)
    pub names: Option<Vec<String>>,

    /// Tag requirements
    pub tags: Option<TagMatcher>,

    /// Owner requirements
    pub owners: Option<Vec<String>>,
}

/// Action matching criteria
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ActionMatcher {
    /// Exact action matches
    pub exact: Option<Vec<String>>,

    /// Pattern matches (supports wildcards)
    pub patterns: Option<Vec<String>>,

    /// Action categories
    pub categories: Option<Vec<String>>,
}

/// Context matching criteria
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ContextMatcher {
    /// Source IP requirements
    pub source_ips: Option<Vec<String>>,

    /// Time constraints
    pub time_ranges: Option<Vec<TimeRange>>,

    /// Location constraints
    pub locations: Option<Vec<String>>,

    /// Custom context attributes
    pub attributes: Option<HashMap<String, AttributeMatcher>>,
}

/// Group matching logic
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum GroupMatcher {
    /// Principal must be in ALL listed groups
    All { groups: Vec<String> },
    /// Principal must be in ANY of the listed groups
    Any { groups: Vec<String> },
    /// Principal must NOT be in any listed groups
    None { groups: Vec<String> },
}

/// Tag matching logic
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum TagMatcher {
    /// Resource must have ALL listed tags
    All { tags: Vec<String> },
    /// Resource must have ANY of the listed tags
    Any { tags: Vec<String> },
    /// Resource must NOT have any listed tags
    None { tags: Vec<String> },
}

/// Attribute matching logic
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "operator", rename_all = "lowercase")]
pub enum AttributeMatcher {
    /// Exact value match
    Equals { value: String },
    /// Pattern match (supports wildcards)
    Matches { pattern: String },
    /// Value in list
    In { values: Vec<String> },
    /// Value exists (any value)
    Exists,
    /// Value does not exist
    NotExists,
}

/// Time range constraint
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TimeRange {
    /// Start time (HH:MM format)
    pub start: String,
    /// End time (HH:MM format)
    pub end: String,
    /// Days of week (Mon, Tue, etc.)
    pub days: Option<Vec<String>>,
    /// Timezone
    pub timezone: Option<String>,
}

/// Custom condition for advanced logic
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Condition {
    /// Condition type
    pub condition_type: String,
    /// Condition parameters
    pub parameters: HashMap<String, String>,
    /// Negate the condition result
    pub negate: bool,
}

/// Policy set containing multiple rules
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PolicySet {
    /// Policy set metadata
    pub metadata: PolicyMetadata,
    /// List of policy rules
    pub rules: Vec<PolicyRule>,
}

/// Policy metadata
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PolicyMetadata {
    /// Policy name
    pub name: String,
    /// Policy version
    pub version: String,
    /// Description
    pub description: String,
    /// Author
    pub author: Option<String>,
    /// Creation timestamp
    pub created_at: SystemTime,
    /// Last modified timestamp
    pub modified_at: SystemTime,
    /// Tags for organization
    pub tags: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_principal_user() {
        let user = PolicyPrincipal::User {
            id: Uuid::new_v4(),
            name: "testuser".to_string(),
            email: Some("test@example.com".to_string()),
            groups: vec!["admin".to_string(), "users".to_string()],
            roles: vec!["developer".to_string()],
            attributes: HashMap::new(),
        };

        assert_eq!(user.name(), "testuser");
        assert!(user.has_group("admin"));
        assert!(user.has_group("users"));
        assert!(!user.has_group("invalid"));
    }

    #[test]
    fn test_policy_resource_node() {
        let node = PolicyResource::Node {
            id: Uuid::new_v4(),
            name: "test-node".to_string(),
            tags: vec!["production".to_string(), "web".to_string()],
            owner: Uuid::new_v4(),
            subnet: Some("192.168.1.0/24".to_string()),
            routes: vec![],
        };

        assert_eq!(node.name(), "test-node");
        assert!(node.has_tag("production"));
        assert!(node.has_tag("web"));
        assert!(!node.has_tag("staging"));
    }

    #[test]
    fn test_policy_context() {
        let context = PolicyContext::new()
            .with_source_ip("192.168.1.100".to_string())
            .with_location("US-East".to_string())
            .with_attribute("department".to_string(), "engineering".to_string());

        assert_eq!(context.source_ip.unwrap(), "192.168.1.100");
        assert_eq!(context.location.unwrap(), "US-East");
        assert_eq!(context.get_attribute("department").unwrap(), "engineering");
    }

    #[test]
    fn test_group_matcher() {
        let matcher = GroupMatcher::Any {
            groups: vec!["admin".to_string(), "moderator".to_string()],
        };

        if let GroupMatcher::Any { groups } = matcher {
            assert!(groups.contains(&"admin".to_string()));
            assert!(groups.contains(&"moderator".to_string()));
        }
    }

    #[test]
    fn test_attribute_matcher() {
        let matcher = AttributeMatcher::Equals {
            value: "production".to_string(),
        };

        if let AttributeMatcher::Equals { value } = matcher {
            assert_eq!(value, "production");
        }
    }
}