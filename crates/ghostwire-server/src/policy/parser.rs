/// HuJSON (Human JSON) parser for policy files
///
/// Provides parsing capabilities for policy files written in HuJSON format,
/// which allows comments and trailing commas for better readability.

use crate::policy::types::*;
use ghostwire_common::error::{Result, GhostWireError};
use serde_json::{self, Value};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use tracing::{debug, warn, error};

/// HuJSON parser for policy files
#[derive(Debug, Clone)]
pub struct HuJsonParser {
    /// Enable strict parsing mode
    strict_mode: bool,
    /// Maximum file size in bytes
    max_file_size: usize,
    /// Enable schema validation
    validate_schema: bool,
}

impl Default for HuJsonParser {
    fn default() -> Self {
        Self {
            strict_mode: false,
            max_file_size: 10 * 1024 * 1024, // 10MB
            validate_schema: true,
        }
    }
}

impl HuJsonParser {
    /// Create a new HuJSON parser
    pub fn new() -> Self {
        Self::default()
    }

    /// Enable strict parsing mode
    pub fn with_strict_mode(mut self, strict: bool) -> Self {
        self.strict_mode = strict;
        self
    }

    /// Set maximum file size
    pub fn with_max_file_size(mut self, size: usize) -> Self {
        self.max_file_size = size;
        self
    }

    /// Enable schema validation
    pub fn with_schema_validation(mut self, validate: bool) -> Self {
        self.validate_schema = validate;
        self
    }

    /// Parse a policy file from path
    pub fn parse_file<P: AsRef<Path>>(&self, path: P) -> Result<PolicySet> {
        let path = path.as_ref();
        debug!("Parsing policy file: {}", path.display());

        // Check file size
        let metadata = fs::metadata(path)
            .map_err(|e| GhostWireError::io(format!("Failed to read file metadata: {}", e)))?;

        if metadata.len() as usize > self.max_file_size {
            return Err(GhostWireError::validation(format!(
                "Policy file too large: {} bytes (max: {})",
                metadata.len(),
                self.max_file_size
            )));
        }

        // Read file content
        let content = fs::read_to_string(path)
            .map_err(|e| GhostWireError::io(format!("Failed to read policy file: {}", e)))?;

        self.parse_content(&content)
    }

    /// Parse policy content from string
    pub fn parse_content(&self, content: &str) -> Result<PolicySet> {
        debug!("Parsing policy content ({} bytes)", content.len());

        // Strip HuJSON features (comments, trailing commas)
        let cleaned_content = self.strip_hujson(content)?;

        // Parse as JSON
        let value: Value = serde_json::from_str(&cleaned_content)
            .map_err(|e| GhostWireError::validation(format!("JSON parsing failed: {}", e)))?;

        // Validate schema if enabled
        if self.validate_schema {
            self.validate_policy_schema(&value)?;
        }

        // Convert to PolicySet
        let policy_set: PolicySet = serde_json::from_value(value)
            .map_err(|e| GhostWireError::validation(format!("Policy deserialization failed: {}", e)))?;

        // Validate policy rules
        self.validate_policy_set(&policy_set)?;

        debug!("Successfully parsed policy with {} rules", policy_set.rules.len());
        Ok(policy_set)
    }

    /// Parse multiple policy files from a directory
    pub fn parse_directory<P: AsRef<Path>>(&self, dir_path: P) -> Result<Vec<PolicySet>> {
        let dir_path = dir_path.as_ref();
        debug!("Parsing policy directory: {}", dir_path.display());

        let mut policy_sets = Vec::new();

        let entries = fs::read_dir(dir_path)
            .map_err(|e| GhostWireError::io(format!("Failed to read directory: {}", e)))?;

        for entry in entries {
            let entry = entry
                .map_err(|e| GhostWireError::io(format!("Failed to read directory entry: {}", e)))?;

            let path = entry.path();

            // Only process .hujson and .json files
            if let Some(extension) = path.extension() {
                if extension == "hujson" || extension == "json" {
                    match self.parse_file(&path) {
                        Ok(policy_set) => {
                            debug!("Loaded policy file: {}", path.display());
                            policy_sets.push(policy_set);
                        }
                        Err(e) => {
                            if self.strict_mode {
                                return Err(e);
                            } else {
                                warn!("Failed to parse policy file {}: {}", path.display(), e);
                            }
                        }
                    }
                }
            }
        }

        if policy_sets.is_empty() {
            warn!("No valid policy files found in directory: {}", dir_path.display());
        }

        Ok(policy_sets)
    }

    /// Strip HuJSON features to make it valid JSON
    fn strip_hujson(&self, content: &str) -> Result<String> {
        let mut result = String::new();
        let mut chars = content.chars().peekable();
        let mut in_string = false;
        let mut escaped = false;

        while let Some(ch) = chars.next() {
            match ch {
                '"' if !escaped => {
                    in_string = !in_string;
                    result.push(ch);
                }
                '\\' if in_string => {
                    escaped = !escaped;
                    result.push(ch);
                }
                '/' if !in_string && chars.peek() == Some(&'/') => {
                    // Single-line comment - skip until newline
                    chars.next(); // consume second '/'
                    while let Some(ch) = chars.next() {
                        if ch == '\n' {
                            result.push(ch);
                            break;
                        }
                    }
                }
                '/' if !in_string && chars.peek() == Some(&'*') => {
                    // Multi-line comment - skip until */
                    chars.next(); // consume '*'
                    let mut found_end = false;
                    while let Some(ch) = chars.next() {
                        if ch == '*' && chars.peek() == Some(&'/') {
                            chars.next(); // consume '/'
                            found_end = true;
                            break;
                        }
                    }
                    if !found_end && self.strict_mode {
                        return Err(GhostWireError::validation("Unterminated comment"));
                    }
                }
                ',' if !in_string => {
                    // Check for trailing comma
                    let mut temp_chars = chars.clone();
                    let mut found_non_whitespace = false;
                    let mut found_closing = false;

                    while let Some(next_ch) = temp_chars.next() {
                        if next_ch.is_whitespace() {
                            continue;
                        }
                        if next_ch == '}' || next_ch == ']' {
                            found_closing = true;
                        } else {
                            found_non_whitespace = true;
                        }
                        break;
                    }

                    // Only include comma if it's not trailing
                    if found_non_whitespace || !found_closing {
                        result.push(ch);
                    }
                }
                _ => {
                    result.push(ch);
                    if ch != '\\' {
                        escaped = false;
                    }
                }
            }
        }

        Ok(result)
    }

    /// Validate policy schema
    fn validate_policy_schema(&self, value: &Value) -> Result<()> {
        // Check required top-level fields
        let obj = value.as_object()
            .ok_or_else(|| GhostWireError::validation("Policy must be a JSON object"))?;

        // Validate metadata
        if let Some(metadata) = obj.get("metadata") {
            self.validate_metadata_schema(metadata)?;
        } else {
            return Err(GhostWireError::validation("Policy metadata is required"));
        }

        // Validate rules
        if let Some(rules) = obj.get("rules") {
            self.validate_rules_schema(rules)?;
        } else {
            return Err(GhostWireError::validation("Policy rules are required"));
        }

        Ok(())
    }

    /// Validate metadata schema
    fn validate_metadata_schema(&self, metadata: &Value) -> Result<()> {
        let obj = metadata.as_object()
            .ok_or_else(|| GhostWireError::validation("Metadata must be an object"))?;

        // Check required fields
        let required_fields = ["name", "version", "description"];
        for field in &required_fields {
            if !obj.contains_key(*field) {
                return Err(GhostWireError::validation(format!("Metadata missing required field: {}", field)));
            }
        }

        Ok(())
    }

    /// Validate rules schema
    fn validate_rules_schema(&self, rules: &Value) -> Result<()> {
        let array = rules.as_array()
            .ok_or_else(|| GhostWireError::validation("Rules must be an array"))?;

        for (index, rule) in array.iter().enumerate() {
            let obj = rule.as_object()
                .ok_or_else(|| GhostWireError::validation(format!("Rule {} must be an object", index)))?;

            // Check required rule fields
            let required_fields = ["id", "description", "effect"];
            for field in &required_fields {
                if !obj.contains_key(*field) {
                    return Err(GhostWireError::validation(format!(
                        "Rule {} missing required field: {}", index, field
                    )));
                }
            }

            // Validate effect value
            if let Some(effect) = obj.get("effect") {
                if let Some(effect_str) = effect.as_str() {
                    if effect_str != "allow" && effect_str != "deny" {
                        return Err(GhostWireError::validation(format!(
                            "Rule {} has invalid effect: {} (must be 'allow' or 'deny')", index, effect_str
                        )));
                    }
                }
            }
        }

        Ok(())
    }

    /// Validate parsed policy set
    fn validate_policy_set(&self, policy_set: &PolicySet) -> Result<()> {
        // Check for duplicate rule IDs
        let mut rule_ids = std::collections::HashSet::new();
        for rule in &policy_set.rules {
            if !rule_ids.insert(&rule.id) {
                return Err(GhostWireError::validation(format!(
                    "Duplicate rule ID: {}", rule.id
                )));
            }
        }

        // Validate individual rules
        for rule in &policy_set.rules {
            self.validate_rule(rule)?;
        }

        Ok(())
    }

    /// Validate individual rule
    fn validate_rule(&self, rule: &PolicyRule) -> Result<()> {
        // Check rule ID format
        if rule.id.is_empty() {
            return Err(GhostWireError::validation("Rule ID cannot be empty"));
        }

        // Check priority range
        if rule.priority < -1000 || rule.priority > 1000 {
            return Err(GhostWireError::validation(format!(
                "Rule {} priority out of range: {} (must be between -1000 and 1000)",
                rule.id, rule.priority
            )));
        }

        // Validate matchers if present
        if let Some(source) = &rule.source {
            self.validate_principal_matcher(source)?;
        }

        if let Some(target) = &rule.target {
            self.validate_resource_matcher(target)?;
        }

        if let Some(action) = &rule.action {
            self.validate_action_matcher(action)?;
        }

        // Validate conditions
        for condition in &rule.conditions {
            self.validate_condition(condition)?;
        }

        Ok(())
    }

    /// Validate principal matcher
    fn validate_principal_matcher(&self, matcher: &PrincipalMatcher) -> Result<()> {
        // Validate principal type
        if let Some(principal_type) = &matcher.principal_type {
            let valid_types = ["user", "node", "service"];
            if !valid_types.contains(&principal_type.as_str()) {
                return Err(GhostWireError::validation(format!(
                    "Invalid principal type: {} (must be one of: {})",
                    principal_type,
                    valid_types.join(", ")
                )));
            }
        }

        // Validate group matcher
        if let Some(groups) = &matcher.groups {
            self.validate_group_matcher(groups)?;
        }

        Ok(())
    }

    /// Validate resource matcher
    fn validate_resource_matcher(&self, matcher: &ResourceMatcher) -> Result<()> {
        // Validate resource type
        if let Some(resource_type) = &matcher.resource_type {
            let valid_types = ["node", "network", "route", "user", "admin", "api"];
            if !valid_types.contains(&resource_type.as_str()) {
                return Err(GhostWireError::validation(format!(
                    "Invalid resource type: {} (must be one of: {})",
                    resource_type,
                    valid_types.join(", ")
                )));
            }
        }

        // Validate tag matcher
        if let Some(tags) = &matcher.tags {
            self.validate_tag_matcher(tags)?;
        }

        Ok(())
    }

    /// Validate action matcher
    fn validate_action_matcher(&self, matcher: &ActionMatcher) -> Result<()> {
        // Validate patterns
        if let Some(patterns) = &matcher.patterns {
            for pattern in patterns {
                if pattern.is_empty() {
                    return Err(GhostWireError::validation("Action pattern cannot be empty"));
                }
            }
        }

        Ok(())
    }

    /// Validate group matcher
    fn validate_group_matcher(&self, matcher: &GroupMatcher) -> Result<()> {
        match matcher {
            GroupMatcher::All { groups } |
            GroupMatcher::Any { groups } |
            GroupMatcher::None { groups } => {
                if groups.is_empty() {
                    return Err(GhostWireError::validation("Group matcher cannot have empty groups list"));
                }
            }
        }
        Ok(())
    }

    /// Validate tag matcher
    fn validate_tag_matcher(&self, matcher: &TagMatcher) -> Result<()> {
        match matcher {
            TagMatcher::All { tags } |
            TagMatcher::Any { tags } |
            TagMatcher::None { tags } => {
                if tags.is_empty() {
                    return Err(GhostWireError::validation("Tag matcher cannot have empty tags list"));
                }
            }
        }
        Ok(())
    }

    /// Validate condition
    fn validate_condition(&self, condition: &Condition) -> Result<()> {
        if condition.condition_type.is_empty() {
            return Err(GhostWireError::validation("Condition type cannot be empty"));
        }

        // Validate known condition types
        let known_types = [
            "time_range", "ip_range", "location", "device_compliance",
            "custom_attribute", "rate_limit", "quota"
        ];

        if !known_types.contains(&condition.condition_type.as_str()) {
            warn!("Unknown condition type: {}", condition.condition_type);
        }

        Ok(())
    }

    /// Create a sample policy for testing
    pub fn create_sample_policy() -> PolicySet {
        let metadata = PolicyMetadata {
            name: "Sample Policy".to_string(),
            version: "1.0.0".to_string(),
            description: "Sample policy for testing".to_string(),
            author: Some("GhostWire".to_string()),
            created_at: std::time::SystemTime::now(),
            modified_at: std::time::SystemTime::now(),
            tags: vec!["sample".to_string(), "test".to_string()],
        };

        let rules = vec![
            PolicyRule {
                id: "allow-admin-all".to_string(),
                description: "Allow admin users full access".to_string(),
                priority: 100,
                enabled: true,
                source: Some(PrincipalMatcher {
                    principal_type: Some("user".to_string()),
                    ids: None,
                    names: None,
                    groups: Some(GroupMatcher::Any {
                        groups: vec!["admin".to_string()],
                    }),
                    attributes: None,
                    owners: None,
                }),
                target: None,
                action: None,
                context: None,
                effect: PolicyAction::Allow,
                conditions: vec![],
                metadata: HashMap::new(),
            },
            PolicyRule {
                id: "deny-production-access".to_string(),
                description: "Deny access to production nodes for non-admin users".to_string(),
                priority: 50,
                enabled: true,
                source: Some(PrincipalMatcher {
                    principal_type: Some("user".to_string()),
                    ids: None,
                    names: None,
                    groups: Some(GroupMatcher::None {
                        groups: vec!["admin".to_string()],
                    }),
                    attributes: None,
                    owners: None,
                }),
                target: Some(ResourceMatcher {
                    resource_type: Some("node".to_string()),
                    ids: None,
                    names: None,
                    tags: Some(TagMatcher::Any {
                        tags: vec!["production".to_string()],
                    }),
                    owners: None,
                }),
                action: Some(ActionMatcher {
                    exact: Some(vec!["connect".to_string()]),
                    patterns: None,
                    categories: None,
                }),
                context: None,
                effect: PolicyAction::Deny,
                conditions: vec![],
                metadata: HashMap::new(),
            },
        ];

        PolicySet { metadata, rules }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::SystemTime;

    #[test]
    fn test_strip_hujson_comments() {
        let parser = HuJsonParser::new();

        let hujson = r#"{
            // This is a comment
            "name": "test", // End of line comment
            /* Multi-line
               comment */
            "value": 42
        }"#;

        let result = parser.strip_hujson(hujson).unwrap();
        assert!(!result.contains("//"));
        assert!(!result.contains("/*"));
        assert!(result.contains("\"name\": \"test\""));
    }

    #[test]
    fn test_strip_hujson_trailing_commas() {
        let parser = HuJsonParser::new();

        let hujson = r#"{
            "items": [
                "first",
                "second",
            ],
            "last": "value",
        }"#;

        let result = parser.strip_hujson(hujson).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert!(parsed.is_object());
    }

    #[test]
    fn test_parse_sample_policy() {
        let parser = HuJsonParser::new();
        let policy_set = parser.create_sample_policy();

        assert_eq!(policy_set.metadata.name, "Sample Policy");
        assert_eq!(policy_set.rules.len(), 2);
        assert_eq!(policy_set.rules[0].id, "allow-admin-all");
        assert_eq!(policy_set.rules[1].id, "deny-production-access");
    }

    #[test]
    fn test_validate_policy_schema() {
        let parser = HuJsonParser::new();

        // Valid policy
        let valid_policy = serde_json::json!({
            "metadata": {
                "name": "Test Policy",
                "version": "1.0.0",
                "description": "Test description",
                "created_at": "2023-01-01T00:00:00Z",
                "modified_at": "2023-01-01T00:00:00Z",
                "tags": []
            },
            "rules": []
        });

        assert!(parser.validate_policy_schema(&valid_policy).is_ok());

        // Invalid policy (missing metadata)
        let invalid_policy = serde_json::json!({
            "rules": []
        });

        assert!(parser.validate_policy_schema(&invalid_policy).is_err());
    }

    #[test]
    fn test_validate_rule() {
        let parser = HuJsonParser::new();

        let valid_rule = PolicyRule {
            id: "test-rule".to_string(),
            description: "Test rule".to_string(),
            priority: 10,
            enabled: true,
            source: None,
            target: None,
            action: None,
            context: None,
            effect: PolicyAction::Allow,
            conditions: vec![],
            metadata: HashMap::new(),
        };

        assert!(parser.validate_rule(&valid_rule).is_ok());

        // Invalid rule (empty ID)
        let mut invalid_rule = valid_rule.clone();
        invalid_rule.id = String::new();
        assert!(parser.validate_rule(&invalid_rule).is_err());

        // Invalid rule (priority out of range)
        let mut invalid_rule = valid_rule.clone();
        invalid_rule.priority = 2000;
        assert!(parser.validate_rule(&invalid_rule).is_err());
    }
}