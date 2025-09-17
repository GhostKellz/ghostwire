/// Policy evaluator for ACL decisions
///
/// Evaluates policy rules against requests to determine access decisions.
/// Implements a flexible rule matching system with support for complex conditions.

use crate::policy::types::*;
use ghostwire_common::{
    types::*,
    error::{Result, GhostWireError},
};
use std::collections::HashMap;
use std::time::{SystemTime, Duration};
use tracing::{debug, trace, warn};
use regex::Regex;
use glob::Pattern;

/// Policy evaluator
#[derive(Debug, Clone)]
pub struct PolicyEvaluator {
    /// Default action when no rules match
    default_action: PolicyAction,
    /// Enable rule tracing for debugging
    enable_tracing: bool,
    /// Maximum evaluation time
    max_evaluation_time: Duration,
    /// Compiled regex patterns cache
    regex_cache: HashMap<String, Regex>,
    /// Compiled glob patterns cache
    glob_cache: HashMap<String, Pattern>,
}

impl Default for PolicyEvaluator {
    fn default() -> Self {
        Self {
            default_action: PolicyAction::Deny,
            enable_tracing: true,
            max_evaluation_time: Duration::from_millis(100),
            regex_cache: HashMap::new(),
            glob_cache: HashMap::new(),
        }
    }
}

impl PolicyEvaluator {
    /// Create a new policy evaluator
    pub fn new() -> Self {
        Self::default()
    }

    /// Set default action
    pub fn with_default_action(mut self, action: PolicyAction) -> Self {
        self.default_action = action;
        self
    }

    /// Enable rule tracing
    pub fn with_tracing(mut self, enable: bool) -> Self {
        self.enable_tracing = enable;
        self
    }

    /// Set maximum evaluation time
    pub fn with_max_evaluation_time(mut self, duration: Duration) -> Self {
        self.max_evaluation_time = duration;
        self
    }

    /// Evaluate a policy request against rules
    pub fn evaluate(
        &mut self,
        request: &PolicyRequest,
        policy_sets: &[PolicySet],
    ) -> Result<PolicyResponse> {
        let start_time = SystemTime::now();

        debug!(
            "Evaluating policy request: {} -> {} ({})",
            request.source.name(),
            request.target.name(),
            request.action
        );

        // Collect all rules from all policy sets
        let mut all_rules = Vec::new();
        for policy_set in policy_sets {
            for rule in &policy_set.rules {
                if rule.enabled {
                    all_rules.push(rule);
                }
            }
        }

        // Sort rules by priority (highest first)
        all_rules.sort_by(|a, b| b.priority.cmp(&a.priority));

        // Evaluate rules in priority order
        for rule in all_rules {
            if self.enable_tracing {
                trace!("Evaluating rule: {} (priority: {})", rule.id, rule.priority);
            }

            // Check timeout
            if start_time.elapsed().unwrap_or_default() > self.max_evaluation_time {
                warn!("Policy evaluation timed out");
                return Ok(PolicyResponse {
                    decision: PolicyDecision::Deny,
                    matched_rule: None,
                    reason: "Evaluation timeout".to_string(),
                    metadata: HashMap::new(),
                    evaluation_time_ms: start_time.elapsed().unwrap_or_default().as_millis() as u64,
                });
            }

            if let Some(decision) = self.evaluate_rule(request, rule)? {
                let evaluation_time = start_time.elapsed().unwrap_or_default().as_millis() as u64;

                debug!(
                    "Rule {} matched with decision: {:?} ({}ms)",
                    rule.id, decision, evaluation_time
                );

                return Ok(PolicyResponse {
                    decision,
                    matched_rule: Some(rule.id.clone()),
                    reason: rule.description.clone(),
                    metadata: rule.metadata.clone(),
                    evaluation_time_ms: evaluation_time,
                });
            }
        }

        // No rules matched, use default action
        let evaluation_time = start_time.elapsed().unwrap_or_default().as_millis() as u64;
        let decision = match self.default_action {
            PolicyAction::Allow => PolicyDecision::Allow,
            PolicyAction::Deny => PolicyDecision::Deny,
        };

        debug!(
            "No rules matched, using default action: {:?} ({}ms)",
            decision, evaluation_time
        );

        Ok(PolicyResponse {
            decision,
            matched_rule: None,
            reason: "Default policy action".to_string(),
            metadata: HashMap::new(),
            evaluation_time_ms: evaluation_time,
        })
    }

    /// Evaluate a single rule against a request
    fn evaluate_rule(
        &mut self,
        request: &PolicyRequest,
        rule: &PolicyRule,
    ) -> Result<Option<PolicyDecision>> {
        // Check source principal matcher
        if let Some(source_matcher) = &rule.source {
            if !self.match_principal(&request.source, source_matcher)? {
                return Ok(None);
            }
        }

        // Check target resource matcher
        if let Some(target_matcher) = &rule.target {
            if !self.match_resource(&request.target, target_matcher)? {
                return Ok(None);
            }
        }

        // Check action matcher
        if let Some(action_matcher) = &rule.action {
            if !self.match_action(&request.action, action_matcher)? {
                return Ok(None);
            }
        }

        // Check context matcher
        if let Some(context_matcher) = &rule.context {
            if !self.match_context(&request.context, context_matcher)? {
                return Ok(None);
            }
        }

        // Check additional conditions
        for condition in &rule.conditions {
            if !self.evaluate_condition(request, condition)? {
                return Ok(None);
            }
        }

        // All matchers passed, return rule effect
        let decision = match rule.effect {
            PolicyAction::Allow => PolicyDecision::Allow,
            PolicyAction::Deny => PolicyDecision::Deny,
        };

        Ok(Some(decision))
    }

    /// Match principal against matcher
    fn match_principal(
        &mut self,
        principal: &PolicyPrincipal,
        matcher: &PrincipalMatcher,
    ) -> Result<bool> {
        // Check principal type
        if let Some(expected_type) = &matcher.principal_type {
            let actual_type = match principal {
                PolicyPrincipal::User { .. } => "user",
                PolicyPrincipal::Node { .. } => "node",
                PolicyPrincipal::Service { .. } => "service",
            };

            if actual_type != expected_type {
                return Ok(false);
            }
        }

        // Check IDs
        if let Some(ids) = &matcher.ids {
            let principal_id = principal.id();
            if !self.match_string_list(&principal_id, ids)? {
                return Ok(false);
            }
        }

        // Check names
        if let Some(names) = &matcher.names {
            let principal_name = principal.name();
            if !self.match_string_list(principal_name, names)? {
                return Ok(false);
            }
        }

        // Check groups
        if let Some(group_matcher) = &matcher.groups {
            if !self.match_groups(&principal.groups(), group_matcher)? {
                return Ok(false);
            }
        }

        // Check attributes
        if let Some(attributes) = &matcher.attributes {
            for (key, attr_matcher) in attributes {
                let value = principal.get_attribute(key);
                if !self.match_attribute(value, attr_matcher)? {
                    return Ok(false);
                }
            }
        }

        // Check owners (for nodes)
        if let Some(owners) = &matcher.owners {
            match principal {
                PolicyPrincipal::Node { owner, .. } => {
                    let owner_str = owner.to_string();
                    if !self.match_string_list(&owner_str, owners)? {
                        return Ok(false);
                    }
                }
                _ => {
                    // Non-node principals don't have owners
                    return Ok(false);
                }
            }
        }

        Ok(true)
    }

    /// Match resource against matcher
    fn match_resource(
        &mut self,
        resource: &PolicyResource,
        matcher: &ResourceMatcher,
    ) -> Result<bool> {
        // Check resource type
        if let Some(expected_type) = &matcher.resource_type {
            let actual_type = match resource {
                PolicyResource::Node { .. } => "node",
                PolicyResource::Network { .. } => "network",
                PolicyResource::Route { .. } => "route",
                PolicyResource::User { .. } => "user",
                PolicyResource::Admin { .. } => "admin",
                PolicyResource::Api { .. } => "api",
            };

            if actual_type != expected_type {
                return Ok(false);
            }
        }

        // Check IDs
        if let Some(ids) = &matcher.ids {
            let resource_id = resource.id();
            if !self.match_string_list(&resource_id, ids)? {
                return Ok(false);
            }
        }

        // Check names
        if let Some(names) = &matcher.names {
            let resource_name = resource.name();
            if !self.match_string_list(&resource_name, names)? {
                return Ok(false);
            }
        }

        // Check tags
        if let Some(tag_matcher) = &matcher.tags {
            if !self.match_tags(&resource.tags(), tag_matcher)? {
                return Ok(false);
            }
        }

        // Check owners
        if let Some(owners) = &matcher.owners {
            if let Some(owner) = resource.owner() {
                let owner_str = owner.to_string();
                if !self.match_string_list(&owner_str, owners)? {
                    return Ok(false);
                }
            } else {
                // Resource has no owner
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Match action against matcher
    fn match_action(&mut self, action: &str, matcher: &ActionMatcher) -> Result<bool> {
        // Check exact matches
        if let Some(exact) = &matcher.exact {
            if exact.contains(&action.to_string()) {
                return Ok(true);
            }
        }

        // Check pattern matches
        if let Some(patterns) = &matcher.patterns {
            for pattern in patterns {
                if self.match_glob_pattern(action, pattern)? {
                    return Ok(true);
                }
            }
        }

        // Check categories (simplified implementation)
        if let Some(categories) = &matcher.categories {
            let action_category = self.get_action_category(action);
            if categories.contains(&action_category) {
                return Ok(true);
            }
        }

        // If we have matchers but none matched, return false
        if matcher.exact.is_some() || matcher.patterns.is_some() || matcher.categories.is_some() {
            Ok(false)
        } else {
            // No matchers means match all
            Ok(true)
        }
    }

    /// Match context against matcher
    fn match_context(
        &mut self,
        context: &PolicyContext,
        matcher: &ContextMatcher,
    ) -> Result<bool> {
        // Check source IPs
        if let Some(source_ips) = &matcher.source_ips {
            if let Some(source_ip) = &context.source_ip {
                if !self.match_ip_ranges(source_ip, source_ips)? {
                    return Ok(false);
                }
            } else {
                return Ok(false);
            }
        }

        // Check time ranges
        if let Some(time_ranges) = &matcher.time_ranges {
            if !self.match_time_ranges(time_ranges)? {
                return Ok(false);
            }
        }

        // Check locations
        if let Some(locations) = &matcher.locations {
            if let Some(location) = &context.location {
                if !self.match_string_list(location, locations)? {
                    return Ok(false);
                }
            } else {
                return Ok(false);
            }
        }

        // Check custom attributes
        if let Some(attributes) = &matcher.attributes {
            for (key, attr_matcher) in attributes {
                let value = context.get_attribute(key);
                if !self.match_attribute(value, attr_matcher)? {
                    return Ok(false);
                }
            }
        }

        Ok(true)
    }

    /// Evaluate a custom condition
    fn evaluate_condition(
        &mut self,
        request: &PolicyRequest,
        condition: &Condition,
    ) -> Result<bool> {
        let result = match condition.condition_type.as_str() {
            "time_range" => self.evaluate_time_range_condition(request, condition)?,
            "ip_range" => self.evaluate_ip_range_condition(request, condition)?,
            "location" => self.evaluate_location_condition(request, condition)?,
            "device_compliance" => self.evaluate_device_compliance_condition(request, condition)?,
            "custom_attribute" => self.evaluate_custom_attribute_condition(request, condition)?,
            "rate_limit" => self.evaluate_rate_limit_condition(request, condition)?,
            "quota" => self.evaluate_quota_condition(request, condition)?,
            _ => {
                warn!("Unknown condition type: {}", condition.condition_type);
                true // Unknown conditions default to true
            }
        };

        // Apply negation if specified
        Ok(if condition.negate { !result } else { result })
    }

    /// Match string against list of patterns
    fn match_string_list(&mut self, value: &str, patterns: &[String]) -> Result<bool> {
        for pattern in patterns {
            if self.match_glob_pattern(value, pattern)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Match using glob pattern
    fn match_glob_pattern(&mut self, value: &str, pattern: &str) -> Result<bool> {
        // Check cache first
        if let Some(compiled_pattern) = self.glob_cache.get(pattern) {
            return Ok(compiled_pattern.matches(value));
        }

        // Compile and cache pattern
        let compiled_pattern = Pattern::new(pattern)
            .map_err(|e| GhostWireError::validation(format!("Invalid glob pattern '{}': {}", pattern, e)))?;

        let matches = compiled_pattern.matches(value);
        self.glob_cache.insert(pattern.to_string(), compiled_pattern);

        Ok(matches)
    }

    /// Match groups using group matcher
    fn match_groups(&mut self, groups: &[&str], matcher: &GroupMatcher) -> Result<bool> {
        match matcher {
            GroupMatcher::All { groups: required } => {
                for required_group in required {
                    if !groups.contains(&required_group.as_str()) {
                        return Ok(false);
                    }
                }
                Ok(true)
            }
            GroupMatcher::Any { groups: required } => {
                for required_group in required {
                    if groups.contains(&required_group.as_str()) {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            GroupMatcher::None { groups: forbidden } => {
                for forbidden_group in forbidden {
                    if groups.contains(&forbidden_group.as_str()) {
                        return Ok(false);
                    }
                }
                Ok(true)
            }
        }
    }

    /// Match tags using tag matcher
    fn match_tags(&mut self, tags: &[&str], matcher: &TagMatcher) -> Result<bool> {
        match matcher {
            TagMatcher::All { tags: required } => {
                for required_tag in required {
                    if !tags.contains(&required_tag.as_str()) {
                        return Ok(false);
                    }
                }
                Ok(true)
            }
            TagMatcher::Any { tags: required } => {
                for required_tag in required {
                    if tags.contains(&required_tag.as_str()) {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            TagMatcher::None { tags: forbidden } => {
                for forbidden_tag in forbidden {
                    if tags.contains(&forbidden_tag.as_str()) {
                        return Ok(false);
                    }
                }
                Ok(true)
            }
        }
    }

    /// Match attribute using attribute matcher
    fn match_attribute(&mut self, value: Option<&str>, matcher: &AttributeMatcher) -> Result<bool> {
        match matcher {
            AttributeMatcher::Exists => Ok(value.is_some()),
            AttributeMatcher::NotExists => Ok(value.is_none()),
            AttributeMatcher::Equals { value: expected } => {
                Ok(value.map_or(false, |v| v == expected))
            }
            AttributeMatcher::Matches { pattern } => {
                if let Some(v) = value {
                    self.match_glob_pattern(v, pattern)
                } else {
                    Ok(false)
                }
            }
            AttributeMatcher::In { values } => {
                if let Some(v) = value {
                    Ok(values.contains(&v.to_string()))
                } else {
                    Ok(false)
                }
            }
        }
    }

    /// Match IP against CIDR ranges
    fn match_ip_ranges(&self, ip: &str, ranges: &[String]) -> Result<bool> {
        use std::net::IpAddr;

        let ip_addr: IpAddr = ip.parse()
            .map_err(|_| GhostWireError::validation(format!("Invalid IP address: {}", ip)))?;

        for range in ranges {
            if range.contains('/') {
                // CIDR notation
                use ipnet::IpNet;
                let network: IpNet = range.parse()
                    .map_err(|_| GhostWireError::validation(format!("Invalid CIDR range: {}", range)))?;
                if network.contains(&ip_addr) {
                    return Ok(true);
                }
            } else {
                // Single IP
                let range_ip: IpAddr = range.parse()
                    .map_err(|_| GhostWireError::validation(format!("Invalid IP address: {}", range)))?;
                if ip_addr == range_ip {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    /// Match current time against time ranges
    fn match_time_ranges(&self, time_ranges: &[TimeRange]) -> Result<bool> {
        use chrono::{Local, Timelike, Weekday};

        let now = Local::now();
        let current_time = format!("{:02}:{:02}", now.hour(), now.minute());
        let current_day = match now.weekday() {
            Weekday::Mon => "Mon",
            Weekday::Tue => "Tue",
            Weekday::Wed => "Wed",
            Weekday::Thu => "Thu",
            Weekday::Fri => "Fri",
            Weekday::Sat => "Sat",
            Weekday::Sun => "Sun",
        };

        for time_range in time_ranges {
            // Check day of week
            if let Some(days) = &time_range.days {
                if !days.contains(&current_day.to_string()) {
                    continue;
                }
            }

            // Check time range
            if current_time >= time_range.start && current_time <= time_range.end {
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Get action category for grouping
    fn get_action_category(&self, action: &str) -> String {
        match action {
            "connect" | "ping" | "ssh" => "network".to_string(),
            "read" | "list" | "get" => "read".to_string(),
            "write" | "update" | "create" => "write".to_string(),
            "delete" | "remove" => "delete".to_string(),
            "admin" | "manage" | "configure" => "admin".to_string(),
            _ => "other".to_string(),
        }
    }

    // Condition evaluation methods
    fn evaluate_time_range_condition(&self, _request: &PolicyRequest, condition: &Condition) -> Result<bool> {
        // Implementation would check current time against condition parameters
        Ok(true) // Simplified for now
    }

    fn evaluate_ip_range_condition(&self, request: &PolicyRequest, condition: &Condition) -> Result<bool> {
        if let Some(source_ip) = &request.context.source_ip {
            if let Some(allowed_ranges) = condition.parameters.get("allowed_ranges") {
                let ranges: Vec<String> = allowed_ranges.split(',').map(|s| s.trim().to_string()).collect();
                return self.match_ip_ranges(source_ip, &ranges);
            }
        }
        Ok(false)
    }

    fn evaluate_location_condition(&self, request: &PolicyRequest, condition: &Condition) -> Result<bool> {
        if let Some(location) = &request.context.location {
            if let Some(allowed_locations) = condition.parameters.get("allowed_locations") {
                let locations: Vec<String> = allowed_locations.split(',').map(|s| s.trim().to_string()).collect();
                return Ok(locations.contains(location));
            }
        }
        Ok(false)
    }

    fn evaluate_device_compliance_condition(&self, request: &PolicyRequest, _condition: &Condition) -> Result<bool> {
        // Check device compliance status from context
        if let Some(device) = &request.context.device {
            if let Some(compliance) = &device.compliance_status {
                return Ok(compliance == "compliant");
            }
        }
        Ok(false)
    }

    fn evaluate_custom_attribute_condition(&self, request: &PolicyRequest, condition: &Condition) -> Result<bool> {
        if let Some(attribute_name) = condition.parameters.get("attribute") {
            if let Some(expected_value) = condition.parameters.get("value") {
                if let Some(actual_value) = request.context.get_attribute(attribute_name) {
                    return Ok(actual_value == expected_value);
                }
            }
        }
        Ok(false)
    }

    fn evaluate_rate_limit_condition(&self, _request: &PolicyRequest, _condition: &Condition) -> Result<bool> {
        // Rate limiting would require external state management
        Ok(true) // Simplified for now
    }

    fn evaluate_quota_condition(&self, _request: &PolicyRequest, _condition: &Condition) -> Result<bool> {
        // Quota checking would require external state management
        Ok(true) // Simplified for now
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn create_test_request() -> PolicyRequest {
        PolicyRequest {
            source: PolicyPrincipal::User {
                id: Uuid::new_v4(),
                name: "testuser".to_string(),
                email: Some("test@example.com".to_string()),
                groups: vec!["users".to_string()],
                roles: vec!["developer".to_string()],
                attributes: HashMap::new(),
            },
            target: PolicyResource::Node {
                id: Uuid::new_v4(),
                name: "test-node".to_string(),
                tags: vec!["development".to_string()],
                owner: Uuid::new_v4(),
                subnet: None,
                routes: vec![],
            },
            action: "connect".to_string(),
            context: PolicyContext::new(),
            timestamp: SystemTime::now(),
        }
    }

    fn create_test_rule(effect: PolicyAction) -> PolicyRule {
        PolicyRule {
            id: "test-rule".to_string(),
            description: "Test rule".to_string(),
            priority: 0,
            enabled: true,
            source: None,
            target: None,
            action: None,
            context: None,
            effect,
            conditions: vec![],
            metadata: HashMap::new(),
        }
    }

    #[test]
    fn test_evaluate_allow_rule() {
        let mut evaluator = PolicyEvaluator::new();
        let request = create_test_request();
        let rule = create_test_rule(PolicyAction::Allow);

        let result = evaluator.evaluate_rule(&request, &rule).unwrap();
        assert_eq!(result, Some(PolicyDecision::Allow));
    }

    #[test]
    fn test_evaluate_deny_rule() {
        let mut evaluator = PolicyEvaluator::new();
        let request = create_test_request();
        let rule = create_test_rule(PolicyAction::Deny);

        let result = evaluator.evaluate_rule(&request, &rule).unwrap();
        assert_eq!(result, Some(PolicyDecision::Deny));
    }

    #[test]
    fn test_match_principal_groups() {
        let mut evaluator = PolicyEvaluator::new();

        let principal = PolicyPrincipal::User {
            id: Uuid::new_v4(),
            name: "testuser".to_string(),
            email: None,
            groups: vec!["admin".to_string(), "users".to_string()],
            roles: vec![],
            attributes: HashMap::new(),
        };

        // Test ANY matcher
        let matcher = PrincipalMatcher {
            principal_type: None,
            ids: None,
            names: None,
            groups: Some(GroupMatcher::Any {
                groups: vec!["admin".to_string()],
            }),
            attributes: None,
            owners: None,
        };

        assert!(evaluator.match_principal(&principal, &matcher).unwrap());

        // Test ALL matcher
        let matcher = PrincipalMatcher {
            principal_type: None,
            ids: None,
            names: None,
            groups: Some(GroupMatcher::All {
                groups: vec!["admin".to_string(), "users".to_string()],
            }),
            attributes: None,
            owners: None,
        };

        assert!(evaluator.match_principal(&principal, &matcher).unwrap());

        // Test NONE matcher
        let matcher = PrincipalMatcher {
            principal_type: None,
            ids: None,
            names: None,
            groups: Some(GroupMatcher::None {
                groups: vec!["forbidden".to_string()],
            }),
            attributes: None,
            owners: None,
        };

        assert!(evaluator.match_principal(&principal, &matcher).unwrap());
    }

    #[test]
    fn test_match_glob_pattern() {
        let mut evaluator = PolicyEvaluator::new();

        assert!(evaluator.match_glob_pattern("test.example.com", "*.example.com").unwrap());
        assert!(evaluator.match_glob_pattern("connect", "conn*").unwrap());
        assert!(!evaluator.match_glob_pattern("disconnect", "conn*").unwrap());
        assert!(evaluator.match_glob_pattern("admin", "*").unwrap());
    }

    #[test]
    fn test_match_ip_ranges() {
        let evaluator = PolicyEvaluator::new();

        // Test CIDR matching
        let ranges = vec!["192.168.1.0/24".to_string()];
        assert!(evaluator.match_ip_ranges("192.168.1.100", &ranges).unwrap());
        assert!(!evaluator.match_ip_ranges("10.0.0.1", &ranges).unwrap());

        // Test exact IP matching
        let ranges = vec!["192.168.1.100".to_string()];
        assert!(evaluator.match_ip_ranges("192.168.1.100", &ranges).unwrap());
        assert!(!evaluator.match_ip_ranges("192.168.1.101", &ranges).unwrap());
    }

    #[test]
    fn test_default_action() {
        let mut evaluator = PolicyEvaluator::new().with_default_action(PolicyAction::Allow);
        let request = create_test_request();
        let policy_sets = vec![];

        let response = evaluator.evaluate(&request, &policy_sets).unwrap();
        assert_eq!(response.decision, PolicyDecision::Allow);
        assert!(response.matched_rule.is_none());
        assert_eq!(response.reason, "Default policy action");
    }
}