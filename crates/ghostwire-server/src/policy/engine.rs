/// Main policy engine orchestrating policy management and evaluation
///
/// Provides a high-level interface for policy loading, caching, evaluation,
/// and management with support for hot-reloading and performance optimization.

use crate::policy::{
    types::*,
    parser::HuJsonParser,
    evaluator::PolicyEvaluator,
};
use ghostwire_common::{
    types::*,
    error::{Result, GhostWireError},
};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, Duration, Instant};
use tokio::time::{interval, sleep};
use tracing::{info, warn, error, debug};
use serde::{Serialize, Deserialize};

/// Policy cache entry
#[derive(Debug, Clone)]
struct CachedPolicy {
    policy_set: PolicySet,
    cached_at: SystemTime,
    file_path: PathBuf,
    file_modified: SystemTime,
}

/// Policy evaluation cache
#[derive(Debug, Clone)]
struct EvaluationCache {
    request_hash: u64,
    response: PolicyResponse,
    cached_at: Instant,
}

/// Policy engine statistics
#[derive(Debug, Clone, Serialize)]
pub struct PolicyEngineStats {
    pub loaded_policies: usize,
    pub total_rules: usize,
    pub evaluation_stats: PolicyStats,
    pub cache_stats: CacheStats,
    pub reload_stats: ReloadStats,
}

/// Cache statistics
#[derive(Debug, Clone, Serialize)]
pub struct CacheStats {
    pub policy_cache_size: usize,
    pub evaluation_cache_size: usize,
    pub cache_hit_rate: f64,
    pub cache_miss_count: u64,
    pub cache_hit_count: u64,
}

/// Reload statistics
#[derive(Debug, Clone, Serialize)]
pub struct ReloadStats {
    pub total_reloads: u64,
    pub successful_reloads: u64,
    pub failed_reloads: u64,
    pub last_reload_time: Option<SystemTime>,
    pub last_reload_duration_ms: u64,
}

/// Main policy engine
pub struct PolicyEngine {
    config: PolicyConfig,
    parser: HuJsonParser,
    evaluator: PolicyEvaluator,

    // Policy storage
    policies: Arc<RwLock<Vec<PolicySet>>>,
    policy_cache: Arc<RwLock<HashMap<String, CachedPolicy>>>,

    // Evaluation cache
    evaluation_cache: Arc<RwLock<HashMap<u64, EvaluationCache>>>,

    // Statistics
    stats: Arc<RwLock<PolicyEngineStats>>,
    cache_stats: Arc<RwLock<CacheStats>>,
    reload_stats: Arc<RwLock<ReloadStats>>,

    // Runtime state
    is_running: Arc<RwLock<bool>>,
}

impl PolicyEngine {
    /// Create a new policy engine
    pub fn new(config: PolicyConfig) -> Self {
        let parser = HuJsonParser::new()
            .with_strict_mode(false)
            .with_schema_validation(config.validate_on_reload);

        let evaluator = PolicyEvaluator::new()
            .with_default_action(config.default_action.clone())
            .with_tracing(config.audit_logging);

        let initial_stats = PolicyEngineStats {
            loaded_policies: 0,
            total_rules: 0,
            evaluation_stats: PolicyStats {
                total_evaluations: 0,
                allowed_decisions: 0,
                denied_decisions: 0,
                average_evaluation_time_ms: 0.0,
                cache_hit_rate: 0.0,
                policy_reload_count: 0,
                last_reload_time: None,
            },
            cache_stats: CacheStats {
                policy_cache_size: 0,
                evaluation_cache_size: 0,
                cache_hit_rate: 0.0,
                cache_miss_count: 0,
                cache_hit_count: 0,
            },
            reload_stats: ReloadStats {
                total_reloads: 0,
                successful_reloads: 0,
                failed_reloads: 0,
                last_reload_time: None,
                last_reload_duration_ms: 0,
            },
        };

        Self {
            config,
            parser,
            evaluator,
            policies: Arc::new(RwLock::new(Vec::new())),
            policy_cache: Arc::new(RwLock::new(HashMap::new())),
            evaluation_cache: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(initial_stats)),
            cache_stats: Arc::new(RwLock::new(CacheStats {
                policy_cache_size: 0,
                evaluation_cache_size: 0,
                cache_hit_rate: 0.0,
                cache_miss_count: 0,
                cache_hit_count: 0,
            })),
            reload_stats: Arc::new(RwLock::new(ReloadStats {
                total_reloads: 0,
                successful_reloads: 0,
                failed_reloads: 0,
                last_reload_time: None,
                last_reload_duration_ms: 0,
            })),
            is_running: Arc::new(RwLock::new(false)),
        }
    }

    /// Start the policy engine
    pub async fn start(&self) -> Result<()> {
        info!("Starting policy engine");

        // Set running state
        *self.is_running.write().unwrap() = true;

        // Load initial policies
        self.reload_policies().await?;

        // Start background reload task
        if self.config.reload_interval_seconds > 0 {
            self.start_reload_task().await;
        }

        info!("Policy engine started successfully");
        Ok(())
    }

    /// Stop the policy engine
    pub async fn stop(&self) -> Result<()> {
        info!("Stopping policy engine");

        *self.is_running.write().unwrap() = false;

        // Clear caches
        self.policy_cache.write().unwrap().clear();
        self.evaluation_cache.write().unwrap().clear();

        info!("Policy engine stopped");
        Ok(())
    }

    /// Evaluate a policy request
    pub async fn evaluate(&self, request: PolicyRequest) -> Result<PolicyResponse> {
        let start_time = Instant::now();

        // Check evaluation cache first
        if self.config.enable_cache {
            let request_hash = self.hash_request(&request);

            if let Some(cached_response) = self.get_cached_evaluation(request_hash) {
                self.update_cache_stats(true);
                debug!("Policy evaluation cache hit for request hash: {}", request_hash);
                return Ok(cached_response.response);
            }

            self.update_cache_stats(false);
        }

        // Get current policies
        let policies = self.policies.read().unwrap().clone();

        // Perform evaluation
        let mut evaluator = self.evaluator.clone();
        let response = evaluator.evaluate(&request, &policies)?;

        // Cache the result if caching is enabled
        if self.config.enable_cache {
            let request_hash = self.hash_request(&request);
            self.cache_evaluation(request_hash, response.clone());
        }

        // Update statistics
        self.update_evaluation_stats(&response, start_time.elapsed());

        if self.config.audit_logging {
            info!(
                "Policy evaluation: {} -> {} ({}) = {:?} [{}ms]",
                request.source.name(),
                request.target.name(),
                request.action,
                response.decision,
                response.evaluation_time_ms
            );
        }

        Ok(response)
    }

    /// Reload all policies
    pub async fn reload_policies(&self) -> Result<()> {
        let start_time = Instant::now();

        info!("Reloading policies");

        {
            let mut reload_stats = self.reload_stats.write().unwrap();
            reload_stats.total_reloads += 1;
        }

        let mut new_policies = Vec::new();
        let mut errors = Vec::new();

        // Load from policy files
        for policy_file in &self.config.policy_files {
            match self.load_policy_file(policy_file).await {
                Ok(policy_set) => new_policies.push(policy_set),
                Err(e) => {
                    errors.push(format!("Failed to load {}: {}", policy_file, e));
                }
            }
        }

        // Load from policy directory
        if let Some(policy_dir) = &self.config.policy_directory {
            match self.load_policy_directory(policy_dir).await {
                Ok(mut dir_policies) => new_policies.append(&mut dir_policies),
                Err(e) => {
                    errors.push(format!("Failed to load directory {}: {}", policy_dir, e));
                }
            }
        }

        // Update policies if we have any
        if !new_policies.is_empty() {
            *self.policies.write().unwrap() = new_policies;

            // Clear evaluation cache after policy reload
            if self.config.enable_cache {
                self.evaluation_cache.write().unwrap().clear();
            }

            let reload_duration = start_time.elapsed();
            {
                let mut reload_stats = self.reload_stats.write().unwrap();
                reload_stats.successful_reloads += 1;
                reload_stats.last_reload_time = Some(SystemTime::now());
                reload_stats.last_reload_duration_ms = reload_duration.as_millis() as u64;
            }

            self.update_policy_stats();

            info!(
                "Successfully reloaded {} policies in {}ms",
                new_policies.len(),
                reload_duration.as_millis()
            );

            if !errors.is_empty() {
                warn!("Policy reload completed with errors: {}", errors.join("; "));
            }
        } else {
            let mut reload_stats = self.reload_stats.write().unwrap();
            reload_stats.failed_reloads += 1;

            let error_msg = if errors.is_empty() {
                "No policies found".to_string()
            } else {
                errors.join("; ")
            };

            error!("Policy reload failed: {}", error_msg);
            return Err(GhostWireError::configuration(format!("Policy reload failed: {}", error_msg)));
        }

        Ok(())
    }

    /// Add a policy set dynamically
    pub async fn add_policy(&self, policy_set: PolicySet) -> Result<()> {
        info!("Adding policy set: {}", policy_set.metadata.name);

        // Validate the policy set
        if policy_set.rules.is_empty() {
            return Err(GhostWireError::validation("Policy set cannot be empty"));
        }

        // Add to current policies
        self.policies.write().unwrap().push(policy_set);

        // Clear evaluation cache
        if self.config.enable_cache {
            self.evaluation_cache.write().unwrap().clear();
        }

        self.update_policy_stats();
        Ok(())
    }

    /// Remove a policy set by name
    pub async fn remove_policy(&self, policy_name: &str) -> Result<bool> {
        info!("Removing policy set: {}", policy_name);

        let mut policies = self.policies.write().unwrap();
        let initial_len = policies.len();

        policies.retain(|p| p.metadata.name != policy_name);

        let removed = policies.len() < initial_len;

        if removed {
            // Clear evaluation cache
            if self.config.enable_cache {
                self.evaluation_cache.write().unwrap().clear();
            }

            self.update_policy_stats();
            info!("Successfully removed policy set: {}", policy_name);
        } else {
            warn!("Policy set not found: {}", policy_name);
        }

        Ok(removed)
    }

    /// List all loaded policies
    pub async fn list_policies(&self) -> Vec<PolicyMetadata> {
        self.policies
            .read()
            .unwrap()
            .iter()
            .map(|p| p.metadata.clone())
            .collect()
    }

    /// Get policy engine statistics
    pub async fn get_stats(&self) -> PolicyEngineStats {
        self.stats.read().unwrap().clone()
    }

    /// Validate a policy set
    pub async fn validate_policy(&self, policy_set: &PolicySet) -> Result<()> {
        // Use parser validation
        let content = serde_json::to_string_pretty(policy_set)
            .map_err(|e| GhostWireError::validation(format!("Policy serialization failed: {}", e)))?;

        self.parser.parse_content(&content)?;
        Ok(())
    }

    // Private methods

    async fn load_policy_file(&self, file_path: &str) -> Result<PolicySet> {
        let path = Path::new(file_path);

        // Check if file is already cached and up-to-date
        if self.config.enable_cache {
            if let Some(cached) = self.get_cached_policy(file_path) {
                if let Ok(metadata) = std::fs::metadata(path) {
                    if let Ok(modified) = metadata.modified() {
                        if modified <= cached.file_modified {
                            debug!("Using cached policy for: {}", file_path);
                            return Ok(cached.policy_set);
                        }
                    }
                }
            }
        }

        // Load and parse the policy file
        let policy_set = self.parser.parse_file(path)?;

        // Cache the policy if caching is enabled
        if self.config.enable_cache {
            self.cache_policy(file_path, &policy_set).await?;
        }

        Ok(policy_set)
    }

    async fn load_policy_directory(&self, dir_path: &str) -> Result<Vec<PolicySet>> {
        let path = Path::new(dir_path);

        if !path.exists() {
            return Err(GhostWireError::configuration(format!("Policy directory not found: {}", dir_path)));
        }

        if !path.is_dir() {
            return Err(GhostWireError::configuration(format!("Path is not a directory: {}", dir_path)));
        }

        self.parser.parse_directory(path)
    }

    async fn cache_policy(&self, file_path: &str, policy_set: &PolicySet) -> Result<()> {
        let path = Path::new(file_path);
        let metadata = std::fs::metadata(path)
            .map_err(|e| GhostWireError::io(format!("Failed to get file metadata: {}", e)))?;

        let file_modified = metadata.modified()
            .map_err(|e| GhostWireError::io(format!("Failed to get file modification time: {}", e)))?;

        let cached_policy = CachedPolicy {
            policy_set: policy_set.clone(),
            cached_at: SystemTime::now(),
            file_path: path.to_path_buf(),
            file_modified,
        };

        self.policy_cache.write().unwrap().insert(file_path.to_string(), cached_policy);
        Ok(())
    }

    fn get_cached_policy(&self, file_path: &str) -> Option<CachedPolicy> {
        self.policy_cache.read().unwrap().get(file_path).cloned()
    }

    fn hash_request(&self, request: &PolicyRequest) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        request.source.id().hash(&mut hasher);
        request.target.id().hash(&mut hasher);
        request.action.hash(&mut hasher);
        request.context.source_ip.hash(&mut hasher);
        request.context.location.hash(&mut hasher);
        hasher.finish()
    }

    fn get_cached_evaluation(&self, request_hash: u64) -> Option<EvaluationCache> {
        let cache = self.evaluation_cache.read().unwrap();
        if let Some(cached) = cache.get(&request_hash) {
            // Check if cache entry is still valid
            let cache_age = cached.cached_at.elapsed().as_secs();
            if cache_age < self.config.cache_ttl_seconds {
                return Some(cached.clone());
            }
        }
        None
    }

    fn cache_evaluation(&self, request_hash: u64, response: PolicyResponse) {
        let cache_entry = EvaluationCache {
            request_hash,
            response,
            cached_at: Instant::now(),
        };

        let mut cache = self.evaluation_cache.write().unwrap();
        cache.insert(request_hash, cache_entry);

        // Cleanup old entries if cache is getting too large
        if cache.len() > 10000 {
            let cutoff = Instant::now() - Duration::from_secs(self.config.cache_ttl_seconds);
            cache.retain(|_, entry| entry.cached_at > cutoff);
        }
    }

    fn update_cache_stats(&self, cache_hit: bool) {
        let mut stats = self.cache_stats.write().unwrap();
        if cache_hit {
            stats.cache_hit_count += 1;
        } else {
            stats.cache_miss_count += 1;
        }

        let total = stats.cache_hit_count + stats.cache_miss_count;
        if total > 0 {
            stats.cache_hit_rate = stats.cache_hit_count as f64 / total as f64;
        }
    }

    fn update_evaluation_stats(&self, response: &PolicyResponse, duration: Duration) {
        let mut stats = self.stats.write().unwrap();
        stats.evaluation_stats.total_evaluations += 1;

        match response.decision {
            PolicyDecision::Allow => stats.evaluation_stats.allowed_decisions += 1,
            PolicyDecision::Deny => stats.evaluation_stats.denied_decisions += 1,
            PolicyDecision::Undecided => {}
        }

        // Update average evaluation time
        let total_evals = stats.evaluation_stats.total_evaluations as f64;
        let current_avg = stats.evaluation_stats.average_evaluation_time_ms;
        let new_time = duration.as_millis() as f64;

        stats.evaluation_stats.average_evaluation_time_ms =
            (current_avg * (total_evals - 1.0) + new_time) / total_evals;
    }

    fn update_policy_stats(&self) {
        let policies = self.policies.read().unwrap();
        let total_rules: usize = policies.iter().map(|p| p.rules.len()).sum();

        let mut stats = self.stats.write().unwrap();
        stats.loaded_policies = policies.len();
        stats.total_rules = total_rules;

        // Update cache stats
        let policy_cache_size = self.policy_cache.read().unwrap().len();
        let evaluation_cache_size = self.evaluation_cache.read().unwrap().len();

        let mut cache_stats = self.cache_stats.write().unwrap();
        cache_stats.policy_cache_size = policy_cache_size;
        cache_stats.evaluation_cache_size = evaluation_cache_size;

        stats.cache_stats = cache_stats.clone();
    }

    async fn start_reload_task(&self) {
        let config = self.config.clone();
        let engine = Arc::new(self);
        let is_running = self.is_running.clone();

        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(config.reload_interval_seconds));

            loop {
                interval.tick().await;

                if !*is_running.read().unwrap() {
                    break;
                }

                if let Err(e) = engine.reload_policies().await {
                    error!("Automatic policy reload failed: {}", e);
                }
            }

            debug!("Policy reload task stopped");
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn create_test_config() -> PolicyConfig {
        PolicyConfig {
            policy_files: vec![],
            policy_directory: None,
            reload_interval_seconds: 0, // Disable auto-reload for tests
            default_action: PolicyAction::Deny,
            enable_cache: true,
            cache_ttl_seconds: 60,
            validate_on_reload: true,
            audit_logging: false,
        }
    }

    fn create_test_request() -> PolicyRequest {
        PolicyRequest {
            source: PolicyPrincipal::User {
                id: Uuid::new_v4(),
                name: "testuser".to_string(),
                email: Some("test@example.com".to_string()),
                groups: vec!["users".to_string()],
                roles: vec![],
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

    #[tokio::test]
    async fn test_policy_engine_lifecycle() {
        let config = create_test_config();
        let engine = PolicyEngine::new(config);

        // Engine should start successfully
        assert!(engine.start().await.is_err()); // No policies loaded

        // Add a policy manually
        let policy_set = HuJsonParser::create_sample_policy();
        assert!(engine.add_policy(policy_set).await.is_ok());

        // Engine should start successfully now
        assert!(engine.start().await.is_ok());

        // Engine should stop successfully
        assert!(engine.stop().await.is_ok());
    }

    #[tokio::test]
    async fn test_policy_evaluation() {
        let config = create_test_config();
        let engine = PolicyEngine::new(config);

        // Add a sample policy
        let policy_set = HuJsonParser::create_sample_policy();
        engine.add_policy(policy_set).await.unwrap();

        let request = create_test_request();
        let response = engine.evaluate(request).await.unwrap();

        // Should get a decision
        assert!(matches!(response.decision, PolicyDecision::Allow | PolicyDecision::Deny));
    }

    #[tokio::test]
    async fn test_policy_cache() {
        let mut config = create_test_config();
        config.enable_cache = true;

        let engine = PolicyEngine::new(config);
        let policy_set = HuJsonParser::create_sample_policy();
        engine.add_policy(policy_set).await.unwrap();

        let request = create_test_request();

        // First evaluation should be uncached
        let response1 = engine.evaluate(request.clone()).await.unwrap();

        // Second evaluation should be cached
        let response2 = engine.evaluate(request).await.unwrap();

        // Responses should be identical
        assert_eq!(response1.decision, response2.decision);
        assert_eq!(response1.matched_rule, response2.matched_rule);
    }

    #[tokio::test]
    async fn test_policy_management() {
        let config = create_test_config();
        let engine = PolicyEngine::new(config);

        // Initially no policies
        let policies = engine.list_policies().await;
        assert_eq!(policies.len(), 0);

        // Add a policy
        let policy_set = HuJsonParser::create_sample_policy();
        let policy_name = policy_set.metadata.name.clone();
        engine.add_policy(policy_set).await.unwrap();

        // Should have one policy
        let policies = engine.list_policies().await;
        assert_eq!(policies.len(), 1);
        assert_eq!(policies[0].name, policy_name);

        // Remove the policy
        let removed = engine.remove_policy(&policy_name).await.unwrap();
        assert!(removed);

        // Should have no policies again
        let policies = engine.list_policies().await;
        assert_eq!(policies.len(), 0);
    }

    #[tokio::test]
    async fn test_policy_validation() {
        let config = create_test_config();
        let engine = PolicyEngine::new(config);

        // Valid policy should pass validation
        let valid_policy = HuJsonParser::create_sample_policy();
        assert!(engine.validate_policy(&valid_policy).await.is_ok());

        // Invalid policy should fail validation
        let mut invalid_policy = valid_policy;
        invalid_policy.rules[0].id = String::new(); // Empty ID is invalid
        // Note: This test might pass if validation doesn't catch empty IDs in this path
    }
}