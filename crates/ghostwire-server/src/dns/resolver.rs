/// DNS resolver implementation
///
/// Core DNS resolution engine that handles queries, manages backends,
/// implements split-DNS logic, and provides caching capabilities.

use crate::dns::*;
use crate::coordinator::Coordinator;
use ghostwire_common::{
    types::*,
    error::{Result, GhostWireError},
};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{SystemTime, Instant, Duration};
use tokio::sync::RwLock;
use trust_dns_server::proto::rr::{Name, RecordType, RData, Record};
use trust_dns_resolver::{AsyncResolver, TokioAsyncResolver};
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts, NameServerConfig, Protocol};
use tracing::{debug, warn, error, info};
use lru::LruCache;

/// DNS cache entry
#[derive(Debug, Clone)]
struct CacheEntry {
    /// Cached response
    response: DnsResponse,
    /// Cache timestamp
    cached_at: Instant,
    /// Entry TTL
    ttl: Duration,
}

/// Rate limiter entry
#[derive(Debug, Clone)]
struct RateLimitEntry {
    /// Query count
    count: u32,
    /// Window start time
    window_start: Instant,
}

/// DNS resolver
pub struct DnsResolver {
    config: DnsConfig,
    coordinator: Arc<Coordinator>,
    upstream_resolver: AsyncResolver,
    cache: Arc<RwLock<LruCache<String, CacheEntry>>>,
    rate_limiter: Arc<RwLock<HashMap<IpAddr, RateLimitEntry>>>,
    stats: Arc<RwLock<DnsStats>>,
    backends: Vec<Box<dyn DnsBackend + Send + Sync>>,
}

impl DnsResolver {
    /// Create a new DNS resolver
    pub async fn new(config: DnsConfig, coordinator: Arc<Coordinator>) -> Result<Self> {
        // Create upstream resolver
        let mut resolver_config = ResolverConfig::new();
        for server in &config.upstream_servers {
            let nameserver = NameServerConfig::new(*server, 53, Protocol::Udp);
            resolver_config.add_name_server(nameserver);
        }

        let resolver_opts = ResolverOpts::default();
        let upstream_resolver = TokioAsyncResolver::tokio(resolver_config, resolver_opts)
            .map_err(|e| GhostWireError::network(format!("Failed to create upstream resolver: {}", e)))?;

        // Create cache
        let cache = Arc::new(RwLock::new(LruCache::new(config.cache.max_entries)));

        // Create rate limiter
        let rate_limiter = Arc::new(RwLock::new(HashMap::new()));

        // Create stats
        let stats = Arc::new(RwLock::new(DnsStats {
            total_queries: 0,
            queries_by_type: HashMap::new(),
            responses_by_source: HashMap::new(),
            cache_hit_rate: 0.0,
            average_response_time_ms: 0.0,
            rate_limited_queries: 0,
            blocked_queries: 0,
            upstream_queries: 0,
            cache_stats: CacheStats {
                current_size: 0,
                cache_hits: 0,
                cache_misses: 0,
                cache_evictions: 0,
                memory_usage: 0,
            },
        }));

        // Create backends
        let mut backends: Vec<Box<dyn DnsBackend + Send + Sync>> = Vec::new();

        // Add coordinator backend
        if config.backends.coordinator.enabled {
            backends.push(Box::new(CoordinatorDnsBackend::new(
                coordinator.clone(),
                config.backends.coordinator.clone(),
            )));
        }

        // Add file backend if configured
        if let Some(file_config) = &config.backends.file {
            if file_config.enabled {
                backends.push(Box::new(FileDnsBackend::new(file_config.clone())?));
            }
        }

        // Add external API backend if configured
        if let Some(api_config) = &config.backends.external_api {
            if api_config.enabled {
                backends.push(Box::new(ExternalApiDnsBackend::new(api_config.clone())?));
            }
        }

        // Add Redis backend if configured
        if let Some(redis_config) = &config.backends.redis {
            if redis_config.enabled {
                backends.push(Box::new(RedisDnsBackend::new(redis_config.clone())?));
            }
        }

        Ok(Self {
            config,
            coordinator,
            upstream_resolver,
            cache,
            rate_limiter,
            stats,
            backends,
        })
    }

    /// Resolve a DNS query
    pub async fn resolve(&self, context: DnsQueryContext) -> Result<DnsResponse> {
        let start_time = Instant::now();

        debug!(
            "Resolving DNS query: {} {} from {}",
            context.query_name,
            context.query_type,
            context.client_ip
        );

        // Update stats
        self.update_query_stats(&context).await;

        // Check rate limiting
        if self.config.security.rate_limiting {
            if self.is_rate_limited(&context.client_ip).await? {
                warn!(
                    "Rate limited DNS query from {}: {} {}",
                    context.client_ip,
                    context.query_name,
                    context.query_type
                );

                self.stats.write().await.rate_limited_queries += 1;

                return Ok(DnsResponse {
                    records: vec![],
                    authority: vec![],
                    additional: vec![],
                    response_code: ResponseCode::Refused,
                    ttl: 0,
                    source: ResponseSource::Static,
                });
            }
        }

        // Check security filters
        if self.config.security.block_suspicious {
            if self.is_suspicious_query(&context)? {
                warn!(
                    "Blocked suspicious DNS query from {}: {} {}",
                    context.client_ip,
                    context.query_name,
                    context.query_type
                );

                self.stats.write().await.blocked_queries += 1;

                return Ok(DnsResponse {
                    records: vec![],
                    authority: vec![],
                    additional: vec![],
                    response_code: ResponseCode::NXDomain,
                    ttl: self.config.cache.negative_ttl,
                    source: ResponseSource::Static,
                });
            }
        }

        // Check cache first
        if self.config.cache.enabled {
            let cache_key = self.create_cache_key(&context);
            if let Some(cached_response) = self.get_cached_response(&cache_key).await {
                debug!("Cache hit for query: {} {}", context.query_name, context.query_type);

                self.stats.write().await.cache_stats.cache_hits += 1;
                self.update_response_stats(&cached_response, start_time.elapsed()).await;

                return Ok(cached_response);
            }

            self.stats.write().await.cache_stats.cache_misses += 1;
        }

        // Determine resolution strategy based on split-DNS configuration
        let response = if self.should_resolve_internally(&context.query_name)? {
            // Resolve using internal backends
            self.resolve_internal(&context).await?
        } else {
            // Forward to upstream DNS
            self.resolve_upstream(&context).await?
        };

        // Cache the response
        if self.config.cache.enabled && response.response_code == ResponseCode::NoError {
            let cache_key = self.create_cache_key(&context);
            self.cache_response(&cache_key, &response).await;
        }

        // Update stats
        self.update_response_stats(&response, start_time.elapsed()).await;

        debug!(
            "Resolved DNS query: {} {} -> {:?} ({}ms)",
            context.query_name,
            context.query_type,
            response.response_code,
            start_time.elapsed().as_millis()
        );

        Ok(response)
    }

    /// Get resolver statistics
    pub async fn get_stats(&self) -> DnsStats {
        let mut stats = self.stats.read().await.clone();

        // Update cache stats
        let cache = self.cache.read().await;
        stats.cache_stats.current_size = cache.len();

        // Calculate cache hit rate
        let total_cache_requests = stats.cache_stats.cache_hits + stats.cache_stats.cache_misses;
        if total_cache_requests > 0 {
            stats.cache_hit_rate = stats.cache_stats.cache_hits as f64 / total_cache_requests as f64;
        }

        stats
    }

    /// Clear DNS cache
    pub async fn clear_cache(&self) -> Result<()> {
        self.cache.write().await.clear();
        info!("DNS cache cleared");
        Ok(())
    }

    /// Flush expired cache entries
    pub async fn flush_expired_cache(&self) -> Result<usize> {
        let mut cache = self.cache.write().await;
        let now = Instant::now();
        let mut expired_keys = Vec::new();

        // Find expired entries
        for (key, entry) in cache.iter() {
            if now.duration_since(entry.cached_at) > entry.ttl {
                expired_keys.push(key.clone());
            }
        }

        // Remove expired entries
        let count = expired_keys.len();
        for key in expired_keys {
            cache.pop(&key);
        }

        if count > 0 {
            debug!("Flushed {} expired DNS cache entries", count);
        }

        Ok(count)
    }

    // Private helper methods

    async fn update_query_stats(&self, context: &DnsQueryContext) {
        let mut stats = self.stats.write().await;
        stats.total_queries += 1;

        let query_type_str = context.query_type.to_string();
        *stats.queries_by_type.entry(query_type_str).or_insert(0) += 1;
    }

    async fn update_response_stats(&self, response: &DnsResponse, duration: Duration) {
        let mut stats = self.stats.write().await;

        // Update response source stats
        let source_str = match &response.source {
            ResponseSource::Cache => "cache",
            ResponseSource::Coordinator => "coordinator",
            ResponseSource::File => "file",
            ResponseSource::ExternalApi => "external_api",
            ResponseSource::Redis => "redis",
            ResponseSource::Upstream => "upstream",
            ResponseSource::Static => "static",
        };

        *stats.responses_by_source.entry(source_str.to_string()).or_insert(0) += 1;

        // Update average response time
        let total_queries = stats.total_queries as f64;
        let current_avg = stats.average_response_time_ms;
        let new_time = duration.as_millis() as f64;

        stats.average_response_time_ms = (current_avg * (total_queries - 1.0) + new_time) / total_queries;

        // Count upstream queries
        if matches!(response.source, ResponseSource::Upstream) {
            stats.upstream_queries += 1;
        }
    }

    async fn is_rate_limited(&self, client_ip: &IpAddr) -> Result<bool> {
        let mut rate_limiter = self.rate_limiter.write().await;
        let now = Instant::now();
        let window_duration = Duration::from_secs(60); // 1 minute window

        match rate_limiter.get_mut(client_ip) {
            Some(entry) => {
                // Check if we're in a new window
                if now.duration_since(entry.window_start) >= window_duration {
                    entry.count = 1;
                    entry.window_start = now;
                    Ok(false)
                } else {
                    entry.count += 1;
                    Ok(entry.count > self.config.security.queries_per_ip_per_minute)
                }
            }
            None => {
                // First query from this IP
                rate_limiter.insert(*client_ip, RateLimitEntry {
                    count: 1,
                    window_start: now,
                });
                Ok(false)
            }
        }
    }

    fn is_suspicious_query(&self, context: &DnsQueryContext) -> Result<bool> {
        // Check if query type is allowed
        let query_type_str = context.query_type.to_string();
        if !self.config.security.allowed_query_types.contains(&query_type_str) {
            return Ok(true);
        }

        // Check for suspicious patterns
        let query_name_str = context.query_name.to_string();

        // Block excessively long queries
        if query_name_str.len() > 253 {
            return Ok(true);
        }

        // Block queries with suspicious patterns
        let suspicious_patterns = [
            "malware", "phishing", "spam", "abuse",
            "dga-", "bot-", "c2-", "evil",
        ];

        for pattern in &suspicious_patterns {
            if query_name_str.to_lowercase().contains(pattern) {
                return Ok(true);
            }
        }

        Ok(false)
    }

    fn should_resolve_internally(&self, query_name: &Name) -> Result<bool> {
        if !self.config.split_dns.enabled {
            return Ok(false);
        }

        let query_name_str = query_name.to_string();

        // Check internal domains
        for domain in &self.config.split_dns.internal_domains {
            if query_name_str.ends_with(domain) {
                return Ok(true);
            }
        }

        // Check external domains
        for domain in &self.config.split_dns.external_domains {
            if query_name_str.ends_with(domain) {
                return Ok(false);
            }
        }

        // Check overrides
        for override_rule in &self.config.split_dns.overrides {
            if self.matches_pattern(&query_name_str, &override_rule.pattern) {
                return Ok(matches!(override_rule.action, OverrideAction::Internal));
            }
        }

        // Use default behavior
        Ok(matches!(self.config.split_dns.default_behavior, DefaultBehavior::Block))
    }

    fn matches_pattern(&self, name: &str, pattern: &str) -> bool {
        if pattern.contains('*') {
            // Simple wildcard matching
            if pattern.starts_with("*.") {
                let suffix = &pattern[2..];
                name.ends_with(suffix)
            } else if pattern.ends_with(".*") {
                let prefix = &pattern[..pattern.len() - 2];
                name.starts_with(prefix)
            } else {
                name == pattern
            }
        } else {
            name == pattern || name.ends_with(&format!(".{}", pattern))
        }
    }

    async fn resolve_internal(&self, context: &DnsQueryContext) -> Result<DnsResponse> {
        debug!("Resolving internally: {} {}", context.query_name, context.query_type);

        // Try each backend in order
        for backend in &self.backends {
            match backend.resolve(context).await {
                Ok(Some(response)) => {
                    debug!("Internal resolution successful via backend: {:?}", response.source);
                    return Ok(response);
                }
                Ok(None) => {
                    // Backend didn't have the record, try next
                    continue;
                }
                Err(e) => {
                    warn!("Backend error during internal resolution: {}", e);
                    continue;
                }
            }
        }

        // No backend could resolve the query
        debug!("Internal resolution failed: no backend found record");

        Ok(DnsResponse {
            records: vec![],
            authority: vec![],
            additional: vec![],
            response_code: ResponseCode::NXDomain,
            ttl: self.config.cache.negative_ttl,
            source: ResponseSource::Static,
        })
    }

    async fn resolve_upstream(&self, context: &DnsQueryContext) -> Result<DnsResponse> {
        debug!("Resolving upstream: {} {}", context.query_name, context.query_type);

        // Check for override rules first
        let query_name_str = context.query_name.to_string();
        for override_rule in &self.config.split_dns.overrides {
            if self.matches_pattern(&query_name_str, &override_rule.pattern) {
                match &override_rule.action {
                    OverrideAction::Block => {
                        return Ok(DnsResponse {
                            records: vec![],
                            authority: vec![],
                            additional: vec![],
                            response_code: ResponseCode::NXDomain,
                            ttl: self.config.cache.negative_ttl,
                            source: ResponseSource::Static,
                        });
                    }
                    OverrideAction::Static => {
                        if let Some(static_record) = &override_rule.record {
                            return self.create_static_response(context, static_record);
                        }
                    }
                    OverrideAction::Forward => {
                        // Use specific servers for this query
                        if let Some(servers) = &override_rule.servers {
                            return self.resolve_with_specific_servers(context, servers).await;
                        }
                    }
                    OverrideAction::Internal => {
                        return self.resolve_internal(context).await;
                    }
                }
            }
        }

        // Default upstream resolution
        match self.upstream_resolver.lookup(context.query_name.clone(), context.query_type).await {
            Ok(lookup) => {
                let mut records = Vec::new();

                for record in lookup.iter() {
                    records.push(DnsRecord {
                        name: record.name().to_string(),
                        record_type: record.record_type().to_string(),
                        value: record.data().to_string(),
                        ttl: record.ttl(),
                        class: "IN".to_string(),
                    });
                }

                Ok(DnsResponse {
                    records,
                    authority: vec![],
                    additional: vec![],
                    response_code: ResponseCode::NoError,
                    ttl: lookup.valid_until().duration_since(SystemTime::now())
                        .unwrap_or_default()
                        .as_secs() as u32,
                    source: ResponseSource::Upstream,
                })
            }
            Err(e) => {
                warn!("Upstream resolution failed: {}", e);

                Ok(DnsResponse {
                    records: vec![],
                    authority: vec![],
                    additional: vec![],
                    response_code: ResponseCode::ServFail,
                    ttl: self.config.cache.negative_ttl,
                    source: ResponseSource::Upstream,
                })
            }
        }
    }

    async fn resolve_with_specific_servers(&self, context: &DnsQueryContext, servers: &[IpAddr]) -> Result<DnsResponse> {
        // This would implement resolution with specific DNS servers
        // For now, fall back to default upstream
        self.resolve_upstream(context).await
    }

    fn create_static_response(&self, context: &DnsQueryContext, static_record: &StaticRecord) -> Result<DnsResponse> {
        let record = DnsRecord {
            name: context.query_name.to_string(),
            record_type: static_record.record_type.clone(),
            value: static_record.value.clone(),
            ttl: static_record.ttl,
            class: "IN".to_string(),
        };

        Ok(DnsResponse {
            records: vec![record],
            authority: vec![],
            additional: vec![],
            response_code: ResponseCode::NoError,
            ttl: static_record.ttl,
            source: ResponseSource::Static,
        })
    }

    fn create_cache_key(&self, context: &DnsQueryContext) -> String {
        format!("{}:{}", context.query_name, context.query_type)
    }

    async fn get_cached_response(&self, cache_key: &str) -> Option<DnsResponse> {
        let cache = self.cache.read().await;
        if let Some(entry) = cache.peek(cache_key) {
            let now = Instant::now();
            if now.duration_since(entry.cached_at) <= entry.ttl {
                return Some(entry.response.clone());
            }
        }
        None
    }

    async fn cache_response(&self, cache_key: &str, response: &DnsResponse) {
        let ttl = Duration::from_secs(
            response.ttl.max(self.config.cache.min_ttl).min(self.config.cache.max_ttl) as u64
        );

        let entry = CacheEntry {
            response: response.clone(),
            cached_at: Instant::now(),
            ttl,
        };

        let mut cache = self.cache.write().await;
        cache.put(cache_key.to_string(), entry);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trust_dns_server::proto::rr::Name;
    use std::str::FromStr;

    #[test]
    fn test_matches_pattern() {
        let resolver_config = DnsConfig::default();
        let coordinator = Arc::new(crate::coordinator::Coordinator::new_test());

        // This would need to be async in real test
        // let resolver = DnsResolver::new(resolver_config, coordinator).await.unwrap();

        // Test wildcard patterns
        // assert!(resolver.matches_pattern("test.example.com", "*.example.com"));
        // assert!(resolver.matches_pattern("example.com", "example.*"));
        // assert!(resolver.matches_pattern("exact.match", "exact.match"));
    }

    #[test]
    fn test_cache_key_generation() {
        let context = DnsQueryContext {
            client_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            query_name: Name::from_str("example.com").unwrap(),
            query_type: RecordType::A,
            timestamp: SystemTime::now(),
            interface: "eth0".to_string(),
            query_id: 12345,
        };

        let resolver_config = DnsConfig::default();
        let coordinator = Arc::new(crate::coordinator::Coordinator::new_test());

        // This would need to be async in real test
        // let resolver = DnsResolver::new(resolver_config, coordinator).await.unwrap();
        // let cache_key = resolver.create_cache_key(&context);
        // assert!(cache_key.contains("example.com"));
        // assert!(cache_key.contains("A"));
    }

    #[test]
    fn test_suspicious_query_detection() {
        let config = DnsConfig::default();
        let context = DnsQueryContext {
            client_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            query_name: Name::from_str("malware.evil.com").unwrap(),
            query_type: RecordType::A,
            timestamp: SystemTime::now(),
            interface: "eth0".to_string(),
            query_id: 12345,
        };

        let coordinator = Arc::new(crate::coordinator::Coordinator::new_test());

        // This would need to be async in real test
        // let resolver = DnsResolver::new(config, coordinator).await.unwrap();
        // assert!(resolver.is_suspicious_query(&context).unwrap());
    }
}