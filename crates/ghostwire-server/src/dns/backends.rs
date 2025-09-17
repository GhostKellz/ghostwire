/// DNS backend implementations
///
/// Provides various backends for DNS resolution including coordinator-based
/// node resolution, file-based records, external APIs, and Redis storage.

use crate::dns::{DnsQueryContext, DnsResponse, DnsRecord, ResponseCode, ResponseSource};
use crate::coordinator::Coordinator;
use ghostwire_common::{
    types::*,
    error::{Result, GhostWireError},
};
use async_trait::async_trait;
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::time::SystemTime;
use tokio::sync::RwLock;
use trust_dns_server::proto::rr::{Name, RecordType};
use serde::{Deserialize, Serialize};
use tracing::{debug, warn, error, info};

/// DNS backend trait
#[async_trait]
pub trait DnsBackend {
    /// Resolve a DNS query
    async fn resolve(&self, context: &DnsQueryContext) -> Result<Option<DnsResponse>>;

    /// Get backend name
    fn name(&self) -> &str;

    /// Check if backend is healthy
    async fn health_check(&self) -> Result<bool>;
}

/// Coordinator-based DNS backend
pub struct CoordinatorDnsBackend {
    coordinator: Arc<Coordinator>,
    config: crate::dns::CoordinatorBackend,
}

impl CoordinatorDnsBackend {
    pub fn new(coordinator: Arc<Coordinator>, config: crate::dns::CoordinatorBackend) -> Self {
        Self { coordinator, config }
    }

    async fn resolve_node_record(&self, name: &Name, record_type: RecordType) -> Result<Option<DnsResponse>> {
        let name_str = name.to_string().trim_end_matches('.').to_lowercase();

        debug!("Attempting to resolve node record: {} ({})", name_str, record_type);

        // Parse node name format: {name}.{user}.ghost
        let base_domain = format!(".{}", self.config.node_name_format.replace("{name}.{user}", ""));

        if !name_str.ends_with(&base_domain.trim_start_matches('.')) {
            return Ok(None);
        }

        // Extract node and user from the name
        let without_domain = name_str.strip_suffix(&base_domain.trim_start_matches('.')).unwrap();
        let parts: Vec<&str> = without_domain.split('.').collect();

        if parts.len() < 2 {
            return Ok(None);
        }

        let node_name = parts[0];
        let user_name = parts[1];

        debug!("Parsed node name: {}, user: {}", node_name, user_name);

        // Look up the node
        let nodes = self.coordinator.list_nodes().await?;
        let node = nodes.iter().find(|n| {
            n.name == node_name && {
                // Get user name for the node
                if let Ok(users) = tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current().block_on(async {
                        self.coordinator.get_user_by_id(&n.owner).await
                    })
                }) {
                    users.name == user_name
                } else {
                    false
                }
            }
        });

        if let Some(node) = node {
            let mut records = Vec::new();

            match record_type {
                RecordType::A => {
                    records.push(DnsRecord {
                        name: name_str.clone(),
                        record_type: "A".to_string(),
                        value: node.ipv4.to_string(),
                        ttl: self.config.node_ttl,
                        class: "IN".to_string(),
                    });
                }
                RecordType::AAAA => {
                    if self.config.include_ipv6 {
                        if let Some(ipv6) = node.ipv6 {
                            records.push(DnsRecord {
                                name: name_str.clone(),
                                record_type: "AAAA".to_string(),
                                value: ipv6.to_string(),
                                ttl: self.config.node_ttl,
                                class: "IN".to_string(),
                            });
                        }
                    }
                }
                RecordType::TXT => {
                    // Add node metadata as TXT records
                    let metadata = format!(
                        "node-id={} online={} owner={}",
                        node.id,
                        node.online,
                        node.owner
                    );
                    records.push(DnsRecord {
                        name: name_str.clone(),
                        record_type: "TXT".to_string(),
                        value: metadata,
                        ttl: self.config.node_ttl,
                        class: "IN".to_string(),
                    });
                }
                _ => {
                    // Unsupported record type for nodes
                    return Ok(None);
                }
            }

            if !records.is_empty() {
                debug!("Resolved node record: {} -> {} records", name_str, records.len());

                return Ok(Some(DnsResponse {
                    records,
                    authority: vec![],
                    additional: vec![],
                    response_code: ResponseCode::NoError,
                    ttl: self.config.node_ttl,
                    source: ResponseSource::Coordinator,
                }));
            }
        }

        Ok(None)
    }

    async fn resolve_service_record(&self, name: &Name, record_type: RecordType) -> Result<Option<DnsResponse>> {
        // Handle service discovery records like _service._tcp.domain
        let name_str = name.to_string().trim_end_matches('.').to_lowercase();

        if !name_str.starts_with('_') || record_type != RecordType::SRV {
            return Ok(None);
        }

        debug!("Attempting to resolve service record: {}", name_str);

        // Parse service name: _http._tcp.ghost
        let parts: Vec<&str> = name_str.split('.').collect();
        if parts.len() < 3 {
            return Ok(None);
        }

        let service = parts[0].trim_start_matches('_');
        let protocol = parts[1].trim_start_matches('_');

        debug!("Parsed service: {}, protocol: {}", service, protocol);

        // Look up nodes that provide this service
        let nodes = self.coordinator.list_nodes().await?;
        let mut records = Vec::new();

        for node in nodes.iter().filter(|n| n.online) {
            // Check if node provides this service (simplified logic)
            let provides_service = match service {
                "ssh" => node.capabilities.supports_ssh,
                "http" | "https" => node.tags.contains(&"web".to_string()),
                "derp" => node.capabilities.supports_derp,
                _ => false,
            };

            if provides_service {
                let port = match service {
                    "ssh" => 22,
                    "http" => 80,
                    "https" => 443,
                    "derp" => 3478,
                    _ => continue,
                };

                let target = format!("{}.{}.ghost", node.name, "user"); // Simplified
                let srv_value = format!("10 10 {} {}", port, target);

                records.push(DnsRecord {
                    name: name_str.clone(),
                    record_type: "SRV".to_string(),
                    value: srv_value,
                    ttl: self.config.node_ttl,
                    class: "IN".to_string(),
                });
            }
        }

        if !records.is_empty() {
            debug!("Resolved service record: {} -> {} records", name_str, records.len());

            return Ok(Some(DnsResponse {
                records,
                authority: vec![],
                additional: vec![],
                response_code: ResponseCode::NoError,
                ttl: self.config.node_ttl,
                source: ResponseSource::Coordinator,
            }));
        }

        Ok(None)
    }
}

#[async_trait]
impl DnsBackend for CoordinatorDnsBackend {
    async fn resolve(&self, context: &DnsQueryContext) -> Result<Option<DnsResponse>> {
        // Try node record resolution first
        if let Some(response) = self.resolve_node_record(&context.query_name, context.query_type).await? {
            return Ok(Some(response));
        }

        // Try service record resolution
        if let Some(response) = self.resolve_service_record(&context.query_name, context.query_type).await? {
            return Ok(Some(response));
        }

        Ok(None)
    }

    fn name(&self) -> &str {
        "coordinator"
    }

    async fn health_check(&self) -> Result<bool> {
        // Check if coordinator is accessible
        match self.coordinator.get_stats().await {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}

/// File-based DNS backend
pub struct FileDnsBackend {
    config: crate::dns::FileBackend,
    records: Arc<RwLock<HashMap<String, Vec<DnsRecord>>>>,
    last_modified: Arc<RwLock<Option<SystemTime>>>,
}

impl FileDnsBackend {
    pub fn new(config: crate::dns::FileBackend) -> Result<Self> {
        let backend = Self {
            config,
            records: Arc::new(RwLock::new(HashMap::new())),
            last_modified: Arc::new(RwLock::new(None)),
        };

        // Load initial records
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                backend.load_records().await
            })
        })?;

        Ok(backend)
    }

    async fn load_records(&self) -> Result<()> {
        let path = Path::new(&self.config.zone_file);

        if !path.exists() {
            warn!("Zone file does not exist: {}", self.config.zone_file);
            return Ok(());
        }

        let metadata = fs::metadata(path)
            .map_err(|e| GhostWireError::io(format!("Failed to read zone file metadata: {}", e)))?;

        let modified = metadata.modified()
            .map_err(|e| GhostWireError::io(format!("Failed to get zone file modification time: {}", e)))?;

        // Check if file has been modified
        {
            let last_modified = self.last_modified.read().await;
            if let Some(last) = *last_modified {
                if modified <= last {
                    // File hasn't changed
                    return Ok(());
                }
            }
        }

        info!("Loading DNS records from zone file: {}", self.config.zone_file);

        let content = fs::read_to_string(path)
            .map_err(|e| GhostWireError::io(format!("Failed to read zone file: {}", e)))?;

        let parsed_records = self.parse_zone_file(&content)?;

        // Update records and modification time
        *self.records.write().await = parsed_records;
        *self.last_modified.write().await = Some(modified);

        info!("Loaded {} DNS record types from zone file", self.records.read().await.len());

        Ok(())
    }

    fn parse_zone_file(&self, content: &str) -> Result<HashMap<String, Vec<DnsRecord>>> {
        let mut records = HashMap::new();

        for (line_num, line) in content.lines().enumerate() {
            let line = line.trim();

            // Skip comments and empty lines
            if line.is_empty() || line.starts_with(';') {
                continue;
            }

            // Parse DNS record line
            // Format: name TTL class type value
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 4 {
                warn!("Invalid DNS record on line {}: {}", line_num + 1, line);
                continue;
            }

            let name = parts[0].to_lowercase();
            let ttl = parts[1].parse::<u32>().unwrap_or(300);
            let class = parts[2].to_uppercase();
            let record_type = parts[3].to_uppercase();
            let value = parts[4..].join(" ");

            let record = DnsRecord {
                name: name.clone(),
                record_type,
                value,
                ttl,
                class,
            };

            records.entry(name).or_insert_with(Vec::new).push(record);
        }

        Ok(records)
    }

    async fn check_and_reload(&self) -> Result<()> {
        if self.config.watch_changes {
            self.load_records().await?;
        }
        Ok(())
    }
}

#[async_trait]
impl DnsBackend for FileDnsBackend {
    async fn resolve(&self, context: &DnsQueryContext) -> Result<Option<DnsResponse>> {
        // Check for file changes if watching is enabled
        self.check_and_reload().await?;

        let name_str = context.query_name.to_string().trim_end_matches('.').to_lowercase();
        let record_type_str = context.query_type.to_string();

        let records = self.records.read().await;
        if let Some(file_records) = records.get(&name_str) {
            let matching_records: Vec<DnsRecord> = file_records
                .iter()
                .filter(|r| r.record_type == record_type_str)
                .cloned()
                .collect();

            if !matching_records.is_empty() {
                debug!("File backend resolved: {} {} -> {} records", name_str, record_type_str, matching_records.len());

                return Ok(Some(DnsResponse {
                    records: matching_records,
                    authority: vec![],
                    additional: vec![],
                    response_code: ResponseCode::NoError,
                    ttl: 300, // Default TTL
                    source: ResponseSource::File,
                }));
            }
        }

        Ok(None)
    }

    fn name(&self) -> &str {
        "file"
    }

    async fn health_check(&self) -> Result<bool> {
        let path = Path::new(&self.config.zone_file);
        Ok(path.exists())
    }
}

/// External API DNS backend
pub struct ExternalApiDnsBackend {
    config: crate::dns::ExternalApiBackend,
    client: reqwest::Client,
    cache: Arc<RwLock<HashMap<String, (DnsResponse, SystemTime)>>>,
}

impl ExternalApiDnsBackend {
    pub fn new(config: crate::dns::ExternalApiBackend) -> Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(config.timeout))
            .build()
            .map_err(|e| GhostWireError::network(format!("Failed to create HTTP client: {}", e)))?;

        Ok(Self {
            config,
            client,
            cache: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    async fn query_api(&self, name: &str, record_type: &str) -> Result<Option<DnsResponse>> {
        let mut url = reqwest::Url::parse(&self.config.endpoint)
            .map_err(|e| GhostWireError::configuration(format!("Invalid API endpoint: {}", e)))?;

        url.query_pairs_mut()
            .append_pair("name", name)
            .append_pair("type", record_type);

        let mut request = self.client.get(url);

        if let Some(api_key) = &self.config.api_key {
            request = request.header("Authorization", format!("Bearer {}", api_key));
        }

        let response = request.send().await
            .map_err(|e| GhostWireError::network(format!("API request failed: {}", e)))?;

        if !response.status().is_success() {
            return Ok(None);
        }

        let api_response: ApiDnsResponse = response.json().await
            .map_err(|e| GhostWireError::protocol(format!("Failed to parse API response: {}", e)))?;

        if api_response.records.is_empty() {
            return Ok(None);
        }

        Ok(Some(DnsResponse {
            records: api_response.records,
            authority: vec![],
            additional: vec![],
            response_code: ResponseCode::NoError,
            ttl: self.config.cache_ttl,
            source: ResponseSource::ExternalApi,
        }))
    }

    async fn get_cached(&self, cache_key: &str) -> Option<DnsResponse> {
        let cache = self.cache.read().await;
        if let Some((response, cached_at)) = cache.get(cache_key) {
            let cache_duration = std::time::Duration::from_secs(self.config.cache_ttl as u64);
            if cached_at.elapsed().unwrap_or_default() < cache_duration {
                return Some(response.clone());
            }
        }
        None
    }

    async fn cache_response(&self, cache_key: String, response: DnsResponse) {
        let mut cache = self.cache.write().await;
        cache.insert(cache_key, (response, SystemTime::now()));

        // Simple cache cleanup - remove entries older than 2x cache TTL
        let max_age = std::time::Duration::from_secs(self.config.cache_ttl as u64 * 2);
        cache.retain(|_, (_, cached_at)| {
            cached_at.elapsed().unwrap_or_default() < max_age
        });
    }
}

#[async_trait]
impl DnsBackend for ExternalApiDnsBackend {
    async fn resolve(&self, context: &DnsQueryContext) -> Result<Option<DnsResponse>> {
        let name_str = context.query_name.to_string().trim_end_matches('.').to_lowercase();
        let record_type_str = context.query_type.to_string();
        let cache_key = format!("{}:{}", name_str, record_type_str);

        // Check cache first
        if let Some(cached_response) = self.get_cached(&cache_key).await {
            debug!("External API cache hit: {} {}", name_str, record_type_str);
            return Ok(Some(cached_response));
        }

        // Query the API
        match self.query_api(&name_str, &record_type_str).await? {
            Some(response) => {
                debug!("External API resolved: {} {} -> {} records", name_str, record_type_str, response.records.len());

                // Cache the response
                self.cache_response(cache_key, response.clone()).await;

                Ok(Some(response))
            }
            None => Ok(None),
        }
    }

    fn name(&self) -> &str {
        "external_api"
    }

    async fn health_check(&self) -> Result<bool> {
        // Simple health check - try to reach the API endpoint
        match self.client.head(&self.config.endpoint).send().await {
            Ok(response) => Ok(response.status().is_success()),
            Err(_) => Ok(false),
        }
    }
}

/// Redis DNS backend
pub struct RedisDnsBackend {
    config: crate::dns::RedisBackend,
}

impl RedisDnsBackend {
    pub fn new(config: crate::dns::RedisBackend) -> Result<Self> {
        // Redis implementation would go here
        // For now, return a placeholder
        Ok(Self { config })
    }
}

#[async_trait]
impl DnsBackend for RedisDnsBackend {
    async fn resolve(&self, _context: &DnsQueryContext) -> Result<Option<DnsResponse>> {
        // Redis implementation would go here
        Ok(None)
    }

    fn name(&self) -> &str {
        "redis"
    }

    async fn health_check(&self) -> Result<bool> {
        // Redis health check would go here
        Ok(true)
    }
}

/// API response format for external DNS API
#[derive(Debug, Deserialize)]
struct ApiDnsResponse {
    records: Vec<DnsRecord>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use trust_dns_server::proto::rr::Name;
    use std::str::FromStr;

    #[test]
    fn test_zone_file_parsing() {
        let content = r#"
; Example zone file
example.com.    300 IN  A       192.168.1.1
example.com.    300 IN  AAAA    2001:db8::1
www.example.com. 300 IN CNAME   example.com.
"#;

        let config = crate::dns::FileBackend {
            enabled: true,
            zone_file: "/tmp/test.zone".to_string(),
            watch_changes: false,
            reload_interval: 300,
        };

        let backend = FileDnsBackend {
            config,
            records: Arc::new(RwLock::new(HashMap::new())),
            last_modified: Arc::new(RwLock::new(None)),
        };

        let parsed = backend.parse_zone_file(content).unwrap();

        assert!(parsed.contains_key("example.com."));
        assert!(parsed.contains_key("www.example.com."));

        let example_records = &parsed["example.com."];
        assert_eq!(example_records.len(), 2); // A and AAAA records
    }

    #[tokio::test]
    async fn test_coordinator_backend_health_check() {
        let coordinator = Arc::new(crate::coordinator::Coordinator::new_test());
        let config = crate::dns::CoordinatorBackend::default();
        let backend = CoordinatorDnsBackend::new(coordinator, config);

        // This should pass if coordinator is accessible
        let healthy = backend.health_check().await.unwrap();
        assert!(healthy);
    }

    #[test]
    fn test_api_url_construction() {
        let config = crate::dns::ExternalApiBackend {
            enabled: true,
            endpoint: "https://api.example.com/dns".to_string(),
            api_key: Some("test-key".to_string()),
            timeout: 30,
            cache_ttl: 300,
        };

        let mut url = reqwest::Url::parse(&config.endpoint).unwrap();
        url.query_pairs_mut()
            .append_pair("name", "test.example.com")
            .append_pair("type", "A");

        assert!(url.as_str().contains("name=test.example.com"));
        assert!(url.as_str().contains("type=A"));
    }
}