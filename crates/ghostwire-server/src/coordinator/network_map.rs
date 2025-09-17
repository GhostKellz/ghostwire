/// Network map generation and distribution
///
/// Generates customized network maps for each node based on:
/// - ACL policies and permissions
/// - User membership and groups
/// - Node capabilities and routes
/// - Real-time connectivity information

use crate::database::{DatabaseConnection, NodeOperations, RouteOperations, AclOperations};
use super::node_manager::NodeManager;
use ghostwire_common::{
    error::{Result, GhostWireError},
    types::*,
};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::{RwLock, Notify};
use tracing::{debug, info, warn};

/// Network map generator and cache
pub struct NetworkMapper {
    database: Arc<DatabaseConnection>,
    node_manager: Arc<NodeManager>,
    cached_maps: Arc<RwLock<HashMap<NodeId, CachedNetworkMap>>>,
    map_version: Arc<RwLock<u64>>,
    update_notify: Arc<Notify>,
    stop_signal: Arc<RwLock<bool>>,
}

/// Cached network map with metadata
#[derive(Debug, Clone)]
struct CachedNetworkMap {
    map: NetworkMap,
    generated_at: SystemTime,
    version: u64,
}

impl NetworkMapper {
    /// Create new network mapper
    pub async fn new(
        database: Arc<DatabaseConnection>,
        node_manager: Arc<NodeManager>,
    ) -> Result<Self> {
        Ok(Self {
            database,
            node_manager,
            cached_maps: Arc::new(RwLock::new(HashMap::new())),
            map_version: Arc::new(RwLock::new(1)),
            update_notify: Arc::new(Notify::new()),
            stop_signal: Arc::new(RwLock::new(false)),
        })
    }

    /// Generate network map for a specific node
    pub async fn generate_map_for_node(&self, node: &Node) -> Result<NetworkMap> {
        self.generate_map_for_node_id(&node.id).await
    }

    /// Generate network map for a node by ID
    pub async fn generate_map_for_node_id(&self, node_id: &NodeId) -> Result<NetworkMap> {
        // Check cache first
        if let Some(cached) = self.get_cached_map(node_id).await {
            return Ok(cached.map);
        }

        // Generate new map
        let map = self.build_network_map(node_id).await?;

        // Cache the result
        self.cache_map(node_id, &map).await;

        Ok(map)
    }

    /// Check if a node needs a map update
    pub async fn check_for_updates(&self, node_id: &NodeId) -> Result<bool> {
        let current_version = *self.map_version.read().await;

        if let Some(cached) = self.get_cached_map(node_id).await {
            Ok(cached.version < current_version)
        } else {
            Ok(true) // No cached map, needs update
        }
    }

    /// Handle node removal and invalidate affected maps
    pub async fn handle_node_removal(&self, removed_node_id: &NodeId) -> Result<()> {
        // Increment version to invalidate all maps
        self.increment_version().await;

        // Remove specific cached map
        self.cached_maps.write().await.remove(removed_node_id);

        // Notify updater
        self.update_notify.notify_waiters();

        debug!("Invalidated network maps due to node removal: {}", removed_node_id);
        Ok(())
    }

    /// Start background map updater
    pub async fn start_updater(&self) -> Result<()> {
        let database = Arc::clone(&self.database);
        let node_manager = Arc::clone(&self.node_manager);
        let cached_maps = Arc::clone(&self.cached_maps);
        let map_version = Arc::clone(&self.map_version);
        let update_notify = Arc::clone(&self.update_notify);
        let stop_signal = Arc::clone(&self.stop_signal);

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));

            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        // Periodic cleanup and refresh
                        Self::cleanup_old_maps(&cached_maps).await;
                    }
                    _ = update_notify.notified() => {
                        // Handle update notifications
                        debug!("Network map update notification received");
                    }
                }

                // Check stop signal
                if *stop_signal.read().await {
                    break;
                }
            }

            info!("Network map updater stopped");
        });

        Ok(())
    }

    /// Stop the map updater
    pub async fn stop_updater(&self) -> Result<()> {
        *self.stop_signal.write().await = true;
        self.update_notify.notify_waiters();
        Ok(())
    }

    /// Build network map for a specific node
    async fn build_network_map(&self, target_node_id: &NodeId) -> Result<NetworkMap> {
        // Get target node
        let target_node = self.node_manager.get_node(target_node_id).await?
            .ok_or_else(|| GhostWireError::not_found("Target node not found"))?;

        // Get all online nodes
        let all_nodes = self.node_manager.get_online_nodes().await?;

        // Get ACL rules for policy evaluation
        let acl_rules = self.get_current_acl_rules().await?;

        // Filter peers based on ACL policies
        let mut authorized_peers = Vec::new();
        for node in all_nodes {
            if node.id == target_node.id {
                continue; // Skip self
            }

            if self.is_peer_authorized(&target_node, &node, &acl_rules).await? {
                authorized_peers.push(node);
            }
        }

        // Get routes from database
        let routes = RouteOperations::list_enabled(&self.database).await?;

        // Build DNS configuration
        let dns_config = self.build_dns_config(&target_node).await?;

        // Create network map
        let map = NetworkMap {
            node_key: target_node.public_key.clone(),
            private_key: None, // Never include private keys in network maps
            peers: authorized_peers,
            dns: dns_config,
            derp_map: self.build_derp_map().await?,
            packet_filter: self.build_packet_filter(&target_node, &acl_rules).await?,
            user_profiles: self.build_user_profiles(&target_node).await?,
            domain: "ghostwire.local".to_string(),
            collect_services: None,
        };

        debug!("Generated network map for node {} with {} peers",
               target_node_id, authorized_peers.len());

        Ok(map)
    }

    /// Get cached network map if valid
    async fn get_cached_map(&self, node_id: &NodeId) -> Option<CachedNetworkMap> {
        let maps = self.cached_maps.read().await;
        let current_version = *self.map_version.read().await;

        if let Some(cached) = maps.get(node_id) {
            // Check if cache is still valid (version and age)
            let age = SystemTime::now()
                .duration_since(cached.generated_at)
                .unwrap_or_default();

            if cached.version >= current_version && age < Duration::from_secs(300) {
                return Some(cached.clone());
            }
        }

        None
    }

    /// Cache a network map
    async fn cache_map(&self, node_id: &NodeId, map: &NetworkMap) {
        let version = *self.map_version.read().await;
        let cached = CachedNetworkMap {
            map: map.clone(),
            generated_at: SystemTime::now(),
            version,
        };

        self.cached_maps.write().await.insert(*node_id, cached);
    }

    /// Increment map version to invalidate caches
    async fn increment_version(&self) {
        let mut version = self.map_version.write().await;
        *version += 1;
        debug!("Incremented network map version to {}", *version);
    }

    /// Check if a peer is authorized based on ACL rules
    async fn is_peer_authorized(
        &self,
        source: &Node,
        dest: &Node,
        acl_rules: &[AclRule],
    ) -> Result<bool> {
        // Simple ACL evaluation - in production this would be more sophisticated
        for rule in acl_rules {
            if self.matches_acl_spec(source, &rule.source_spec).await? &&
               self.matches_acl_spec(dest, &rule.dest_spec).await? {
                return Ok(matches!(rule.action, AclAction::Accept));
            }
        }

        // Default deny if no rules match
        Ok(false)
    }

    /// Check if node matches ACL specification
    async fn matches_acl_spec(&self, node: &Node, spec: &[String]) -> Result<bool> {
        for spec_item in spec {
            if spec_item == "*" {
                return Ok(true);
            }

            // Check tags
            if spec_item.starts_with("tag:") {
                let tag = &spec_item[4..];
                if node.tags.contains(&tag.to_string()) {
                    return Ok(true);
                }
            }

            // Check user
            if spec_item.starts_with("user:") {
                let user_id_str = &spec_item[5..];
                if let Ok(user_id) = uuid::Uuid::parse_str(user_id_str) {
                    if node.user_id == user_id {
                        return Ok(true);
                    }
                }
            }

            // Check IP ranges
            if let Ok(cidr) = spec_item.parse::<ipnet::IpNet>() {
                if cidr.contains(&node.ipv4) ||
                   node.ipv6.map_or(false, |ipv6| cidr.contains(&ipv6)) {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    /// Get current ACL rules
    async fn get_current_acl_rules(&self) -> Result<Vec<AclRule>> {
        // Get latest policy version
        let version = AclOperations::get_latest_policy_version(&self.database).await?
            .unwrap_or(0);

        if version > 0 {
            AclOperations::get_policy_rules(&self.database, version).await
        } else {
            // Default rules if no ACL policy is configured
            Ok(vec![AclRule {
                id: None,
                policy_version: 0,
                rule_index: 0,
                action: AclAction::Accept,
                source_spec: vec!["*".to_string()],
                dest_spec: vec!["*".to_string()],
                created_at: SystemTime::now(),
            }])
        }
    }

    /// Build DNS configuration
    async fn build_dns_config(&self, _node: &Node) -> Result<DnsConfig> {
        // TODO: Implement MagicDNS configuration
        Ok(DnsConfig {
            resolvers: vec!["1.1.1.1".parse().unwrap(), "8.8.8.8".parse().unwrap()],
            domains: vec!["ghostwire.local".to_string()],
            magic_dns: true,
            routes: HashMap::new(),
        })
    }

    /// Build DERP map
    async fn build_derp_map(&self) -> Result<DerpMap> {
        // TODO: Implement dynamic DERP map from relay servers
        Ok(DerpMap {
            regions: HashMap::new(),
        })
    }

    /// Build packet filter from ACL rules
    async fn build_packet_filter(&self, node: &Node, acl_rules: &[AclRule]) -> Result<Vec<PacketFilter>> {
        let mut filters = Vec::new();

        for rule in acl_rules {
            if self.matches_acl_spec(node, &rule.source_spec).await? &&
               matches!(rule.action, AclAction::Accept) {

                // Convert destination specs to packet filters
                let mut src_ips = Vec::new();
                for dest_spec in &rule.dest_spec {
                    if dest_spec != "*" {
                        src_ips.push(dest_spec.clone());
                    }
                }

                if !src_ips.is_empty() {
                    filters.push(PacketFilter {
                        src_ips,
                        dst_ports: vec![PortRange { first: 0, last: 65535 }],
                    });
                }
            }
        }

        Ok(filters)
    }

    /// Build user profiles for the network map
    async fn build_user_profiles(&self, _node: &Node) -> Result<HashMap<UserId, UserProfile>> {
        // TODO: Implement user profile lookup
        Ok(HashMap::new())
    }

    /// Clean up old cached maps
    async fn cleanup_old_maps(cached_maps: &Arc<RwLock<HashMap<NodeId, CachedNetworkMap>>>) {
        let mut maps = cached_maps.write().await;
        let cutoff = SystemTime::now() - Duration::from_secs(600); // 10 minutes

        maps.retain(|_, cached| cached.generated_at > cutoff);
    }
}