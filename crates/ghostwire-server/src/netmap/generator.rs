/// Network map generator
///
/// Generates comprehensive network maps from the current state of nodes,
/// routes, DNS configuration, and policies. Supports incremental delta
/// generation and node-specific filtering.

use crate::netmap::types::*;
use crate::coordinator::Coordinator;
use crate::policy::{PolicyEngine, PolicyRequest, PolicyPrincipal, PolicyResource, PolicyContext};
use ghostwire_common::{
    types::*,
    error::{Result, GhostWireError},
};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::SystemTime;
use tracing::{debug, warn, error};
use uuid::Uuid;

/// Network map generator
#[derive(Clone)]
pub struct NetworkMapGenerator {
    config: crate::netmap::NetworkMapConfig,
    version_counter: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

impl NetworkMapGenerator {
    /// Create a new network map generator
    pub fn new(config: crate::netmap::NetworkMapConfig) -> Self {
        Self {
            config,
            version_counter: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(1)),
        }
    }

    /// Generate a complete network map
    pub async fn generate(&self, coordinator: &Coordinator) -> Result<NetworkMap> {
        let version = self.version_counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);

        debug!("Generating network map version {}", version);

        let mut network_map = NetworkMap::new(version);

        // Generate network configuration
        network_map.network_config = self.generate_network_config(coordinator).await?;

        // Generate nodes
        network_map.nodes = self.generate_nodes(coordinator).await?;

        // Generate routes
        if self.config.include_routes {
            network_map.routes = self.generate_routes(coordinator).await?;
        }

        // Generate DNS configuration
        if self.config.include_dns {
            network_map.dns_config = Some(self.generate_dns_config(coordinator).await?);
        }

        // Generate policies
        if self.config.include_policies {
            network_map.policies = Some(self.generate_policies(coordinator).await?);
        }

        // Generate DERP servers
        network_map.derp_servers = self.generate_derp_servers(coordinator).await?;

        // Update statistics
        network_map.update_stats();

        // Calculate checksum
        network_map.update_checksum()
            .map_err(|e| GhostWireError::internal(format!("Failed to calculate checksum: {}", e)))?;

        debug!("Generated network map with {} nodes, {} routes",
               network_map.nodes.len(), network_map.routes.len());

        Ok(network_map)
    }

    /// Generate a delta between two network maps
    pub fn generate_delta(&self, previous: &NetworkMap, current: &NetworkMap) -> Result<NetworkMapDelta> {
        debug!("Generating delta from version {} to {}", previous.version, current.version);

        let mut operations = Vec::new();

        // Compare nodes
        self.compare_nodes(&previous.nodes, &current.nodes, &mut operations);

        // Compare routes
        self.compare_routes(&previous.routes, &current.routes, &mut operations);

        // Compare DNS configuration
        self.compare_dns_config(
            previous.dns_config.as_ref(),
            current.dns_config.as_ref(),
            &mut operations,
        );

        // Compare network configuration
        if previous.network_config != current.network_config {
            operations.push(DeltaOperation::UpdateNetworkConfig {
                network_config: current.network_config.clone(),
            });
        }

        // Compare DERP servers
        if previous.derp_servers != current.derp_servers {
            operations.push(DeltaOperation::UpdateDerpServers {
                derp_servers: current.derp_servers.clone(),
            });
        }

        let delta = NetworkMapDelta {
            version: current.version,
            previous_version: previous.version,
            generated_at: SystemTime::now(),
            operations,
            checksum: String::new(),
        };

        // Calculate checksum for delta
        let serialized = serde_json::to_string(&delta)
            .map_err(|e| GhostWireError::internal(format!("Failed to serialize delta: {}", e)))?;
        let hash = blake3::hash(serialized.as_bytes());
        let mut delta_with_checksum = delta;
        delta_with_checksum.checksum = hex::encode(hash.as_bytes());

        debug!("Generated delta with {} operations", delta_with_checksum.operations.len());

        Ok(delta_with_checksum)
    }

    /// Filter network map for a specific node
    pub async fn filter_map_for_node(&self, map: &NetworkMap, node_id: &NodeId) -> Result<NetworkMap> {
        debug!("Filtering network map for node {}", node_id);

        let mut filtered_map = map.clone();

        // Filter nodes based on ACL policies
        if self.config.include_policies {
            filtered_map.nodes = self.filter_nodes_by_acl(&map.nodes, node_id).await?;
        }

        // Filter routes
        if self.config.include_routes {
            filtered_map.routes = self.filter_routes_by_acl(&map.routes, node_id).await?;
        }

        // Update statistics for filtered map
        filtered_map.update_stats();

        // Recalculate checksum
        filtered_map.update_checksum()
            .map_err(|e| GhostWireError::internal(format!("Failed to calculate checksum: {}", e)))?;

        Ok(filtered_map)
    }

    /// Filter delta for a specific node
    pub fn filter_delta_for_node(&self, delta: &NetworkMapDelta, node_id: &NodeId) -> Result<NetworkMapDelta> {
        // For now, return the full delta
        // In a real implementation, we'd filter operations based on ACL
        Ok(delta.clone())
    }

    // Private helper methods

    async fn generate_network_config(&self, coordinator: &Coordinator) -> Result<NetworkConfig> {
        // Get network configuration from coordinator
        let network_info = coordinator.get_network_info().await?;

        Ok(NetworkConfig {
            name: network_info.name,
            ipv4_pool: network_info.ipv4_pool,
            ipv6_pool: network_info.ipv6_pool,
            default_routes: network_info.default_routes,
            settings: NetworkSettings {
                enable_ipv6: network_info.enable_ipv6,
                enable_magic_dns: network_info.enable_magic_dns,
                enable_ssh: network_info.enable_ssh,
                keepalive_seconds: network_info.keepalive_seconds,
                mtu: network_info.mtu,
                encryption: EncryptionSettings {
                    algorithm: "ChaCha20-Poly1305".to_string(),
                    key_rotation_hours: 24,
                    forward_secrecy: true,
                },
            },
        })
    }

    async fn generate_nodes(&self, coordinator: &Coordinator) -> Result<Vec<NetworkNode>> {
        let nodes = coordinator.list_nodes().await?;

        let mut network_nodes = Vec::new();

        for node in nodes {
            let network_node = NetworkNode {
                id: node.id,
                name: node.name,
                owner: node.owner,
                ipv4: node.ipv4,
                ipv6: node.ipv6,
                public_key: node.public_key,
                endpoints: node.endpoints,
                capabilities: NodeCapabilities {
                    can_route: node.capabilities.can_route,
                    can_advertise_routes: node.capabilities.can_advertise_routes,
                    supports_ssh: node.capabilities.supports_ssh,
                    supports_derp: node.capabilities.supports_derp,
                    operating_system: node.capabilities.operating_system,
                    client_version: node.capabilities.client_version,
                    features: node.capabilities.features,
                },
                online: node.online,
                last_seen: node.last_seen,
                tags: node.tags,
                settings: NodeSettings {
                    mtu: node.settings.mtu,
                    keepalive_seconds: node.settings.keepalive_seconds,
                    exit_node_preference: node.settings.exit_node_preference,
                    dns_override: node.settings.dns_override,
                    accept_routes: node.settings.accept_routes,
                    accept_dns: node.settings.accept_dns,
                },
                connection_info: ConnectionInfo {
                    preferred_derp: node.connection_info.preferred_derp,
                    direct_connection: node.connection_info.direct_connection,
                    quality_metrics: node.connection_info.quality_metrics.map(|qm| QualityMetrics {
                        rtt_ms: qm.rtt_ms,
                        packet_loss: qm.packet_loss,
                        jitter_ms: qm.jitter_ms,
                        bandwidth_bps: qm.bandwidth_bps,
                    }),
                    bandwidth_limits: node.connection_info.bandwidth_limits.map(|bl| BandwidthLimits {
                        upload_bps: bl.upload_bps,
                        download_bps: bl.download_bps,
                        burst_bytes: bl.burst_bytes,
                    }),
                },
            };

            network_nodes.push(network_node);
        }

        Ok(network_nodes)
    }

    async fn generate_routes(&self, coordinator: &Coordinator) -> Result<Vec<RouteAdvertisement>> {
        let route_advertisements = coordinator.get_route_advertisements().await?;

        let mut network_routes = Vec::new();

        for route_ad in route_advertisements {
            let network_route = RouteAdvertisement {
                node_id: route_ad.node_id,
                routes: route_ad.routes.into_iter().map(|r| Route {
                    prefix: r.prefix,
                    enabled: r.enabled,
                    description: r.description,
                    tags: r.tags,
                }).collect(),
                advertised_at: route_ad.advertised_at,
                priority: route_ad.priority,
                metrics: RouteMetrics {
                    cost: route_ad.metrics.cost,
                    hop_count: route_ad.metrics.hop_count,
                    reliability: route_ad.metrics.reliability,
                    bandwidth_bps: route_ad.metrics.bandwidth_bps,
                },
            };

            network_routes.push(network_route);
        }

        Ok(network_routes)
    }

    async fn generate_dns_config(&self, coordinator: &Coordinator) -> Result<DnsConfig> {
        let dns_info = coordinator.get_dns_config().await?;

        Ok(DnsConfig {
            servers: dns_info.servers,
            search_domains: dns_info.search_domains,
            records: dns_info.records.into_iter().map(|r| DnsRecord {
                name: r.name,
                record_type: match r.record_type.as_str() {
                    "A" => DnsRecordType::A,
                    "AAAA" => DnsRecordType::Aaaa,
                    "CNAME" => DnsRecordType::Cname,
                    "MX" => DnsRecordType::Mx,
                    "TXT" => DnsRecordType::Txt,
                    "SRV" => DnsRecordType::Srv,
                    "PTR" => DnsRecordType::Ptr,
                    _ => DnsRecordType::A, // Default fallback
                },
                value: r.value,
                ttl: r.ttl,
                tags: r.tags,
            }).collect(),
            settings: DnsSettings {
                enable_split_dns: dns_info.settings.enable_split_dns,
                internal_domains: dns_info.settings.internal_domains,
                fallback_to_public: dns_info.settings.fallback_to_public,
                cache_ttl_seconds: dns_info.settings.cache_ttl_seconds,
            },
        })
    }

    async fn generate_policies(&self, coordinator: &Coordinator) -> Result<Vec<NetworkPolicy>> {
        let policies = coordinator.get_active_policies().await?;

        let network_policies = policies.into_iter().map(|policy| NetworkPolicy {
            id: policy.id,
            name: policy.name,
            rules: policy.rules.into_iter().map(|rule| PolicyRuleRef {
                id: rule.id,
                effect: rule.effect,
                priority: rule.priority,
                summary: rule.summary,
            }).collect(),
            version: policy.version,
        }).collect();

        Ok(network_policies)
    }

    async fn generate_derp_servers(&self, coordinator: &Coordinator) -> Result<Vec<DerpServer>> {
        let derp_config = coordinator.get_derp_config().await?;

        let derp_servers = derp_config.regions.into_iter().map(|region| DerpServer {
            region_id: region.region_id,
            region_name: region.region_name,
            nodes: region.nodes.into_iter().map(|node| DerpNode {
                id: node.id,
                hostname: node.hostname,
                ipv4: node.ipv4,
                ipv6: node.ipv6,
                stun_port: node.stun_port,
                https_port: node.https_port,
                capabilities: node.capabilities,
            }).collect(),
            metadata: DerpRegionMetadata {
                location: region.metadata.location,
                coordinates: region.metadata.coordinates.map(|c| Coordinates {
                    latitude: c.latitude,
                    longitude: c.longitude,
                }),
                avoid: region.metadata.avoid,
                tags: region.metadata.tags,
            },
        }).collect();

        Ok(derp_servers)
    }

    fn compare_nodes(&self, previous: &[NetworkNode], current: &[NetworkNode], operations: &mut Vec<DeltaOperation>) {
        let mut previous_map: HashMap<NodeId, &NetworkNode> = HashMap::new();
        let mut current_map: HashMap<NodeId, &NetworkNode> = HashMap::new();

        for node in previous {
            previous_map.insert(node.id, node);
        }

        for node in current {
            current_map.insert(node.id, node);
        }

        // Find added nodes
        for (node_id, node) in &current_map {
            if !previous_map.contains_key(node_id) {
                operations.push(DeltaOperation::AddNode {
                    node: (*node).clone(),
                });
            }
        }

        // Find removed nodes
        for node_id in previous_map.keys() {
            if !current_map.contains_key(node_id) {
                operations.push(DeltaOperation::RemoveNode {
                    node_id: *node_id,
                });
            }
        }

        // Find updated nodes
        for (node_id, current_node) in &current_map {
            if let Some(previous_node) = previous_map.get(node_id) {
                if let Some(changes) = self.detect_node_changes(previous_node, current_node) {
                    operations.push(DeltaOperation::UpdateNode {
                        node_id: *node_id,
                        changes,
                    });
                }
            }
        }
    }

    fn detect_node_changes(&self, previous: &NetworkNode, current: &NetworkNode) -> Option<NodeChanges> {
        let mut changes = NodeChanges {
            endpoints: None,
            online: None,
            last_seen: None,
            tags: None,
            settings: None,
            connection_info: None,
        };

        let mut has_changes = false;

        if previous.endpoints != current.endpoints {
            changes.endpoints = Some(current.endpoints.clone());
            has_changes = true;
        }

        if previous.online != current.online {
            changes.online = Some(current.online);
            has_changes = true;
        }

        if previous.last_seen != current.last_seen {
            changes.last_seen = Some(current.last_seen);
            has_changes = true;
        }

        if previous.tags != current.tags {
            changes.tags = Some(current.tags.clone());
            has_changes = true;
        }

        if previous.settings != current.settings {
            changes.settings = Some(current.settings.clone());
            has_changes = true;
        }

        if previous.connection_info != current.connection_info {
            changes.connection_info = Some(current.connection_info.clone());
            has_changes = true;
        }

        if has_changes {
            Some(changes)
        } else {
            None
        }
    }

    fn compare_routes(&self, previous: &[RouteAdvertisement], current: &[RouteAdvertisement], operations: &mut Vec<DeltaOperation>) {
        let mut previous_map: HashMap<NodeId, &RouteAdvertisement> = HashMap::new();
        let mut current_map: HashMap<NodeId, &RouteAdvertisement> = HashMap::new();

        for route in previous {
            previous_map.insert(route.node_id, route);
        }

        for route in current {
            current_map.insert(route.node_id, route);
        }

        // Find added routes
        for (node_id, route) in &current_map {
            if !previous_map.contains_key(node_id) {
                operations.push(DeltaOperation::AddRoute {
                    route: (*route).clone(),
                });
            }
        }

        // Find removed routes
        for node_id in previous_map.keys() {
            if !current_map.contains_key(node_id) {
                operations.push(DeltaOperation::RemoveRoute {
                    node_id: *node_id,
                });
            }
        }

        // Find updated routes
        for (node_id, current_route) in &current_map {
            if let Some(previous_route) = previous_map.get(node_id) {
                if let Some(changes) = self.detect_route_changes(previous_route, current_route) {
                    operations.push(DeltaOperation::UpdateRoute {
                        node_id: *node_id,
                        changes,
                    });
                }
            }
        }
    }

    fn detect_route_changes(&self, previous: &RouteAdvertisement, current: &RouteAdvertisement) -> Option<RouteChanges> {
        let mut changes = RouteChanges {
            routes: None,
            priority: None,
            metrics: None,
        };

        let mut has_changes = false;

        if previous.routes != current.routes {
            changes.routes = Some(current.routes.clone());
            has_changes = true;
        }

        if previous.priority != current.priority {
            changes.priority = Some(current.priority);
            has_changes = true;
        }

        if previous.metrics != current.metrics {
            changes.metrics = Some(current.metrics.clone());
            has_changes = true;
        }

        if has_changes {
            Some(changes)
        } else {
            None
        }
    }

    fn compare_dns_config(
        &self,
        previous: Option<&DnsConfig>,
        current: Option<&DnsConfig>,
        operations: &mut Vec<DeltaOperation>,
    ) {
        match (previous, current) {
            (None, Some(current_dns)) => {
                operations.push(DeltaOperation::UpdateDns {
                    dns_config: current_dns.clone(),
                });
            }
            (Some(previous_dns), Some(current_dns)) => {
                if previous_dns != current_dns {
                    operations.push(DeltaOperation::UpdateDns {
                        dns_config: current_dns.clone(),
                    });
                }
            }
            (Some(_), None) => {
                // DNS config removed - could add a RemoveDns operation
                // For now, we'll send an empty DNS config
                operations.push(DeltaOperation::UpdateDns {
                    dns_config: DnsConfig {
                        servers: vec![],
                        search_domains: vec![],
                        records: vec![],
                        settings: DnsSettings {
                            enable_split_dns: false,
                            internal_domains: vec![],
                            fallback_to_public: true,
                            cache_ttl_seconds: 300,
                        },
                    },
                });
            }
            (None, None) => {
                // No change
            }
        }
    }

    async fn filter_nodes_by_acl(&self, nodes: &[NetworkNode], requesting_node_id: &NodeId) -> Result<Vec<NetworkNode>> {
        // For now, return all nodes
        // In a real implementation, we'd check ACL policies
        Ok(nodes.to_vec())
    }

    async fn filter_routes_by_acl(&self, routes: &[RouteAdvertisement], requesting_node_id: &NodeId) -> Result<Vec<RouteAdvertisement>> {
        // For now, return all routes
        // In a real implementation, we'd check ACL policies
        Ok(routes.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn create_test_node(id: NodeId, name: &str, online: bool) -> NetworkNode {
        NetworkNode {
            id,
            name: name.to_string(),
            owner: Uuid::new_v4(),
            ipv4: Ipv4Addr::new(100, 64, 0, 1),
            ipv6: None,
            public_key: PublicKey([0u8; 32]),
            endpoints: vec![],
            capabilities: NodeCapabilities {
                can_route: false,
                can_advertise_routes: false,
                supports_ssh: true,
                supports_derp: true,
                operating_system: "Linux".to_string(),
                client_version: "1.0.0".to_string(),
                features: vec![],
            },
            online,
            last_seen: SystemTime::now(),
            tags: vec![],
            settings: NodeSettings {
                mtu: None,
                keepalive_seconds: None,
                exit_node_preference: None,
                dns_override: None,
                accept_routes: true,
                accept_dns: true,
            },
            connection_info: ConnectionInfo {
                preferred_derp: None,
                direct_connection: false,
                quality_metrics: None,
                bandwidth_limits: None,
            },
        }
    }

    #[test]
    fn test_network_map_generator_creation() {
        let config = crate::netmap::NetworkMapConfig::default();
        let generator = NetworkMapGenerator::new(config);

        // Version counter should start at 1
        let version = generator.version_counter.load(std::sync::atomic::Ordering::SeqCst);
        assert_eq!(version, 1);
    }

    #[test]
    fn test_detect_node_changes() {
        let config = crate::netmap::NetworkMapConfig::default();
        let generator = NetworkMapGenerator::new(config);

        let node1 = create_test_node(Uuid::new_v4(), "test1", true);
        let mut node2 = node1.clone();
        node2.online = false;

        let changes = generator.detect_node_changes(&node1, &node2);
        assert!(changes.is_some());

        let changes = changes.unwrap();
        assert_eq!(changes.online, Some(false));
    }

    #[test]
    fn test_compare_nodes() {
        let config = crate::netmap::NetworkMapConfig::default();
        let generator = NetworkMapGenerator::new(config);

        let node1 = create_test_node(Uuid::new_v4(), "test1", true);
        let node2 = create_test_node(Uuid::new_v4(), "test2", true);

        let previous = vec![node1.clone()];
        let current = vec![node1.clone(), node2.clone()];

        let mut operations = Vec::new();
        generator.compare_nodes(&previous, &current, &mut operations);

        assert_eq!(operations.len(), 1);
        assert!(matches!(operations[0], DeltaOperation::AddNode { .. }));
    }

    #[test]
    fn test_delta_generation() {
        let config = crate::netmap::NetworkMapConfig::default();
        let generator = NetworkMapGenerator::new(config);

        let mut map1 = NetworkMap::new(1);
        let mut map2 = NetworkMap::new(2);

        // Add a node to the second map
        let node = create_test_node(Uuid::new_v4(), "test", true);
        map2.nodes.push(node);

        let delta = generator.generate_delta(&map1, &map2).unwrap();

        assert_eq!(delta.version, 2);
        assert_eq!(delta.previous_version, 1);
        assert_eq!(delta.operations.len(), 1);
        assert!(matches!(delta.operations[0], DeltaOperation::AddNode { .. }));
    }
}