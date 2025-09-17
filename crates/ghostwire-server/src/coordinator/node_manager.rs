/// Node lifecycle management
///
/// Handles node registration, updates, and removal with:
/// - IP address allocation
/// - Key management
/// - Endpoint tracking
/// - Online/offline status

use crate::database::{DatabaseConnection, NodeOperations};
use ghostwire_common::{
    config::ServerConfig,
    error::{Result, GhostWireError},
    types::*,
};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::SystemTime;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// Node manager for lifecycle operations
pub struct NodeManager {
    database: Arc<DatabaseConnection>,
    config: Arc<ServerConfig>,
    nodes: Arc<RwLock<HashMap<NodeId, Node>>>,
    ip_allocator: Arc<RwLock<IpAllocator>>,
}

impl NodeManager {
    /// Create new node manager
    pub async fn new(database: Arc<DatabaseConnection>, config: Arc<ServerConfig>) -> Result<Self> {
        // Load existing nodes from database
        let all_nodes = NodeOperations::list_all(&database).await?;

        let mut nodes = HashMap::new();
        let mut allocated_ips = Vec::new();

        for node in all_nodes {
            allocated_ips.push(node.ipv4);
            if let Some(ipv6) = node.ipv6 {
                allocated_ips.push(ipv6);
            }
            nodes.insert(node.id, node);
        }

        // Initialize IP allocator
        let ip_allocator = IpAllocator::new(
            config.network.ipv4_range.clone(),
            config.network.ipv6_range.clone(),
            allocated_ips,
        )?;

        Ok(Self {
            database,
            config,
            nodes: Arc::new(RwLock::new(nodes)),
            ip_allocator: Arc::new(RwLock::new(ip_allocator)),
        })
    }

    /// Register a new node
    pub async fn register_node(
        &self,
        user_id: UserId,
        request: super::NodeRegistrationRequest,
    ) -> Result<Node> {
        // Allocate IP addresses
        let ipv4 = self.ip_allocator.write().await.allocate_ipv4()?;
        let ipv6 = if request.capabilities.supports_ipv6 {
            Some(self.ip_allocator.write().await.allocate_ipv6()?)
        } else {
            None
        };

        // Create node
        let node = Node {
            id: uuid::Uuid::new_v4(),
            user_id,
            name: request.name,
            public_key: PublicKey(request.public_key.try_into().map_err(|_| {
                GhostWireError::validation("Invalid public key size")
            })?),
            ipv4,
            ipv6,
            endpoints: request.endpoints,
            allowed_ips: vec![ipv4.to_string(), ipv6.map(|ip| ip.to_string()).unwrap_or_default()]
                .into_iter()
                .filter(|s| !s.is_empty())
                .collect(),
            routes: Vec::new(),
            tags: request.tags,
            created_at: SystemTime::now(),
            last_seen: SystemTime::now(),
            expires_at: None,
            online: true,
        };

        // Save to database
        NodeOperations::create(&self.database, &node).await?;

        // Add to cache
        self.nodes.write().await.insert(node.id, node.clone());

        info!("Registered node {} ({}) for user {}", node.id, node.name, user_id);

        Ok(node)
    }

    /// Unregister a node
    pub async fn unregister_node(&self, node_id: &NodeId) -> Result<()> {
        // Remove from cache
        let node = self.nodes.write().await.remove(node_id);

        if let Some(node) = node {
            // Free IP addresses
            self.ip_allocator.write().await.free_ip(node.ipv4);
            if let Some(ipv6) = node.ipv6 {
                self.ip_allocator.write().await.free_ip(ipv6);
            }

            // Remove from database
            NodeOperations::delete(&self.database, node_id).await?;

            info!("Unregistered node {} ({})", node_id, node.name);
        } else {
            warn!("Attempted to unregister unknown node {}", node_id);
        }

        Ok(())
    }

    /// Update node endpoints
    pub async fn update_endpoints(&self, node_id: &NodeId, endpoints: Vec<Endpoint>) -> Result<()> {
        // Update in cache
        if let Some(node) = self.nodes.write().await.get_mut(node_id) {
            node.endpoints = endpoints.clone();
            node.last_seen = SystemTime::now();
        }

        // Update in database
        NodeOperations::update_endpoints(&self.database, node_id, endpoints).await?;

        debug!("Updated endpoints for node {}", node_id);
        Ok(())
    }

    /// Mark node as online
    pub async fn mark_online(&self, node_id: &NodeId) -> Result<()> {
        // Update cache
        if let Some(node) = self.nodes.write().await.get_mut(node_id) {
            node.online = true;
            node.last_seen = SystemTime::now();
        }

        // Update database
        NodeOperations::update_online_status(&self.database, node_id, true).await?;

        debug!("Marked node {} as online", node_id);
        Ok(())
    }

    /// Mark node as offline
    pub async fn mark_offline(&self, node_id: &NodeId) -> Result<()> {
        // Update cache
        if let Some(node) = self.nodes.write().await.get_mut(node_id) {
            node.online = false;
        }

        // Update database
        NodeOperations::update_online_status(&self.database, node_id, false).await?;

        debug!("Marked node {} as offline", node_id);
        Ok(())
    }

    /// Get node by ID
    pub async fn get_node(&self, node_id: &NodeId) -> Result<Option<Node>> {
        Ok(self.nodes.read().await.get(node_id).cloned())
    }

    /// Get all nodes for a user
    pub async fn get_user_nodes(&self, user_id: &UserId) -> Result<Vec<Node>> {
        let nodes = self.nodes.read().await;
        Ok(nodes
            .values()
            .filter(|n| n.user_id == *user_id)
            .cloned()
            .collect())
    }

    /// Get all online nodes
    pub async fn get_online_nodes(&self) -> Result<Vec<Node>> {
        let nodes = self.nodes.read().await;
        Ok(nodes
            .values()
            .filter(|n| n.online)
            .cloned()
            .collect())
    }

    /// Check if a public key is already registered
    pub async fn is_key_registered(&self, public_key: &PublicKey) -> bool {
        self.nodes
            .read()
            .await
            .values()
            .any(|n| n.public_key == *public_key)
    }
}

/// IP address allocator
struct IpAllocator {
    ipv4_range: cidr::Ipv4Cidr,
    ipv6_range: Option<cidr::Ipv6Cidr>,
    allocated: Vec<IpAddr>,
    next_ipv4: u32,
    next_ipv6: u128,
}

impl IpAllocator {
    /// Create new IP allocator
    fn new(
        ipv4_range: String,
        ipv6_range: Option<String>,
        allocated: Vec<IpAddr>,
    ) -> Result<Self> {
        let ipv4_range = ipv4_range
            .parse::<cidr::Ipv4Cidr>()
            .map_err(|e| GhostWireError::config(format!("Invalid IPv4 range: {}", e)))?;

        let ipv6_range = ipv6_range
            .map(|s| {
                s.parse::<cidr::Ipv6Cidr>()
                    .map_err(|e| GhostWireError::config(format!("Invalid IPv6 range: {}", e)))
            })
            .transpose()?;

        // Find next available IPs
        let mut next_ipv4 = u32::from(ipv4_range.first_address()) + 1; // Skip network address
        let mut next_ipv6 = ipv6_range
            .as_ref()
            .map(|r| u128::from(r.first_address()) + 1)
            .unwrap_or(0);

        // Skip allocated IPs
        for ip in &allocated {
            match ip {
                IpAddr::V4(v4) => {
                    let ip_val = u32::from(*v4);
                    if ip_val >= next_ipv4 && ipv4_range.contains(v4) {
                        next_ipv4 = ip_val + 1;
                    }
                }
                IpAddr::V6(v6) => {
                    let ip_val = u128::from(*v6);
                    if ip_val >= next_ipv6 {
                        if let Some(range) = &ipv6_range {
                            if range.contains(v6) {
                                next_ipv6 = ip_val + 1;
                            }
                        }
                    }
                }
            }
        }

        Ok(Self {
            ipv4_range,
            ipv6_range,
            allocated,
            next_ipv4,
            next_ipv6,
        })
    }

    /// Allocate next IPv4 address
    fn allocate_ipv4(&mut self) -> Result<IpAddr> {
        let last = u32::from(self.ipv4_range.last_address());

        // Find next available
        while self.next_ipv4 <= last {
            let ip = Ipv4Addr::from(self.next_ipv4);
            self.next_ipv4 += 1;

            if !self.allocated.contains(&IpAddr::V4(ip)) {
                self.allocated.push(IpAddr::V4(ip));
                return Ok(IpAddr::V4(ip));
            }
        }

        Err(GhostWireError::resource_exhausted("IPv4 address pool exhausted"))
    }

    /// Allocate next IPv6 address
    fn allocate_ipv6(&mut self) -> Result<IpAddr> {
        let range = self
            .ipv6_range
            .as_ref()
            .ok_or_else(|| GhostWireError::config("IPv6 not configured"))?;

        let last = u128::from(range.last_address());

        // Find next available
        while self.next_ipv6 <= last {
            let ip = Ipv6Addr::from(self.next_ipv6);
            self.next_ipv6 += 1;

            if !self.allocated.contains(&IpAddr::V6(ip)) {
                self.allocated.push(IpAddr::V6(ip));
                return Ok(IpAddr::V6(ip));
            }
        }

        Err(GhostWireError::resource_exhausted("IPv6 address pool exhausted"))
    }

    /// Free an IP address
    fn free_ip(&mut self, ip: IpAddr) {
        self.allocated.retain(|&a| a != ip);

        // Reset next counters if we freed a lower address
        match ip {
            IpAddr::V4(v4) => {
                let ip_val = u32::from(v4);
                if ip_val < self.next_ipv4 && self.ipv4_range.contains(&v4) {
                    self.next_ipv4 = ip_val;
                }
            }
            IpAddr::V6(v6) => {
                let ip_val = u128::from(v6);
                if ip_val < self.next_ipv6 {
                    if let Some(range) = &self.ipv6_range {
                        if range.contains(&v6) {
                            self.next_ipv6 = ip_val;
                        }
                    }
                }
            }
        }
    }
}