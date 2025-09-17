/// Coordination server core functionality
///
/// This module implements the core coordination server that manages:
/// - Node registration and lifecycle
/// - Key exchange and distribution
/// - Network map generation
/// - Heartbeat monitoring
/// - Session management

pub mod node_manager;
pub mod session_manager;
pub mod network_map;
pub mod key_exchange;
pub mod heartbeat;

use crate::database::DatabaseConnection;
use ghostwire_common::{
    config::ServerConfig,
    error::{Result, GhostWireError},
    types::*,
};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// Core coordination server
pub struct Coordinator {
    config: Arc<ServerConfig>,
    database: Arc<DatabaseConnection>,
    node_manager: Arc<node_manager::NodeManager>,
    session_manager: Arc<session_manager::SessionManager>,
    network_mapper: Arc<network_map::NetworkMapper>,
    heartbeat_monitor: Arc<heartbeat::HeartbeatMonitor>,
}

impl Coordinator {
    /// Create new coordinator instance
    pub async fn new(config: ServerConfig, database: Arc<DatabaseConnection>) -> Result<Self> {
        info!("Initializing GhostWire coordinator");

        let config = Arc::new(config);

        // Initialize components
        let node_manager = Arc::new(
            node_manager::NodeManager::new(database.clone(), config.clone()).await?
        );

        let session_manager = Arc::new(
            session_manager::SessionManager::new(config.clone())
        );

        let network_mapper = Arc::new(
            network_map::NetworkMapper::new(database.clone(), node_manager.clone()).await?
        );

        let heartbeat_monitor = Arc::new(
            heartbeat::HeartbeatMonitor::new(
                database.clone(),
                node_manager.clone(),
                config.network.keepalive_interval,
            )
        );

        Ok(Self {
            config,
            database,
            node_manager,
            session_manager,
            network_mapper,
            heartbeat_monitor,
        })
    }

    /// Start the coordinator services
    pub async fn start(&self) -> Result<()> {
        info!("Starting coordinator services");

        // Start heartbeat monitor
        self.heartbeat_monitor.start().await?;

        // Start network map updater
        self.network_mapper.start_updater().await?;

        info!("Coordinator services started successfully");
        Ok(())
    }

    /// Stop the coordinator services
    pub async fn stop(&self) -> Result<()> {
        info!("Stopping coordinator services");

        self.heartbeat_monitor.stop().await?;
        self.network_mapper.stop_updater().await?;

        info!("Coordinator services stopped");
        Ok(())
    }

    /// Register a new node
    pub async fn register_node(
        &self,
        user_id: UserId,
        request: NodeRegistrationRequest,
    ) -> Result<NodeRegistrationResponse> {
        debug!("Processing node registration for user {}", user_id);

        // Validate the request
        self.validate_registration(&request)?;

        // Register the node
        let node = self.node_manager.register_node(user_id, request).await?;

        // Create session
        let session = self.session_manager.create_session(&node).await?;

        // Generate initial network map
        let network_map = self.network_mapper.generate_map_for_node(&node).await?;

        Ok(NodeRegistrationResponse {
            node_id: node.id,
            ipv4: node.ipv4,
            ipv6: node.ipv6,
            session_token: session.token,
            network_map,
            derp_map: self.get_derp_map(),
        })
    }

    /// Process node heartbeat
    pub async fn process_heartbeat(
        &self,
        node_id: NodeId,
        heartbeat: NodeHeartbeat,
    ) -> Result<HeartbeatResponse> {
        // Update heartbeat timestamp
        self.heartbeat_monitor.record_heartbeat(&node_id).await?;

        // Update node endpoints if changed
        if let Some(endpoints) = heartbeat.endpoints {
            self.node_manager.update_endpoints(&node_id, endpoints).await?;
        }

        // Check if network map needs update
        let needs_map_update = self.network_mapper.check_for_updates(&node_id).await?;

        Ok(HeartbeatResponse {
            network_map: if needs_map_update {
                Some(self.network_mapper.generate_map_for_node_id(&node_id).await?)
            } else {
                None
            },
            next_heartbeat: self.config.network.keepalive_interval.as_secs(),
        })
    }

    /// Unregister a node
    pub async fn unregister_node(&self, node_id: &NodeId) -> Result<()> {
        debug!("Unregistering node {}", node_id);

        // Remove from node manager
        self.node_manager.unregister_node(node_id).await?;

        // Invalidate session
        self.session_manager.invalidate_node_sessions(node_id).await?;

        // Trigger network map updates for affected nodes
        self.network_mapper.handle_node_removal(node_id).await?;

        Ok(())
    }

    /// Get current DERP map
    fn get_derp_map(&self) -> DerpMap {
        // TODO: Implement dynamic DERP map based on relay servers
        DerpMap {
            regions: self.config.derp.regions.clone(),
        }
    }

    /// Validate node registration request
    fn validate_registration(&self, request: &NodeRegistrationRequest) -> Result<()> {
        // Validate public key length
        if request.public_key.len() != 32 {
            return Err(GhostWireError::validation("Invalid public key length"));
        }

        // Validate node name
        if request.name.is_empty() || request.name.len() > 63 {
            return Err(GhostWireError::validation("Invalid node name length"));
        }

        // Validate hostname format if provided
        if !request.name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(GhostWireError::validation("Invalid node name format"));
        }

        Ok(())
    }
}

/// Node registration request
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NodeRegistrationRequest {
    pub name: String,
    pub public_key: Vec<u8>,
    pub endpoints: Vec<Endpoint>,
    pub capabilities: NodeCapabilities,
    pub pre_auth_key: Option<String>,
    pub tags: Vec<String>,
}

/// Node registration response
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NodeRegistrationResponse {
    pub node_id: NodeId,
    pub ipv4: std::net::IpAddr,
    pub ipv6: Option<std::net::IpAddr>,
    pub session_token: String,
    pub network_map: NetworkMap,
    pub derp_map: DerpMap,
}

/// Node heartbeat
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NodeHeartbeat {
    pub endpoints: Option<Vec<Endpoint>>,
    pub stats: Option<NodeStats>,
}

/// Heartbeat response
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HeartbeatResponse {
    pub network_map: Option<NetworkMap>,
    pub next_heartbeat: u64,
}

/// Node statistics
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NodeStats {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub active_connections: u32,
}

/// Node capabilities
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NodeCapabilities {
    pub can_derp: bool,
    pub can_exit_node: bool,
    pub supports_ipv6: bool,
    pub supports_pcp: bool,
    pub supports_pmp: bool,
    pub supports_upnp: bool,
}