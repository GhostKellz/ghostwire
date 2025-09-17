/// GhostWire client implementation
///
/// Core client daemon that manages WireGuard and QUIC connections,
/// handles authentication, and provides seamless mesh connectivity.

use crate::config::ClientConfig;
use crate::transport::{TransportManager, TransportEvent};
use crate::auth::AuthManager;
use crate::tunnel::TunnelManager;
use crate::platform::PlatformManager;

use ghostwire_common::{
    types::*,
    error::{Result, GhostWireError},
};
use ghostwire_proto::coordination::{
    coordination_client::CoordinationClient,
    RegisterNodeRequest, NodeHeartbeatRequest, GetNetworkMapRequest,
};

use std::sync::Arc;
use std::time::{SystemTime, Duration, Instant};
use tokio::sync::{RwLock, broadcast, mpsc, Mutex};
use tokio::time::{interval, timeout, sleep};
use tracing::{info, warn, error, debug};
use uuid::Uuid;

/// Client state
#[derive(Debug, Clone, PartialEq)]
pub enum ClientState {
    Disconnected,
    Connecting,
    Authenticating,
    Registering,
    Connected,
    Reconnecting,
    Stopping,
    Error(String),
}

/// Main GhostWire client
pub struct GhostWireClient {
    config: ClientConfig,
    state: Arc<RwLock<ClientState>>,
    node_id: Arc<Mutex<Option<NodeId>>>,
    start_time: Instant,
    shutdown_sender: Option<broadcast::Sender<()>>,

    // Core components
    auth_manager: Arc<AuthManager>,
    transport_manager: Arc<TransportManager>,
    tunnel_manager: Arc<TunnelManager>,
    platform_manager: Arc<PlatformManager>,

    // Statistics
    stats: Arc<RwLock<ClientStats>>,

    // Network state
    network_map: Arc<RwLock<Option<NetworkMap>>>,
    peers: Arc<RwLock<Vec<PeerInfo>>>,
}

#[derive(Debug, Clone, Default)]
pub struct ClientStats {
    pub uptime_seconds: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub connection_attempts: u64,
    pub successful_connections: u64,
    pub failed_connections: u64,
    pub last_connected: Option<SystemTime>,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub node_id: NodeId,
    pub name: String,
    pub ipv4: std::net::Ipv4Addr,
    pub ipv6: Option<std::net::Ipv6Addr>,
    pub public_key: String,
    pub endpoint: Option<std::net::SocketAddr>,
    pub last_seen: SystemTime,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub latency_ms: Option<f64>,
    pub connected: bool,
    pub derp_region: Option<u16>,
}

impl GhostWireClient {
    /// Create a new GhostWire client
    pub async fn new(config: ClientConfig) -> Result<Self> {
        info!("Initializing GhostWire client");

        let state = Arc::new(RwLock::new(ClientState::Disconnected));
        let node_id = Arc::new(Mutex::new(None));
        let start_time = Instant::now();

        // Initialize managers
        let auth_manager = Arc::new(AuthManager::new(config.auth.clone()).await?);
        let transport_manager = Arc::new(TransportManager::new(config.transport.clone()).await?);
        let tunnel_manager = Arc::new(TunnelManager::new(config.transport.interface.clone()).await?);
        let platform_manager = Arc::new(PlatformManager::new(config.platform.clone()).await?);

        let stats = Arc::new(RwLock::new(ClientStats::default()));
        let network_map = Arc::new(RwLock::new(None));
        let peers = Arc::new(RwLock::new(Vec::new()));

        info!("GhostWire client initialized successfully");

        Ok(Self {
            config,
            state,
            node_id,
            start_time,
            shutdown_sender: None,
            auth_manager,
            transport_manager,
            tunnel_manager,
            platform_manager,
            stats,
            network_map,
            peers,
        })
    }

    /// Start the client
    pub async fn start(&mut self) -> Result<()> {
        info!("Starting GhostWire client");

        *self.state.write().await = ClientState::Connecting;

        // Create shutdown channel
        let (shutdown_tx, _) = broadcast::channel(1);
        self.shutdown_sender = Some(shutdown_tx.clone());

        // Start managers
        self.platform_manager.start().await?;
        self.tunnel_manager.start().await?;
        self.transport_manager.start().await?;

        // Start background tasks
        self.start_connection_manager(shutdown_tx.clone()).await;
        self.start_heartbeat_task(shutdown_tx.clone()).await;
        self.start_network_map_sync(shutdown_tx.clone()).await;
        self.start_stats_collector(shutdown_tx.clone()).await;
        self.start_transport_handler(shutdown_tx).await;

        info!("GhostWire client started successfully");
        Ok(())
    }

    /// Stop the client
    pub async fn stop(&mut self) -> Result<()> {
        info!("Stopping GhostWire client");

        *self.state.write().await = ClientState::Stopping;

        // Send shutdown signal
        if let Some(sender) = &self.shutdown_sender {
            let _ = sender.send(());
        }

        // Stop managers
        self.transport_manager.stop().await?;
        self.tunnel_manager.stop().await?;
        self.platform_manager.stop().await?;

        *self.state.write().await = ClientState::Disconnected;

        info!("GhostWire client stopped");
        Ok(())
    }

    /// Get current state
    pub async fn get_state(&self) -> ClientState {
        self.state.read().await.clone()
    }

    /// Get client statistics
    pub async fn get_stats(&self) -> ClientStats {
        let mut stats = self.stats.read().await.clone();
        stats.uptime_seconds = self.start_time.elapsed().as_secs();
        stats
    }

    /// Get peer information
    pub async fn get_peers(&self) -> Vec<PeerInfo> {
        self.peers.read().await.clone()
    }

    /// Get network map
    pub async fn get_network_map(&self) -> Option<NetworkMap> {
        self.network_map.read().await.clone()
    }

    // Private implementation methods

    async fn start_connection_manager(&self, shutdown_tx: broadcast::Sender<()>) {
        let client = self.clone();
        let mut shutdown_rx = shutdown_tx.subscribe();

        tokio::spawn(async move {
            let mut retry_count = 0;
            let mut next_retry = Instant::now();

            loop {
                tokio::select! {
                    _ = sleep(Duration::from_millis(100)) => {
                        let state = client.state.read().await.clone();

                        match state {
                            ClientState::Disconnected | ClientState::Reconnecting => {
                                if Instant::now() >= next_retry {
                                    retry_count += 1;
                                    let delay = client.calculate_retry_delay(retry_count);

                                    match client.attempt_connection().await {
                                        Ok(()) => {
                                            retry_count = 0;
                                            next_retry = Instant::now();
                                        }
                                        Err(e) => {
                                            error!("Connection attempt failed: {}", e);
                                            next_retry = Instant::now() + delay;
                                            *client.state.write().await = ClientState::Reconnecting;

                                            // Update stats
                                            let mut stats = client.stats.write().await;
                                            stats.failed_connections += 1;
                                            stats.last_error = Some(e.to_string());
                                        }
                                    }
                                }
                            }
                            ClientState::Error(_) => {
                                if Instant::now() >= next_retry {
                                    *client.state.write().await = ClientState::Disconnected;
                                }
                            }
                            _ => {
                                retry_count = 0;
                                next_retry = Instant::now();
                            }
                        }
                    }
                    _ = shutdown_rx.recv() => {
                        debug!("Connection manager stopped");
                        break;
                    }
                }
            }
        });
    }

    fn calculate_retry_delay(&self, attempt: u32) -> Duration {
        let base_delay = Duration::from_secs(self.config.server.retry.initial_delay_seconds);
        let max_delay = Duration::from_secs(self.config.server.retry.max_delay_seconds);

        let delay = base_delay.as_secs() as f64 * self.config.server.retry.backoff_multiplier.powi(attempt as i32 - 1);
        let delay = Duration::from_secs(delay.min(max_delay.as_secs() as f64) as u64);

        if self.config.server.retry.jitter {
            let jitter = Duration::from_millis(rand::random::<u64>() % 1000);
            delay + jitter
        } else {
            delay
        }
    }

    async fn attempt_connection(&self) -> Result<()> {
        *self.state.write().await = ClientState::Connecting;

        // Update stats
        self.stats.write().await.connection_attempts += 1;

        // Authenticate
        *self.state.write().await = ClientState::Authenticating;
        self.auth_manager.authenticate().await?;

        // Register node
        *self.state.write().await = ClientState::Registering;
        let node_id = self.register_node().await?;
        *self.node_id.lock().await = Some(node_id);

        // Get initial network map
        self.sync_network_map().await?;

        // Configure transport
        self.configure_transport().await?;

        *self.state.write().await = ClientState::Connected;

        // Update stats
        let mut stats = self.stats.write().await;
        stats.successful_connections += 1;
        stats.last_connected = Some(SystemTime::now());

        info!("Successfully connected to GhostWire network");
        Ok(())
    }

    async fn register_node(&self) -> Result<NodeId> {
        let token = self.auth_manager.get_token().await?;
        let mut client = self.create_grpc_client().await?;

        let node_name = self.config.node.name.clone()
            .unwrap_or_else(|| format!("node-{}", uuid::Uuid::new_v4()));

        let public_key = self.transport_manager.get_public_key().await?;

        let request = RegisterNodeRequest {
            name: node_name,
            public_key,
            tags: self.config.node.tags.clone(),
            exit_node: self.config.node.exit_node,
            advertise_routes: self.config.node.advertise_routes.clone(),
            attributes: self.config.node.attributes.clone(),
        };

        let response = client.register_node(request).await
            .map_err(|e| GhostWireError::network(format!("Node registration failed: {}", e)))?
            .into_inner();

        info!("Node registered with ID: {}", response.node_id);
        Ok(NodeId::from(response.node_id))
    }

    async fn sync_network_map(&self) -> Result<()> {
        let token = self.auth_manager.get_token().await?;
        let mut client = self.create_grpc_client().await?;

        let request = GetNetworkMapRequest {};

        let response = client.get_network_map(request).await
            .map_err(|e| GhostWireError::network(format!("Failed to get network map: {}", e)))?
            .into_inner();

        // Update network map
        if let Some(network_map) = response.network_map {
            *self.network_map.write().await = Some(NetworkMap::from(network_map));

            // Update peers
            self.update_peers_from_network_map().await?;

            debug!("Network map synchronized");
        }

        Ok(())
    }

    async fn update_peers_from_network_map(&self) -> Result<()> {
        let network_map = self.network_map.read().await;
        if let Some(ref map) = *network_map {
            let mut peers = Vec::new();

            for node in &map.nodes {
                if Some(node.id) != *self.node_id.lock().await {
                    let peer = PeerInfo {
                        node_id: node.id,
                        name: node.name.clone(),
                        ipv4: node.ipv4,
                        ipv6: node.ipv6,
                        public_key: node.public_key.clone(),
                        endpoint: node.endpoint,
                        last_seen: SystemTime::now(),
                        bytes_sent: 0,
                        bytes_received: 0,
                        latency_ms: None,
                        connected: false,
                        derp_region: node.derp_region,
                    };
                    peers.push(peer);
                }
            }

            *self.peers.write().await = peers;
        }

        Ok(())
    }

    async fn configure_transport(&self) -> Result<()> {
        let network_map = self.network_map.read().await;
        if let Some(ref map) = *network_map {
            self.transport_manager.configure_peers(&map.nodes).await?;
        }
        Ok(())
    }

    async fn create_grpc_client(&self) -> Result<CoordinationClient<tonic::transport::Channel>> {
        let url = format!("{}:{}",
            self.config.server.url,
            self.config.server.grpc_port.unwrap_or(50051));

        let channel = tonic::transport::Channel::from_shared(url)
            .map_err(|e| GhostWireError::configuration(format!("Invalid server URL: {}", e)))?
            .timeout(Duration::from_secs(self.config.server.timeout_seconds))
            .connect()
            .await
            .map_err(|e| GhostWireError::network(format!("Failed to connect to server: {}", e)))?;

        Ok(CoordinationClient::new(channel))
    }

    async fn start_heartbeat_task(&self, shutdown_tx: broadcast::Sender<()>) {
        let client = self.clone();
        let mut shutdown_rx = shutdown_tx.subscribe();

        tokio::spawn(async move {
            let mut heartbeat_interval = interval(Duration::from_secs(30));

            loop {
                tokio::select! {
                    _ = heartbeat_interval.tick() => {
                        if let ClientState::Connected = *client.state.read().await {
                            if let Err(e) = client.send_heartbeat().await {
                                warn!("Heartbeat failed: {}", e);
                                *client.state.write().await = ClientState::Reconnecting;
                            }
                        }
                    }
                    _ = shutdown_rx.recv() => {
                        debug!("Heartbeat task stopped");
                        break;
                    }
                }
            }
        });
    }

    async fn send_heartbeat(&self) -> Result<()> {
        let node_id = self.node_id.lock().await;
        if let Some(id) = *node_id {
            let token = self.auth_manager.get_token().await?;
            let mut client = self.create_grpc_client().await?;

            let request = NodeHeartbeatRequest {
                node_id: id.to_string(),
                status: "online".to_string(),
                endpoint: None, // TODO: Get current endpoint
            };

            client.node_heartbeat(request).await
                .map_err(|e| GhostWireError::network(format!("Heartbeat failed: {}", e)))?;

            debug!("Heartbeat sent successfully");
        }

        Ok(())
    }

    async fn start_network_map_sync(&self, shutdown_tx: broadcast::Sender<()>) {
        let client = self.clone();
        let mut shutdown_rx = shutdown_tx.subscribe();

        tokio::spawn(async move {
            let mut sync_interval = interval(Duration::from_secs(60));

            loop {
                tokio::select! {
                    _ = sync_interval.tick() => {
                        if let ClientState::Connected = *client.state.read().await {
                            if let Err(e) = client.sync_network_map().await {
                                warn!("Network map sync failed: {}", e);
                            }
                        }
                    }
                    _ = shutdown_rx.recv() => {
                        debug!("Network map sync stopped");
                        break;
                    }
                }
            }
        });
    }

    async fn start_stats_collector(&self, shutdown_tx: broadcast::Sender<()>) {
        let client = self.clone();
        let mut shutdown_rx = shutdown_tx.subscribe();

        tokio::spawn(async move {
            let mut stats_interval = interval(Duration::from_secs(10));

            loop {
                tokio::select! {
                    _ = stats_interval.tick() => {
                        if let Err(e) = client.collect_stats().await {
                            debug!("Stats collection failed: {}", e);
                        }
                    }
                    _ = shutdown_rx.recv() => {
                        debug!("Stats collector stopped");
                        break;
                    }
                }
            }
        });
    }

    async fn collect_stats(&self) -> Result<()> {
        // Get transport stats
        let transport_stats = self.transport_manager.get_stats().await?;

        // Update client stats
        let mut stats = self.stats.write().await;
        stats.bytes_sent = transport_stats.bytes_sent;
        stats.bytes_received = transport_stats.bytes_received;
        stats.packets_sent = transport_stats.packets_sent;
        stats.packets_received = transport_stats.packets_received;

        // Update peer stats
        let peer_stats = self.transport_manager.get_peer_stats().await?;
        let mut peers = self.peers.write().await;

        for peer in peers.iter_mut() {
            if let Some(stats) = peer_stats.get(&peer.node_id) {
                peer.bytes_sent = stats.bytes_sent;
                peer.bytes_received = stats.bytes_received;
                peer.latency_ms = stats.latency_ms;
                peer.connected = stats.connected;
                peer.last_seen = stats.last_seen;
            }
        }

        Ok(())
    }

    async fn start_transport_handler(&self, shutdown_tx: broadcast::Sender<()>) {
        let client = self.clone();
        let mut transport_rx = self.transport_manager.get_event_receiver().await;
        let mut shutdown_rx = shutdown_tx.subscribe();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    event = transport_rx.recv() => {
                        if let Some(event) = event {
                            client.handle_transport_event(event).await;
                        }
                    }
                    _ = shutdown_rx.recv() => {
                        debug!("Transport handler stopped");
                        break;
                    }
                }
            }
        });
    }

    async fn handle_transport_event(&self, event: TransportEvent) {
        match event {
            TransportEvent::PeerConnected(node_id) => {
                info!("Peer connected: {}", node_id);
                // Update peer status
                let mut peers = self.peers.write().await;
                if let Some(peer) = peers.iter_mut().find(|p| p.node_id == node_id) {
                    peer.connected = true;
                    peer.last_seen = SystemTime::now();
                }
            }
            TransportEvent::PeerDisconnected(node_id) => {
                info!("Peer disconnected: {}", node_id);
                // Update peer status
                let mut peers = self.peers.write().await;
                if let Some(peer) = peers.iter_mut().find(|p| p.node_id == node_id) {
                    peer.connected = false;
                }
            }
            TransportEvent::PacketReceived { from, size } => {
                debug!("Packet received from {}: {} bytes", from, size);
                // Update stats
                let mut stats = self.stats.write().await;
                stats.packets_received += 1;
            }
            TransportEvent::PacketSent { to, size } => {
                debug!("Packet sent to {}: {} bytes", to, size);
                // Update stats
                let mut stats = self.stats.write().await;
                stats.packets_sent += 1;
            }
            TransportEvent::Error(error) => {
                warn!("Transport error: {}", error);
                // Update stats
                let mut stats = self.stats.write().await;
                stats.last_error = Some(error);
            }
        }
    }
}

impl Clone for GhostWireClient {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            state: self.state.clone(),
            node_id: self.node_id.clone(),
            start_time: self.start_time,
            shutdown_sender: self.shutdown_sender.clone(),
            auth_manager: self.auth_manager.clone(),
            transport_manager: self.transport_manager.clone(),
            tunnel_manager: self.tunnel_manager.clone(),
            platform_manager: self.platform_manager.clone(),
            stats: self.stats.clone(),
            network_map: self.network_map.clone(),
            peers: self.peers.clone(),
        }
    }
}

// Placeholder implementations for missing types
#[derive(Debug, Clone)]
pub struct NetworkMap {
    pub nodes: Vec<NodeInfo>,
    pub routes: Vec<RouteInfo>,
    pub dns_config: Option<DnsConfig>,
}

#[derive(Debug, Clone)]
pub struct NodeInfo {
    pub id: NodeId,
    pub name: String,
    pub ipv4: std::net::Ipv4Addr,
    pub ipv6: Option<std::net::Ipv6Addr>,
    pub public_key: String,
    pub endpoint: Option<std::net::SocketAddr>,
    pub derp_region: Option<u16>,
    pub tags: Vec<String>,
    pub exit_node: bool,
    pub online: bool,
}

#[derive(Debug, Clone)]
pub struct RouteInfo {
    pub destination: cidr::Ipv4Cidr,
    pub via: NodeId,
    pub metric: u32,
    pub enabled: bool,
}

#[derive(Debug, Clone)]
pub struct DnsConfig {
    pub servers: Vec<std::net::IpAddr>,
    pub search_domains: Vec<String>,
    pub magic_dns: bool,
}

impl From<ghostwire_proto::types::NetworkMap> for NetworkMap {
    fn from(_proto: ghostwire_proto::types::NetworkMap) -> Self {
        // TODO: Implement proper conversion
        NetworkMap {
            nodes: vec![],
            routes: vec![],
            dns_config: None,
        }
    }
}