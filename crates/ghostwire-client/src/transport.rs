/// Transport management for hybrid WireGuard and QUIC connectivity
///
/// Manages multiple transport methods including WireGuard (kernel and userspace),
/// QUIC direct connections, and DERP relay fallback for NAT traversal.

use crate::config::{TransportConfig, WireGuardConfig, QuicConfig, DerpConfig};
use crate::client::{NodeInfo, PeerInfo};

use ghostwire_common::{
    types::*,
    error::{Result, GhostWireError},
};

use std::collections::HashMap;
use std::net::{SocketAddr, IpAddr};
use std::sync::Arc;
use std::time::{SystemTime, Duration, Instant};
use tokio::sync::{RwLock, mpsc, broadcast, Mutex};
use tokio::time::{interval, timeout};
use tracing::{info, warn, error, debug};
use uuid::Uuid;

/// Transport events
#[derive(Debug, Clone)]
pub enum TransportEvent {
    PeerConnected(NodeId),
    PeerDisconnected(NodeId),
    PacketReceived { from: NodeId, size: usize },
    PacketSent { to: NodeId, size: usize },
    Error(String),
}

/// Transport statistics
#[derive(Debug, Clone, Default)]
pub struct TransportStats {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub wireguard_peers: u32,
    pub quic_connections: u32,
    pub derp_connections: u32,
    pub active_transports: Vec<String>,
}

/// Peer transport statistics
#[derive(Debug, Clone)]
pub struct PeerStats {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub latency_ms: Option<f64>,
    pub connected: bool,
    pub last_seen: SystemTime,
    pub transport_type: TransportType,
    pub endpoint: Option<SocketAddr>,
}

/// Transport type
#[derive(Debug, Clone, PartialEq)]
pub enum TransportType {
    WireGuard,
    Quic,
    Derp,
}

/// Transport manager
pub struct TransportManager {
    config: TransportConfig,

    // Transport implementations
    wireguard: Option<Arc<WireGuardTransport>>,
    quic: Option<Arc<QuicTransport>>,
    derp: Option<Arc<DerpTransport>>,

    // State management
    peers: Arc<RwLock<HashMap<NodeId, PeerState>>>,
    stats: Arc<RwLock<TransportStats>>,
    event_sender: broadcast::Sender<TransportEvent>,

    // Packet routing
    packet_router: Arc<PacketRouter>,

    shutdown_sender: Option<broadcast::Sender<()>>,
}

/// Peer connection state
#[derive(Debug, Clone)]
struct PeerState {
    node_id: NodeId,
    public_key: String,
    allowed_ips: Vec<cidr::IpCidr>,
    endpoint: Option<SocketAddr>,
    derp_region: Option<u16>,

    // Connection attempts
    transports: HashMap<TransportType, TransportConnection>,
    preferred_transport: Option<TransportType>,

    // Statistics
    last_seen: SystemTime,
    stats: PeerStats,
}

/// Individual transport connection
#[derive(Debug, Clone)]
struct TransportConnection {
    transport_type: TransportType,
    connected: bool,
    last_attempt: Option<Instant>,
    last_success: Option<Instant>,
    attempt_count: u32,
    latency_ms: Option<f64>,
}

/// Packet router for transport selection
struct PacketRouter {
    routing_table: Arc<RwLock<HashMap<IpAddr, NodeId>>>,
    transport_preferences: Arc<RwLock<HashMap<NodeId, TransportType>>>,
}

impl TransportManager {
    /// Create a new transport manager
    pub async fn new(config: TransportConfig) -> Result<Self> {
        info!("Initializing transport manager");

        let (event_sender, _) = broadcast::channel(1000);

        // Initialize transport implementations
        let wireguard = if config.wireguard.enabled {
            Some(Arc::new(WireGuardTransport::new(config.wireguard.clone()).await?))
        } else {
            None
        };

        let quic = if config.quic.enabled {
            Some(Arc::new(QuicTransport::new(config.quic.clone()).await?))
        } else {
            None
        };

        let derp = if config.derp.enabled {
            Some(Arc::new(DerpTransport::new(config.derp.clone()).await?))
        } else {
            None
        };

        let packet_router = Arc::new(PacketRouter::new().await?);

        info!("Transport manager initialized successfully");

        Ok(Self {
            config,
            wireguard,
            quic,
            derp,
            peers: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(TransportStats::default())),
            event_sender,
            packet_router,
            shutdown_sender: None,
        })
    }

    /// Start the transport manager
    pub async fn start(&mut self) -> Result<()> {
        info!("Starting transport manager");

        // Create shutdown channel
        let (shutdown_tx, _) = broadcast::channel(1);
        self.shutdown_sender = Some(shutdown_tx.clone());

        // Start transport implementations
        if let Some(ref wg) = self.wireguard {
            wg.start().await?;
        }

        if let Some(ref quic) = self.quic {
            quic.start().await?;
        }

        if let Some(ref derp) = self.derp {
            derp.start().await?;
        }

        // Start background tasks
        self.start_connection_manager(shutdown_tx.clone()).await;
        self.start_stats_collector(shutdown_tx.clone()).await;
        self.start_packet_handler(shutdown_tx).await;

        info!("Transport manager started successfully");
        Ok(())
    }

    /// Stop the transport manager
    pub async fn stop(&self) -> Result<()> {
        info!("Stopping transport manager");

        // Send shutdown signal
        if let Some(sender) = &self.shutdown_sender {
            let _ = sender.send(());
        }

        // Stop transport implementations
        if let Some(ref wg) = self.wireguard {
            wg.stop().await?;
        }

        if let Some(ref quic) = self.quic {
            quic.stop().await?;
        }

        if let Some(ref derp) = self.derp {
            derp.stop().await?;
        }

        info!("Transport manager stopped");
        Ok(())
    }

    /// Configure peers from network map
    pub async fn configure_peers(&self, nodes: &[NodeInfo]) -> Result<()> {
        info!("Configuring {} peers", nodes.len());

        let mut peers = self.peers.write().await;
        peers.clear();

        for node in nodes {
            let peer_state = PeerState {
                node_id: node.id,
                public_key: node.public_key.clone(),
                allowed_ips: vec![
                    cidr::IpCidr::V4(cidr::Ipv4Cidr::new(node.ipv4, 32).unwrap()),
                ],
                endpoint: node.endpoint,
                derp_region: node.derp_region,
                transports: HashMap::new(),
                preferred_transport: None,
                last_seen: SystemTime::now(),
                stats: PeerStats {
                    bytes_sent: 0,
                    bytes_received: 0,
                    packets_sent: 0,
                    packets_received: 0,
                    latency_ms: None,
                    connected: false,
                    last_seen: SystemTime::now(),
                    transport_type: TransportType::WireGuard,
                    endpoint: node.endpoint,
                },
            };

            // Configure peer in all enabled transports
            if let Some(ref wg) = self.wireguard {
                wg.configure_peer(&peer_state).await?;
            }

            if let Some(ref quic) = self.quic {
                quic.configure_peer(&peer_state).await?;
            }

            if let Some(ref derp) = self.derp {
                derp.configure_peer(&peer_state).await?;
            }

            peers.insert(node.id, peer_state);
        }

        info!("Configured {} peers successfully", peers.len());
        Ok(())
    }

    /// Get public key for this node
    pub async fn get_public_key(&self) -> Result<String> {
        if let Some(ref wg) = self.wireguard {
            wg.get_public_key().await
        } else {
            // Generate a temporary key for non-WireGuard mode
            Ok("temp-public-key".to_string())
        }
    }

    /// Get transport statistics
    pub async fn get_stats(&self) -> Result<TransportStats> {
        Ok(self.stats.read().await.clone())
    }

    /// Get peer statistics
    pub async fn get_peer_stats(&self) -> Result<HashMap<NodeId, PeerStats>> {
        let peers = self.peers.read().await;
        let mut result = HashMap::new();

        for (node_id, peer) in peers.iter() {
            result.insert(*node_id, peer.stats.clone());
        }

        Ok(result)
    }

    /// Get event receiver
    pub async fn get_event_receiver(&self) -> mpsc::UnboundedReceiver<TransportEvent> {
        let (tx, rx) = mpsc::unbounded_channel();

        // Forward events from broadcast to mpsc
        let mut event_rx = self.event_sender.subscribe();
        tokio::spawn(async move {
            while let Ok(event) = event_rx.recv().await {
                if tx.send(event).is_err() {
                    break;
                }
            }
        });

        rx
    }

    /// Send packet to peer
    pub async fn send_packet(&self, to: NodeId, data: &[u8]) -> Result<()> {
        let peers = self.peers.read().await;
        if let Some(peer) = peers.get(&to) {
            let transport_type = peer.preferred_transport
                .unwrap_or(TransportType::WireGuard);

            match transport_type {
                TransportType::WireGuard => {
                    if let Some(ref wg) = self.wireguard {
                        wg.send_packet(to, data).await?;
                    }
                }
                TransportType::Quic => {
                    if let Some(ref quic) = self.quic {
                        quic.send_packet(to, data).await?;
                    }
                }
                TransportType::Derp => {
                    if let Some(ref derp) = self.derp {
                        derp.send_packet(to, data).await?;
                    }
                }
            }

            // Send event
            let _ = self.event_sender.send(TransportEvent::PacketSent {
                to,
                size: data.len(),
            });
        }

        Ok(())
    }

    // Private implementation methods

    async fn start_connection_manager(&self, shutdown_tx: broadcast::Sender<()>) {
        let manager = self.clone();
        let mut shutdown_rx = shutdown_tx.subscribe();

        tokio::spawn(async move {
            let mut connection_interval = interval(Duration::from_secs(10));

            loop {
                tokio::select! {
                    _ = connection_interval.tick() => {
                        if let Err(e) = manager.manage_connections().await {
                            debug!("Connection management error: {}", e);
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

    async fn manage_connections(&self) -> Result<()> {
        let peers = self.peers.read().await;

        for (node_id, peer) in peers.iter() {
            // Try to establish connections using all available transports
            self.attempt_peer_connections(*node_id, peer).await;
        }

        Ok(())
    }

    async fn attempt_peer_connections(&self, node_id: NodeId, peer: &PeerState) {
        // Try WireGuard first (preferred)
        if self.wireguard.is_some() {
            if let Err(e) = self.attempt_wireguard_connection(node_id, peer).await {
                debug!("WireGuard connection to {} failed: {}", node_id, e);
            }
        }

        // Try QUIC if WireGuard fails or is unavailable
        if self.quic.is_some() {
            if let Err(e) = self.attempt_quic_connection(node_id, peer).await {
                debug!("QUIC connection to {} failed: {}", node_id, e);
            }
        }

        // Fall back to DERP
        if self.derp.is_some() {
            if let Err(e) = self.attempt_derp_connection(node_id, peer).await {
                debug!("DERP connection to {} failed: {}", node_id, e);
            }
        }
    }

    async fn attempt_wireguard_connection(&self, node_id: NodeId, peer: &PeerState) -> Result<()> {
        if let Some(ref wg) = self.wireguard {
            wg.connect_peer(node_id).await?;
        }
        Ok(())
    }

    async fn attempt_quic_connection(&self, node_id: NodeId, peer: &PeerState) -> Result<()> {
        if let Some(ref quic) = self.quic {
            if let Some(endpoint) = peer.endpoint {
                quic.connect_peer(node_id, endpoint).await?;
            }
        }
        Ok(())
    }

    async fn attempt_derp_connection(&self, node_id: NodeId, peer: &PeerState) -> Result<()> {
        if let Some(ref derp) = self.derp {
            derp.connect_peer(node_id).await?;
        }
        Ok(())
    }

    async fn start_stats_collector(&self, shutdown_tx: broadcast::Sender<()>) {
        let manager = self.clone();
        let mut shutdown_rx = shutdown_tx.subscribe();

        tokio::spawn(async move {
            let mut stats_interval = interval(Duration::from_secs(5));

            loop {
                tokio::select! {
                    _ = stats_interval.tick() => {
                        if let Err(e) = manager.collect_stats().await {
                            debug!("Stats collection error: {}", e);
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
        let mut total_stats = TransportStats::default();

        // Collect WireGuard stats
        if let Some(ref wg) = self.wireguard {
            let wg_stats = wg.get_stats().await?;
            total_stats.bytes_sent += wg_stats.bytes_sent;
            total_stats.bytes_received += wg_stats.bytes_received;
            total_stats.packets_sent += wg_stats.packets_sent;
            total_stats.packets_received += wg_stats.packets_received;
            total_stats.wireguard_peers = wg_stats.peer_count;
            total_stats.active_transports.push("wireguard".to_string());
        }

        // Collect QUIC stats
        if let Some(ref quic) = self.quic {
            let quic_stats = quic.get_stats().await?;
            total_stats.bytes_sent += quic_stats.bytes_sent;
            total_stats.bytes_received += quic_stats.bytes_received;
            total_stats.packets_sent += quic_stats.packets_sent;
            total_stats.packets_received += quic_stats.packets_received;
            total_stats.quic_connections = quic_stats.connection_count;
            total_stats.active_transports.push("quic".to_string());
        }

        // Collect DERP stats
        if let Some(ref derp) = self.derp {
            let derp_stats = derp.get_stats().await?;
            total_stats.bytes_sent += derp_stats.bytes_sent;
            total_stats.bytes_received += derp_stats.bytes_received;
            total_stats.packets_sent += derp_stats.packets_sent;
            total_stats.packets_received += derp_stats.packets_received;
            total_stats.derp_connections = derp_stats.connection_count;
            total_stats.active_transports.push("derp".to_string());
        }

        *self.stats.write().await = total_stats;
        Ok(())
    }

    async fn start_packet_handler(&self, shutdown_tx: broadcast::Sender<()>) {
        let manager = self.clone();
        let mut shutdown_rx = shutdown_tx.subscribe();

        tokio::spawn(async move {
            // TODO: Implement packet handling loop
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_millis(100)) => {
                        // Handle incoming packets
                    }
                    _ = shutdown_rx.recv() => {
                        debug!("Packet handler stopped");
                        break;
                    }
                }
            }
        });
    }
}

impl Clone for TransportManager {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            wireguard: self.wireguard.clone(),
            quic: self.quic.clone(),
            derp: self.derp.clone(),
            peers: self.peers.clone(),
            stats: self.stats.clone(),
            event_sender: self.event_sender.clone(),
            packet_router: self.packet_router.clone(),
            shutdown_sender: self.shutdown_sender.clone(),
        }
    }
}

impl PacketRouter {
    async fn new() -> Result<Self> {
        Ok(Self {
            routing_table: Arc::new(RwLock::new(HashMap::new())),
            transport_preferences: Arc::new(RwLock::new(HashMap::new())),
        })
    }
}

// Transport implementations with packet handling

pub struct PacketHandler {
    sender: tokio::sync::mpsc::UnboundedSender<(Vec<u8>, SocketAddr)>,
}

impl PacketHandler {
    pub fn new() -> (Self, tokio::sync::mpsc::UnboundedReceiver<(Vec<u8>, SocketAddr)>) {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        (Self { sender: tx }, rx)
    }

    pub async fn handle_packet(&self, packet: Vec<u8>, from: SocketAddr) -> Result<()> {
        self.sender.send((packet, from))
            .map_err(|_| anyhow::anyhow!("Packet handler channel closed"))?;
        Ok(())
    }
}

pub struct WireGuardTransport {
    interface_name: String,
    private_key: Vec<u8>,
    public_key: Vec<u8>,
    listen_port: u16,
    peers: Arc<RwLock<HashMap<String, WireGuardPeer>>>,
    socket: Arc<tokio::net::UdpSocket>,
    stats: Arc<RwLock<TransportStats>>,
}

#[derive(Debug, Clone)]
pub struct WireGuardPeer {
    pub public_key: Vec<u8>,
    pub endpoint: Option<SocketAddr>,
    pub allowed_ips: Vec<ipnet::IpNet>,
    pub persistent_keepalive: Option<Duration>,
    pub last_handshake: Option<SystemTime>,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
}

impl WireGuardTransport {
    async fn new(config: WireGuardConfig) -> Result<Self> {
        let (private_key, public_key) = Self::generate_keys()?;

        let socket = tokio::net::UdpSocket::bind(
            format!("0.0.0.0:{}", config.listen_port)
        )
        .await
        .context("failed to bind WireGuard socket")?;

        Ok(Self {
            interface_name: config.interface.clone(),
            private_key,
            public_key,
            listen_port: config.listen_port,
            peers: Arc::new(RwLock::new(HashMap::new())),
            socket: Arc::new(socket),
            stats: Arc::new(RwLock::new(TransportStats::default())),
        })
    }

    async fn start(&self) -> Result<()> {
        info!("Starting WireGuard transport on port {}", self.listen_port);

        // Start packet listener
        let (packet_handler, mut packet_rx) = PacketHandler::new();
        self.start_listener(packet_handler).await?;

        // Handle incoming packets
        tokio::spawn(async move {
            while let Some((packet, from)) = packet_rx.recv().await {
                debug!("Received WireGuard packet from {}: {} bytes", from, packet.len());
                // Process packet routing here
            }
        });

        Ok(())
    }

    async fn stop(&self) -> Result<()> {
        info!("Stopping WireGuard transport");
        Ok(())
    }

    async fn configure_peer(&self, peer: &PeerState) -> Result<()> {
        let public_key = hex::decode(&peer.public_key)
            .context("invalid peer public key")?;

        let wg_peer = WireGuardPeer {
            public_key,
            endpoint: peer.endpoint,
            allowed_ips: peer.allowed_ips.iter().map(|cidr| {
                match cidr {
                    cidr::IpCidr::V4(v4) => ipnet::IpNet::V4(ipnet::Ipv4Net::new(v4.first_address(), v4.network_length()).unwrap()),
                    cidr::IpCidr::V6(v6) => ipnet::IpNet::V6(ipnet::Ipv6Net::new(v6.first_address(), v6.network_length()).unwrap()),
                }
            }).collect(),
            persistent_keepalive: Some(Duration::from_secs(25)),
            last_handshake: None,
            tx_bytes: 0,
            rx_bytes: 0,
        };

        self.add_peer(wg_peer).await
    }

    async fn connect_peer(&self, node_id: NodeId) -> Result<()> {
        info!("Connecting to WireGuard peer: {}", node_id);
        // Connection logic would be here
        Ok(())
    }

    async fn send_packet(&self, to: NodeId, data: &[u8]) -> Result<()> {
        debug!("Sending WireGuard packet to {}: {} bytes", to, data.len());
        // Packet sending logic would be here
        Ok(())
    }

    async fn get_public_key(&self) -> Result<String> {
        Ok(hex::encode(&self.public_key))
    }

    async fn get_stats(&self) -> Result<TransportLayerStats> {
        let stats = self.stats.read().await;
        Ok(TransportLayerStats {
            bytes_sent: stats.bytes_sent,
            bytes_received: stats.bytes_received,
            packets_sent: stats.packets_sent,
            packets_received: stats.packets_received,
            peer_count: self.peers.read().await.len() as u32,
            connection_count: self.peers.read().await.len() as u32,
        })
    }

    // Additional implementation methods from the complete transport above
    pub async fn add_peer(&self, peer_config: WireGuardPeer) -> Result<()> {
        info!("Adding WireGuard peer: {:?}", hex::encode(&peer_config.public_key));

        let mut peers = self.peers.write().await;
        let peer_key = hex::encode(&peer_config.public_key);
        peers.insert(peer_key, peer_config);

        Ok(())
    }

    pub async fn start_listener(&self, packet_handler: PacketHandler) -> Result<()> {
        let socket = self.socket.clone();
        let peers = self.peers.clone();
        let stats = self.stats.clone();

        tokio::spawn(async move {
            let mut buffer = [0u8; 1500];

            loop {
                match socket.recv_from(&mut buffer).await {
                    Ok((len, src)) => {
                        // Process received packet
                        if let Ok(decrypted) = Self::decrypt_packet(&buffer[..len], &peers).await {
                            if let Err(e) = packet_handler.handle_packet(decrypted, src).await {
                                warn!("Packet handler error: {}", e);
                            }

                            // Update stats
                            if let Ok(mut stats) = stats.try_write() {
                                stats.packets_received += 1;
                                stats.bytes_received += len as u64;
                            }
                        }
                    }
                    Err(e) => {
                        error!("WireGuard socket error: {}", e);
                        break;
                    }
                }
            }
        });

        Ok(())
    }

    fn generate_keys() -> Result<(Vec<u8>, Vec<u8>)> {
        use rand::RngCore;
        let mut rng = rand::thread_rng();

        let mut private_key = [0u8; 32];
        rng.fill_bytes(&mut private_key);

        // Clamp private key for Curve25519
        private_key[0] &= 248;
        private_key[31] &= 127;
        private_key[31] |= 64;

        // Derive public key from private key
        let public_key = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(private_key));

        Ok((private_key.to_vec(), public_key.as_bytes().to_vec()))
    }

    async fn decrypt_packet(packet: &[u8], peers: &Arc<RwLock<HashMap<String, WireGuardPeer>>>) -> Result<Vec<u8>> {
        // Simplified packet decryption
        if packet.len() < 32 {
            return Err(anyhow::anyhow!("Packet too short"));
        }

        // Extract payload (simplified)
        let payload = &packet[16..packet.len()-16];
        Ok(payload.to_vec())
    }
}

pub struct QuicTransport {
    endpoint: Option<quinn::Endpoint>,
    connections: Arc<RwLock<HashMap<String, quinn::Connection>>>,
    server_config: Option<quinn::ServerConfig>,
    client_config: quinn::ClientConfig,
    stats: Arc<RwLock<TransportStats>>,
    bind_addr: SocketAddr,
}

impl QuicTransport {
    async fn new(config: QuicConfig) -> Result<Self> {
        let bind_addr = format!("0.0.0.0:{}", config.listen_port)
            .parse()
            .context("invalid QUIC bind address")?;

        // Generate self-signed certificate for QUIC
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .context("failed to generate self-signed certificate")?;

        let cert_der = cert.serialize_der().context("failed to serialize certificate")?;
        let private_key = cert.serialize_private_key_der();

        // Server configuration
        let mut server_config = None;
        if config.enable_server {
            let mut server_crypto = rustls::ServerConfig::builder()
                .with_safe_defaults()
                .with_no_client_auth()
                .with_single_cert(
                    vec![rustls::Certificate(cert_der.clone())],
                    rustls::PrivateKey(private_key.clone()),
                )
                .context("failed to build server TLS config")?;

            server_crypto.alpn_protocols = vec![b"ghostwire".to_vec()];

            let mut server_cfg = quinn::ServerConfig::with_crypto(Arc::new(server_crypto));
            server_cfg.transport = Arc::new(Self::create_transport_config());
            server_config = Some(server_cfg);
        }

        // Client configuration
        let mut client_crypto = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_custom_certificate_verifier(Arc::new(SkipCertVerification))
            .with_no_client_auth();

        client_crypto.alpn_protocols = vec![b"ghostwire".to_vec()];

        let mut client_config = quinn::ClientConfig::new(Arc::new(client_crypto));
        client_config.transport_config(Arc::new(Self::create_transport_config()));

        Ok(Self {
            endpoint: None,
            connections: Arc::new(RwLock::new(HashMap::new())),
            server_config,
            client_config,
            stats: Arc::new(RwLock::new(TransportStats::default())),
            bind_addr,
        })
    }

    async fn start(&self) -> Result<()> {
        info!("Starting QUIC transport on {}", self.bind_addr);
        Ok(())
    }

    async fn stop(&self) -> Result<()> {
        info!("Stopping QUIC transport");
        if let Some(endpoint) = &self.endpoint {
            endpoint.close(0u32.into(), b"shutdown");
        }
        Ok(())
    }

    async fn configure_peer(&self, peer: &PeerState) -> Result<()> {
        info!("Configuring QUIC peer: {}", peer.node_id);
        Ok(())
    }

    async fn connect_peer(&self, node_id: NodeId, endpoint: SocketAddr) -> Result<()> {
        info!("Connecting to QUIC peer {} at {}", node_id, endpoint);
        Ok(())
    }

    async fn send_packet(&self, to: NodeId, data: &[u8]) -> Result<()> {
        debug!("Sending QUIC packet to {}: {} bytes", to, data.len());
        Ok(())
    }

    async fn get_stats(&self) -> Result<TransportLayerStats> {
        let stats = self.stats.read().await;
        Ok(TransportLayerStats {
            bytes_sent: stats.bytes_sent,
            bytes_received: stats.bytes_received,
            packets_sent: stats.packets_sent,
            packets_received: stats.packets_received,
            peer_count: 0,
            connection_count: self.connections.read().await.len() as u32,
        })
    }

    fn create_transport_config() -> quinn::TransportConfig {
        let mut config = quinn::TransportConfig::default();
        config.max_concurrent_uni_streams(1024_u32.into());
        config.max_concurrent_bidi_streams(1024_u32.into());
        config.max_idle_timeout(Some(Duration::from_secs(60).try_into().unwrap()));
        config.keep_alive_interval(Some(Duration::from_secs(15)));
        config
    }
}

// Skip certificate verification for QUIC (development only)
struct SkipCertVerification;

impl rustls::client::ServerCertVerifier for SkipCertVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _server_name: &rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::ServerCertVerified::assertion())
    }
}

pub struct DerpTransport {
    client: Option<reqwest::Client>,
    server_url: String,
    region_id: u16,
    auth_token: Option<String>,
    node_key: Vec<u8>,
    connections: Arc<RwLock<HashMap<String, DerpConnection>>>,
    stats: Arc<RwLock<TransportStats>>,
}

#[derive(Debug, Clone)]
struct DerpConnection {
    peer_key: Vec<u8>,
    last_activity: SystemTime,
    tx_bytes: u64,
    rx_bytes: u64,
}

impl DerpTransport {
    async fn new(config: DerpConfig) -> Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("GhostWire-DERP-Client/1.0")
            .build()
            .context("failed to create DERP HTTP client")?;

        let node_key = Self::generate_node_key();

        Ok(Self {
            client: Some(client),
            server_url: config.server_url.clone(),
            region_id: config.region_id,
            auth_token: config.auth_token.clone(),
            node_key,
            connections: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(TransportStats::default())),
        })
    }

    async fn start(&self) -> Result<()> {
        info!("Starting DERP transport with server: {}", self.server_url);
        Ok(())
    }

    async fn stop(&self) -> Result<()> {
        info!("Stopping DERP transport");
        Ok(())
    }

    async fn configure_peer(&self, peer: &PeerState) -> Result<()> {
        let peer_key = hex::decode(&peer.public_key)
            .context("invalid peer public key")?;

        let connection = DerpConnection {
            peer_key: peer_key.clone(),
            last_activity: SystemTime::now(),
            tx_bytes: 0,
            rx_bytes: 0,
        };

        let peer_key_hex = hex::encode(&peer_key);
        self.connections.write().await.insert(peer_key_hex, connection);

        Ok(())
    }

    async fn connect_peer(&self, node_id: NodeId) -> Result<()> {
        info!("Establishing DERP connection to peer: {}", node_id);
        Ok(())
    }

    async fn send_packet(&self, to: NodeId, data: &[u8]) -> Result<()> {
        debug!("Sending DERP packet to {}: {} bytes", to, data.len());
        Ok(())
    }

    async fn get_stats(&self) -> Result<TransportLayerStats> {
        let stats = self.stats.read().await;
        Ok(TransportLayerStats {
            bytes_sent: stats.bytes_sent,
            bytes_received: stats.bytes_received,
            packets_sent: stats.packets_sent,
            packets_received: stats.packets_received,
            peer_count: 0,
            connection_count: self.connections.read().await.len() as u32,
        })
    }

    fn generate_node_key() -> Vec<u8> {
        use rand::RngCore;
        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        key.to_vec()
    }
}

#[derive(Debug, Clone, Default)]
pub struct TransportLayerStats {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub peer_count: u32,
    pub connection_count: u32,
}