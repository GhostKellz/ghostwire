use ghostwire_common::{
    error::{Result, GhostWireError},
    types::{NodeId, PublicKey, PrivateKey},
    quic::QuicMessage,
};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::time::SystemTime;
use tokio::sync::mpsc;

/// WireGuard engine trait for different implementations
#[async_trait::async_trait]
pub trait WireGuardEngine: Send + Sync {
    /// Create a new WireGuard interface
    async fn create_interface(&mut self, config: WgConfig) -> Result<WgInterface>;

    /// Send encrypted packet through the interface
    async fn send_packet(&mut self, interface: &WgInterface, data: &[u8]) -> Result<()>;

    /// Receive and decrypt packet from the interface
    async fn receive_packet(&mut self, interface: &WgInterface) -> Result<Vec<u8>>;

    /// Add a peer to the interface
    async fn add_peer(&mut self, interface: &WgInterface, peer: WgPeer) -> Result<()>;

    /// Remove a peer from the interface
    async fn remove_peer(&mut self, interface: &WgInterface, public_key: &PublicKey) -> Result<()>;

    /// Update peer endpoint
    async fn update_peer_endpoint(
        &mut self,
        interface: &WgInterface,
        public_key: &PublicKey,
        endpoint: SocketAddr,
    ) -> Result<()>;

    /// Get interface statistics
    async fn get_stats(&self, interface: &WgInterface) -> Result<WgStats>;

    /// Check if this engine is available on the current system
    fn is_available(&self) -> bool;

    /// Get the performance tier of this engine
    fn performance_tier(&self) -> PerformanceTier;

    /// QUIC integration: Send WireGuard packet over QUIC stream
    async fn send_via_quic(
        &mut self,
        interface: &WgInterface,
        data: &[u8],
        quic_sender: &mut mpsc::UnboundedSender<QuicMessage>,
    ) -> Result<()>;

    /// QUIC integration: Process received QUIC packet as WireGuard data
    async fn receive_via_quic(
        &mut self,
        interface: &WgInterface,
        quic_data: &[u8],
    ) -> Result<Vec<u8>>;
}

/// Performance tiers for different WireGuard implementations
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PerformanceTier {
    /// Pure boringtun - compatibility mode (~200-500 Mbps)
    Compatibility = 1,
    /// Optimized userspace - SIMD + multi-threaded (~1-2 Gbps)
    Optimized = 2,
    /// Kernel WireGuard - maximum performance (2.5+ Gbps)
    Kernel = 3,
}

/// WireGuard interface configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WgConfig {
    pub interface_name: String,
    pub private_key: PrivateKey,
    pub public_key: PublicKey,
    pub listen_port: Option<u16>,
    pub fwmark: Option<u32>,
    pub mtu: Option<u16>,
    /// Enable QUIC multiplexing for this interface
    pub enable_quic_bridge: bool,
    /// Performance hints
    pub expected_throughput: Option<u64>, // bytes/sec
    pub max_peers: Option<u32>,
    /// Optimization settings
    pub enable_simd: bool,
    pub worker_threads: Option<usize>,
    pub batch_size: Option<usize>,
}

impl Default for WgConfig {
    fn default() -> Self {
        Self {
            interface_name: "ghostwire0".to_string(),
            private_key: PrivateKey::from_bytes([0u8; 32]), // Would generate properly
            public_key: PublicKey::from_bytes([0u8; 32]),
            listen_port: None,
            fwmark: None,
            mtu: Some(1420),
            enable_quic_bridge: true,
            expected_throughput: Some(1_000_000_000), // 1 Gbps default
            max_peers: Some(256),
            enable_simd: true,
            worker_threads: None, // Auto-detect
            batch_size: Some(64), // Process packets in batches
        }
    }
}

/// WireGuard interface handle
#[derive(Debug, Clone)]
pub struct WgInterface {
    pub id: String,
    pub name: String,
    pub public_key: PublicKey,
    pub listen_port: Option<u16>,
    pub ip_addresses: Vec<IpAddr>,
    pub created_at: SystemTime,
    pub engine_tier: PerformanceTier,
    /// Handle for QUIC bridge if enabled
    pub quic_bridge_handle: Option<tokio::task::JoinHandle<()>>,
}

/// WireGuard peer configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WgPeer {
    pub node_id: NodeId,
    pub public_key: PublicKey,
    pub preshared_key: Option<[u8; 32]>,
    pub endpoint: Option<SocketAddr>,
    pub allowed_ips: Vec<ipnet::IpNet>,
    pub persistent_keepalive: Option<u16>,
    /// QUIC-specific settings
    pub quic_enabled: bool,
    pub quic_priority: u8,
}

/// WireGuard interface statistics
#[derive(Debug, Clone, Default)]
pub struct WgStats {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_errors: u64,
    pub tx_errors: u64,
    pub handshakes_completed: u64,
    pub handshakes_failed: u64,
    pub last_handshake: Option<SystemTime>,
    /// QUIC-specific stats
    pub quic_streams_active: u32,
    pub quic_bytes_relayed: u64,
    pub quic_latency_ms: Option<f64>,
}

/// Packet processing result for batch operations
#[derive(Debug)]
pub struct PacketBatch {
    pub packets: Vec<ProcessedPacket>,
    pub total_bytes: usize,
    pub processing_time_ns: u64,
}

#[derive(Debug)]
pub struct ProcessedPacket {
    pub data: Vec<u8>,
    pub peer_public_key: Option<PublicKey>,
    pub timestamp: SystemTime,
    pub encrypted: bool,
}

/// High-performance packet buffer for zero-copy operations
#[derive(Debug)]
pub struct PacketBuffer {
    pub data: bytes::BytesMut,
    pub capacity: usize,
    pub used: usize,
}

impl PacketBuffer {
    pub fn new(capacity: usize) -> Self {
        Self {
            data: bytes::BytesMut::with_capacity(capacity),
            capacity,
            used: 0,
        }
    }

    pub fn reset(&mut self) {
        self.data.clear();
        self.used = 0;
    }

    pub fn available(&self) -> usize {
        self.capacity - self.used
    }

    pub fn push_packet(&mut self, packet: &[u8]) -> Result<()> {
        if packet.len() > self.available() {
            return Err(GhostWireError::internal("Buffer capacity exceeded"));
        }

        self.data.extend_from_slice(packet);
        self.used += packet.len();
        Ok(())
    }
}

/// QUIC + WireGuard integration context
#[derive(Debug)]
pub struct QuicWgContext {
    pub interface: WgInterface,
    pub quic_tx: mpsc::UnboundedSender<QuicMessage>,
    pub quic_rx: mpsc::UnboundedReceiver<QuicMessage>,
    pub stats: WgStats,
}

impl WgInterface {
    pub fn new(
        name: String,
        public_key: PublicKey,
        engine_tier: PerformanceTier,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            name,
            public_key,
            listen_port: None,
            ip_addresses: Vec::new(),
            created_at: SystemTime::now(),
            engine_tier,
            quic_bridge_handle: None,
        }
    }

    pub fn performance_class(&self) -> &'static str {
        match self.engine_tier {
            PerformanceTier::Compatibility => "Compatible",
            PerformanceTier::Optimized => "High-Performance",
            PerformanceTier::Kernel => "Maximum Performance",
        }
    }

    pub fn expected_throughput(&self) -> u64 {
        match self.engine_tier {
            PerformanceTier::Compatibility => 500_000_000,    // 500 Mbps
            PerformanceTier::Optimized => 2_000_000_000,      // 2 Gbps
            PerformanceTier::Kernel => 10_000_000_000,        // 10+ Gbps
        }
    }
}

impl WgPeer {
    pub fn new(node_id: NodeId, public_key: PublicKey) -> Self {
        Self {
            node_id,
            public_key,
            preshared_key: None,
            endpoint: None,
            allowed_ips: Vec::new(),
            persistent_keepalive: Some(25), // Standard keepalive
            quic_enabled: true,             // Default to QUIC enabled
            quic_priority: 50,              // Normal priority
        }
    }

    pub fn with_endpoint(mut self, endpoint: SocketAddr) -> Self {
        self.endpoint = Some(endpoint);
        self
    }

    pub fn with_allowed_ips(mut self, allowed_ips: Vec<ipnet::IpNet>) -> Self {
        self.allowed_ips = allowed_ips;
        self
    }

    pub fn with_quic_priority(mut self, priority: u8) -> Self {
        self.quic_priority = priority;
        self
    }
}

/// Engine selection criteria for the hybrid system
#[derive(Debug, Clone)]
pub struct EngineSelectionCriteria {
    pub required_throughput: Option<u64>,
    pub prefer_kernel: bool,
    pub require_user_mode: bool,
    pub enable_optimizations: bool,
    pub max_latency_ms: Option<f64>,
}

impl Default for EngineSelectionCriteria {
    fn default() -> Self {
        Self {
            required_throughput: Some(1_000_000_000), // 1 Gbps
            prefer_kernel: true,
            require_user_mode: false,
            enable_optimizations: true,
            max_latency_ms: Some(5.0), // 5ms max latency
        }
    }
}