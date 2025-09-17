use crate::types::{NodeId, PublicKey};
use crate::error::{Result, GhostWireError};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, SystemTime};
use uuid::Uuid;

/// QUIC stream types for multiplexing different data flows
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StreamType {
    /// WireGuard control messages (handshakes, key rotation)
    WireGuardControl = 0,
    /// WireGuard encrypted data packets
    WireGuardData = 1,
    /// Node heartbeat and keepalive
    Heartbeat = 2,
    /// Route advertisements and network topology
    RouteAdvertisement = 3,
    /// Real-time performance metrics
    Metrics = 4,
    /// DERP relay control (when acting as relay)
    DerpControl = 5,
    /// DERP relayed packets
    DerpRelay = 6,
}

impl StreamType {
    pub fn is_control_stream(&self) -> bool {
        matches!(
            self,
            StreamType::WireGuardControl
                | StreamType::Heartbeat
                | StreamType::RouteAdvertisement
                | StreamType::DerpControl
        )
    }

    pub fn is_data_stream(&self) -> bool {
        matches!(
            self,
            StreamType::WireGuardData | StreamType::DerpRelay
        )
    }

    pub fn priority(&self) -> u8 {
        match self {
            StreamType::WireGuardControl => 255, // Highest priority
            StreamType::Heartbeat => 200,
            StreamType::RouteAdvertisement => 150,
            StreamType::DerpControl => 100,
            StreamType::WireGuardData => 50,     // Normal data
            StreamType::Metrics => 25,
            StreamType::DerpRelay => 10,         // Relayed traffic lower priority
        }
    }
}

/// QUIC connection information
#[derive(Debug, Clone)]
pub struct QuicConnection {
    pub connection_id: Uuid,
    pub peer_node_id: NodeId,
    pub peer_public_key: PublicKey,
    pub local_addr: SocketAddr,
    pub remote_addr: SocketAddr,
    pub established_at: SystemTime,
    pub last_activity: SystemTime,
    pub rtt: Option<Duration>,
    pub bandwidth_estimate: Option<u64>, // bytes/sec
    pub active_streams: HashMap<u64, StreamInfo>,
    pub connection_migration_count: u32,
    pub is_direct: bool, // true for peer-to-peer, false for relayed
}

#[derive(Debug, Clone)]
pub struct StreamInfo {
    pub stream_id: u64,
    pub stream_type: StreamType,
    pub created_at: SystemTime,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub last_activity: SystemTime,
}

/// QUIC multiplexer configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuicConfig {
    /// Maximum number of concurrent streams per connection
    pub max_streams: u64,
    /// Connection idle timeout
    pub idle_timeout: Duration,
    /// Keep-alive interval
    pub keep_alive_interval: Duration,
    /// Maximum bandwidth per connection (bytes/sec)
    pub max_bandwidth: Option<u64>,
    /// Enable connection migration
    pub enable_migration: bool,
    /// QUIC version preferences
    pub supported_versions: Vec<u32>,
    /// TLS ALPN protocols
    pub alpn_protocols: Vec<String>,
}

impl Default for QuicConfig {
    fn default() -> Self {
        Self {
            max_streams: 100,
            idle_timeout: Duration::from_secs(300), // 5 minutes
            keep_alive_interval: Duration::from_secs(15),
            max_bandwidth: Some(1_000_000_000), // 1 Gbps default limit
            enable_migration: true,
            supported_versions: vec![1], // QUIC v1
            alpn_protocols: vec!["ghostwire/1.0".to_string()],
        }
    }
}

/// Message sent over QUIC streams
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuicMessage {
    pub stream_type: StreamType,
    pub sequence: u64,
    pub timestamp: SystemTime,
    pub payload: QuicPayload,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum QuicPayload {
    /// WireGuard handshake initiation
    WgHandshakeInit {
        sender_index: u32,
        ephemeral_public: [u8; 32],
        encrypted_static: Vec<u8>,
        encrypted_timestamp: Vec<u8>,
    },
    /// WireGuard handshake response
    WgHandshakeResponse {
        sender_index: u32,
        receiver_index: u32,
        ephemeral_public: [u8; 32],
        encrypted_nothing: Vec<u8>,
    },
    /// WireGuard data packet
    WgData {
        receiver_index: u32,
        counter: u64,
        encrypted_data: Vec<u8>,
    },
    /// Node heartbeat
    Heartbeat {
        node_id: NodeId,
        sequence: u64,
        endpoints: Vec<SocketAddr>,
    },
    /// Route advertisement
    RouteAdvert {
        node_id: NodeId,
        routes: Vec<crate::types::Route>,
    },
    /// Performance metrics
    Metrics {
        node_id: NodeId,
        metrics: NodeMetrics,
    },
    /// DERP relay request
    DerpRelay {
        target_public_key: PublicKey,
        data: Vec<u8>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeMetrics {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rtt_ms: Option<f64>,
    pub bandwidth_bps: Option<u64>,
    pub packet_loss: Option<f64>,
    pub jitter_ms: Option<f64>,
    pub timestamp: SystemTime,
}

/// QUIC connection state for tracking peer relationships
#[derive(Debug, Clone)]
pub enum ConnectionState {
    /// Attempting to establish QUIC connection
    Connecting,
    /// QUIC connected, performing WireGuard handshake
    Handshaking,
    /// Fully established and ready for data
    Established,
    /// Connection migrating to new network path
    Migrating { new_addr: SocketAddr },
    /// Connection experiencing issues
    Degraded { reason: String },
    /// Connection closed
    Closed { reason: String },
}

/// Enhanced peer connection using QUIC multiplexing
#[derive(Debug, Clone)]
pub struct QuicPeer {
    pub node_id: NodeId,
    pub public_key: PublicKey,
    pub quic_connection: Option<QuicConnection>,
    pub state: ConnectionState,
    pub preferred_endpoint: Option<SocketAddr>,
    pub backup_endpoints: Vec<SocketAddr>,
    pub last_handshake: Option<SystemTime>,
    pub wireguard_session: Option<WireGuardSession>,
    pub metrics: NodeMetrics,
}

#[derive(Debug, Clone)]
pub struct WireGuardSession {
    pub local_index: u32,
    pub remote_index: u32,
    pub sending_key: [u8; 32],
    pub receiving_key: [u8; 32],
    pub sending_counter: u64,
    pub receiving_counter: u64,
    pub created_at: SystemTime,
    pub last_used: SystemTime,
}

impl QuicConnection {
    pub fn new(
        peer_node_id: NodeId,
        peer_public_key: PublicKey,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
    ) -> Self {
        let now = SystemTime::now();
        Self {
            connection_id: Uuid::new_v4(),
            peer_node_id,
            peer_public_key,
            local_addr,
            remote_addr,
            established_at: now,
            last_activity: now,
            rtt: None,
            bandwidth_estimate: None,
            active_streams: HashMap::new(),
            connection_migration_count: 0,
            is_direct: true,
        }
    }

    pub fn update_activity(&mut self) {
        self.last_activity = SystemTime::now();
    }

    pub fn is_idle(&self, timeout: Duration) -> bool {
        self.last_activity
            .elapsed()
            .map(|elapsed| elapsed > timeout)
            .unwrap_or(true)
    }

    pub fn add_stream(&mut self, stream_id: u64, stream_type: StreamType) {
        let now = SystemTime::now();
        let stream_info = StreamInfo {
            stream_id,
            stream_type,
            created_at: now,
            bytes_sent: 0,
            bytes_received: 0,
            last_activity: now,
        };
        self.active_streams.insert(stream_id, stream_info);
    }

    pub fn estimate_capacity(&self) -> Option<u64> {
        // Estimate available capacity based on RTT and bandwidth
        if let (Some(rtt), Some(bandwidth)) = (self.rtt, self.bandwidth_estimate) {
            // Simple bandwidth-delay product calculation
            let bdp = (bandwidth as f64 * rtt.as_secs_f64()) as u64;
            Some(bdp)
        } else {
            None
        }
    }
}

impl QuicPeer {
    pub fn new(node_id: NodeId, public_key: PublicKey) -> Self {
        Self {
            node_id,
            public_key,
            quic_connection: None,
            state: ConnectionState::Connecting,
            preferred_endpoint: None,
            backup_endpoints: Vec::new(),
            last_handshake: None,
            wireguard_session: None,
            metrics: NodeMetrics::default(),
        }
    }

    pub fn is_connected(&self) -> bool {
        matches!(self.state, ConnectionState::Established)
    }

    pub fn can_send_data(&self) -> bool {
        matches!(
            self.state,
            ConnectionState::Established | ConnectionState::Migrating { .. }
        )
    }

    pub fn effective_endpoint(&self) -> Option<SocketAddr> {
        self.quic_connection
            .as_ref()
            .map(|conn| conn.remote_addr)
            .or(self.preferred_endpoint)
    }
}

impl Default for NodeMetrics {
    fn default() -> Self {
        Self {
            rx_bytes: 0,
            tx_bytes: 0,
            rx_packets: 0,
            tx_packets: 0,
            rtt_ms: None,
            bandwidth_bps: None,
            packet_loss: None,
            jitter_ms: None,
            timestamp: SystemTime::now(),
        }
    }
}

/// Trait for QUIC multiplexer implementations
pub trait QuicMultiplexer {
    /// Establish a new QUIC connection to a peer
    async fn connect_peer(&mut self, peer: &QuicPeer) -> Result<()>;

    /// Send a message over a specific stream type
    async fn send_message(
        &mut self,
        peer_id: NodeId,
        message: QuicMessage,
    ) -> Result<()>;

    /// Receive messages from any peer
    async fn receive_message(&mut self) -> Result<(NodeId, QuicMessage)>;

    /// Handle connection migration
    async fn migrate_connection(
        &mut self,
        peer_id: NodeId,
        new_addr: SocketAddr,
    ) -> Result<()>;

    /// Get connection statistics
    fn get_peer_stats(&self, peer_id: NodeId) -> Option<&QuicConnection>;

    /// Close connection to a peer
    async fn disconnect_peer(&mut self, peer_id: NodeId) -> Result<()>;
}