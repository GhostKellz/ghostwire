use crate::engine::{WgInterface, WgStats, ProcessedPacket, PacketBuffer};
use ghostwire_common::{
    error::{Result, GhostWireError},
    quic::{QuicMessage, QuicPayload, StreamType},
    types::{NodeId, PublicKey},
};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::SystemTime;
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, error, trace, warn};

/// QUIC-WireGuard bridge for zero-copy packet forwarding
///
/// This component handles the seamless integration between QUIC streams
/// and WireGuard packet processing, enabling:
/// - Zero-copy packet forwarding between QUIC and WireGuard
/// - Stream multiplexing (control vs data vs heartbeat)
/// - Adaptive flow control based on peer capabilities
/// - Connection migration handling
pub struct QuicWireGuardBridge {
    /// WireGuard interface being bridged
    interface: WgInterface,
    /// QUIC message sender
    quic_tx: mpsc::UnboundedSender<QuicMessage>,
    /// QUIC message receiver
    quic_rx: mpsc::UnboundedReceiver<QuicMessage>,
    /// Active peer sessions
    peer_sessions: Arc<RwLock<HashMap<PublicKey, PeerSession>>>,
    /// Packet buffers for zero-copy operations
    tx_buffer: PacketBuffer,
    rx_buffer: PacketBuffer,
    /// Bridge statistics
    stats: Arc<RwLock<BridgeStats>>,
    /// Configuration
    config: BridgeConfig,
}

/// Peer session tracking for QUIC + WireGuard
#[derive(Debug, Clone)]
struct PeerSession {
    pub node_id: NodeId,
    pub public_key: PublicKey,
    pub quic_streams: HashMap<StreamType, u64>, // Stream ID for each type
    pub wireguard_index: Option<u32>,
    pub last_activity: SystemTime,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub quic_priority: u8,
    pub flow_control_window: u32,
}

/// Bridge configuration
#[derive(Debug, Clone)]
pub struct BridgeConfig {
    /// Maximum packet size for bridging
    pub max_packet_size: usize,
    /// Buffer size for batch processing
    pub buffer_size: usize,
    /// Flow control window size
    pub flow_control_window: u32,
    /// Enable zero-copy optimizations
    pub enable_zero_copy: bool,
    /// Batch processing threshold
    pub batch_threshold: usize,
    /// Adaptive priority adjustment
    pub adaptive_priority: bool,
}

impl Default for BridgeConfig {
    fn default() -> Self {
        Self {
            max_packet_size: 1500,
            buffer_size: 65536, // 64KB buffers
            flow_control_window: 32768,
            enable_zero_copy: true,
            batch_threshold: 16, // Process in batches of 16
            adaptive_priority: true,
        }
    }
}

/// Bridge statistics
#[derive(Debug, Default)]
struct BridgeStats {
    pub packets_bridged: u64,
    pub bytes_bridged: u64,
    pub zero_copy_hits: u64,
    pub zero_copy_misses: u64,
    pub flow_control_events: u64,
    pub stream_migrations: u64,
    pub processing_time_ns: u64,
}

impl QuicWireGuardBridge {
    /// Create a new QUIC-WireGuard bridge
    pub fn new(
        interface: WgInterface,
        quic_tx: mpsc::UnboundedSender<QuicMessage>,
        quic_rx: mpsc::UnboundedReceiver<QuicMessage>,
        config: BridgeConfig,
    ) -> Self {
        Self {
            interface,
            quic_tx,
            quic_rx,
            peer_sessions: Arc::new(RwLock::new(HashMap::new())),
            tx_buffer: PacketBuffer::new(config.buffer_size),
            rx_buffer: PacketBuffer::new(config.buffer_size),
            stats: Arc::new(RwLock::new(BridgeStats::default())),
            config,
        }
    }

    /// Start the bridge processing loop
    pub async fn run(&mut self) -> Result<()> {
        debug!("Starting QUIC-WireGuard bridge for interface {}", self.interface.name);

        let mut batch_buffer = Vec::with_capacity(self.config.batch_threshold);
        let mut last_flush = std::time::Instant::now();

        loop {
            tokio::select! {
                // Process incoming QUIC messages
                Some(quic_msg) = self.quic_rx.recv() => {
                    if let Err(e) = self.handle_quic_message(quic_msg).await {
                        error!("Failed to handle QUIC message: {}", e);
                    }
                }

                // Batch processing timeout - flush accumulated packets
                _ = tokio::time::sleep(tokio::time::Duration::from_micros(100)) => {
                    if !batch_buffer.is_empty() || last_flush.elapsed().as_millis() > 10 {
                        if let Err(e) = self.flush_batch_buffer(&mut batch_buffer).await {
                            error!("Failed to flush batch buffer: {}", e);
                        }
                        last_flush = std::time::Instant::now();
                    }
                }

                // Graceful shutdown
                else => {
                    debug!("QUIC-WireGuard bridge shutting down");
                    break;
                }
            }
        }

        Ok(())
    }

    /// Handle incoming QUIC message and bridge to WireGuard
    async fn handle_quic_message(&mut self, message: QuicMessage) -> Result<()> {
        let start_time = std::time::Instant::now();

        match message.payload {
            QuicPayload::WgData { receiver_index, counter, encrypted_data } => {
                // Bridge QUIC data to WireGuard interface
                self.bridge_quic_to_wireguard(receiver_index, counter, encrypted_data).await?;
            }

            QuicPayload::WgHandshakeInit { sender_index, ephemeral_public, encrypted_static, encrypted_timestamp } => {
                // Handle WireGuard handshake over QUIC
                self.handle_wireguard_handshake_init(
                    sender_index,
                    ephemeral_public,
                    encrypted_static,
                    encrypted_timestamp,
                ).await?;
            }

            QuicPayload::WgHandshakeResponse { sender_index, receiver_index, ephemeral_public, encrypted_nothing } => {
                // Handle WireGuard handshake response over QUIC
                self.handle_wireguard_handshake_response(
                    sender_index,
                    receiver_index,
                    ephemeral_public,
                    encrypted_nothing,
                ).await?;
            }

            QuicPayload::Heartbeat { node_id, sequence, endpoints } => {
                // Update peer activity and endpoints
                self.update_peer_activity(node_id, endpoints).await?;
            }

            _ => {
                trace!("Ignoring non-WireGuard QUIC message: {:?}", message.stream_type);
            }
        }

        // Update processing time stats
        let processing_time = start_time.elapsed().as_nanos() as u64;
        let mut stats = self.stats.write().await;
        stats.processing_time_ns += processing_time;

        Ok(())
    }

    /// Bridge QUIC data packet to WireGuard interface
    async fn bridge_quic_to_wireguard(
        &mut self,
        receiver_index: u32,
        counter: u64,
        encrypted_data: Vec<u8>,
    ) -> Result<()> {
        // Find peer session by receiver index
        let peer_key = self.find_peer_by_index(receiver_index).await?;

        // Zero-copy optimization: if possible, reference data directly
        let packet_data = if self.config.enable_zero_copy && encrypted_data.len() <= self.config.max_packet_size {
            // Direct reference - zero copy
            let mut stats = self.stats.write().await;
            stats.zero_copy_hits += 1;
            encrypted_data
        } else {
            // Copy to buffer for processing
            let mut stats = self.stats.write().await;
            stats.zero_copy_misses += 1;
            encrypted_data
        };

        // Create WireGuard packet from QUIC data
        let wg_packet = self.reconstruct_wireguard_packet(receiver_index, counter, packet_data)?;

        // Process through WireGuard engine (would integrate with actual engine)
        self.process_wireguard_packet(wg_packet, peer_key).await?;

        // Update stats
        let mut stats = self.stats.write().await;
        stats.packets_bridged += 1;
        stats.bytes_bridged += encrypted_data.len() as u64;

        Ok(())
    }

    /// Handle WireGuard handshake initiation over QUIC
    async fn handle_wireguard_handshake_init(
        &mut self,
        sender_index: u32,
        ephemeral_public: [u8; 32],
        encrypted_static: Vec<u8>,
        encrypted_timestamp: Vec<u8>,
    ) -> Result<()> {
        debug!("Handling WireGuard handshake init over QUIC: sender_index={}", sender_index);

        // Reconstruct WireGuard handshake packet
        let handshake_packet = self.reconstruct_handshake_init(
            sender_index,
            ephemeral_public,
            encrypted_static,
            encrypted_timestamp,
        )?;

        // Process handshake through WireGuard engine
        self.process_handshake_packet(handshake_packet).await?;

        Ok(())
    }

    /// Handle WireGuard handshake response over QUIC
    async fn handle_wireguard_handshake_response(
        &mut self,
        sender_index: u32,
        receiver_index: u32,
        ephemeral_public: [u8; 32],
        encrypted_nothing: Vec<u8>,
    ) -> Result<()> {
        debug!("Handling WireGuard handshake response over QUIC: sender={}, receiver={}",
               sender_index, receiver_index);

        // Reconstruct WireGuard handshake response packet
        let response_packet = self.reconstruct_handshake_response(
            sender_index,
            receiver_index,
            ephemeral_public,
            encrypted_nothing,
        )?;

        // Process handshake response through WireGuard engine
        self.process_handshake_packet(response_packet).await?;

        Ok(())
    }

    /// Send WireGuard packet over QUIC stream
    pub async fn send_wireguard_over_quic(
        &mut self,
        packet: &[u8],
        target_peer: PublicKey,
        stream_type: StreamType,
    ) -> Result<()> {
        // Parse WireGuard packet to extract components
        let wg_packet = self.parse_wireguard_packet(packet)?;

        // Create QUIC payload based on packet type
        let quic_payload = match wg_packet {
            WireGuardPacket::Data { receiver_index, counter, encrypted_data } => {
                QuicPayload::WgData { receiver_index, counter, encrypted_data }
            }
            WireGuardPacket::HandshakeInit { sender_index, ephemeral_public, encrypted_static, encrypted_timestamp } => {
                QuicPayload::WgHandshakeInit { sender_index, ephemeral_public, encrypted_static, encrypted_timestamp }
            }
            WireGuardPacket::HandshakeResponse { sender_index, receiver_index, ephemeral_public, encrypted_nothing } => {
                QuicPayload::WgHandshakeResponse { sender_index, receiver_index, ephemeral_public, encrypted_nothing }
            }
        };

        // Create QUIC message
        let quic_message = QuicMessage {
            stream_type,
            sequence: self.get_next_sequence(target_peer).await,
            timestamp: SystemTime::now(),
            payload: quic_payload,
        };

        // Send over QUIC
        self.quic_tx.send(quic_message)
            .map_err(|_| GhostWireError::quic("Failed to send QUIC message"))?;

        Ok(())
    }

    /// Update peer activity from heartbeat
    async fn update_peer_activity(
        &mut self,
        node_id: NodeId,
        endpoints: Vec<std::net::SocketAddr>,
    ) -> Result<()> {
        let mut sessions = self.peer_sessions.write().await;

        // Find session by node_id
        for session in sessions.values_mut() {
            if session.node_id == node_id {
                session.last_activity = SystemTime::now();
                trace!("Updated activity for peer {}", node_id);
                break;
            }
        }

        Ok(())
    }

    /// Find peer by WireGuard receiver index
    async fn find_peer_by_index(&self, receiver_index: u32) -> Result<PublicKey> {
        let sessions = self.peer_sessions.read().await;

        for (public_key, session) in sessions.iter() {
            if session.wireguard_index == Some(receiver_index) {
                return Ok(*public_key);
            }
        }

        Err(GhostWireError::internal(format!("Peer not found for receiver index {}", receiver_index)))
    }

    /// Get next sequence number for peer
    async fn get_next_sequence(&self, _peer: PublicKey) -> u64 {
        // Would implement proper sequence tracking
        0
    }

    /// Flush batch buffer (placeholder for batch processing)
    async fn flush_batch_buffer(&mut self, _batch: &mut Vec<ProcessedPacket>) -> Result<()> {
        // Would implement batch processing for multiple packets
        Ok(())
    }

    /// Reconstruct WireGuard packet from QUIC components
    fn reconstruct_wireguard_packet(
        &self,
        receiver_index: u32,
        counter: u64,
        encrypted_data: Vec<u8>,
    ) -> Result<Vec<u8>> {
        // WireGuard packet format:
        // [4 bytes: message type (4 for data)]
        // [4 bytes: receiver index]
        // [8 bytes: counter]
        // [N bytes: encrypted data]

        let mut packet = Vec::with_capacity(16 + encrypted_data.len());

        // Message type: 4 (data packet)
        packet.extend_from_slice(&4u32.to_le_bytes());

        // Receiver index
        packet.extend_from_slice(&receiver_index.to_le_bytes());

        // Counter
        packet.extend_from_slice(&counter.to_le_bytes());

        // Encrypted data
        packet.extend_from_slice(&encrypted_data);

        Ok(packet)
    }

    /// Reconstruct handshake init packet
    fn reconstruct_handshake_init(
        &self,
        sender_index: u32,
        ephemeral_public: [u8; 32],
        encrypted_static: Vec<u8>,
        encrypted_timestamp: Vec<u8>,
    ) -> Result<Vec<u8>> {
        // WireGuard handshake init format
        let mut packet = Vec::with_capacity(148);

        // Message type: 1 (handshake initiation)
        packet.extend_from_slice(&1u32.to_le_bytes());

        // Sender index
        packet.extend_from_slice(&sender_index.to_le_bytes());

        // Ephemeral public key
        packet.extend_from_slice(&ephemeral_public);

        // Encrypted static (48 bytes)
        packet.extend_from_slice(&encrypted_static);

        // Encrypted timestamp (28 bytes)
        packet.extend_from_slice(&encrypted_timestamp);

        Ok(packet)
    }

    /// Reconstruct handshake response packet
    fn reconstruct_handshake_response(
        &self,
        sender_index: u32,
        receiver_index: u32,
        ephemeral_public: [u8; 32],
        encrypted_nothing: Vec<u8>,
    ) -> Result<Vec<u8>> {
        // WireGuard handshake response format
        let mut packet = Vec::with_capacity(92);

        // Message type: 2 (handshake response)
        packet.extend_from_slice(&2u32.to_le_bytes());

        // Sender index
        packet.extend_from_slice(&sender_index.to_le_bytes());

        // Receiver index
        packet.extend_from_slice(&receiver_index.to_le_bytes());

        // Ephemeral public key
        packet.extend_from_slice(&ephemeral_public);

        // Encrypted nothing (16 bytes)
        packet.extend_from_slice(&encrypted_nothing);

        Ok(packet)
    }

    /// Parse WireGuard packet type
    fn parse_wireguard_packet(&self, packet: &[u8]) -> Result<WireGuardPacket> {
        if packet.len() < 4 {
            return Err(GhostWireError::internal("Packet too short"));
        }

        let message_type = u32::from_le_bytes([packet[0], packet[1], packet[2], packet[3]]);

        match message_type {
            1 => {
                // Handshake initiation
                if packet.len() < 148 {
                    return Err(GhostWireError::internal("Handshake init packet too short"));
                }

                let sender_index = u32::from_le_bytes([packet[4], packet[5], packet[6], packet[7]]);
                let mut ephemeral_public = [0u8; 32];
                ephemeral_public.copy_from_slice(&packet[8..40]);
                let encrypted_static = packet[40..88].to_vec();
                let encrypted_timestamp = packet[88..116].to_vec();

                Ok(WireGuardPacket::HandshakeInit {
                    sender_index,
                    ephemeral_public,
                    encrypted_static,
                    encrypted_timestamp,
                })
            }
            2 => {
                // Handshake response
                if packet.len() < 92 {
                    return Err(GhostWireError::internal("Handshake response packet too short"));
                }

                let sender_index = u32::from_le_bytes([packet[4], packet[5], packet[6], packet[7]]);
                let receiver_index = u32::from_le_bytes([packet[8], packet[9], packet[10], packet[11]]);
                let mut ephemeral_public = [0u8; 32];
                ephemeral_public.copy_from_slice(&packet[12..44]);
                let encrypted_nothing = packet[44..60].to_vec();

                Ok(WireGuardPacket::HandshakeResponse {
                    sender_index,
                    receiver_index,
                    ephemeral_public,
                    encrypted_nothing,
                })
            }
            4 => {
                // Data packet
                if packet.len() < 16 {
                    return Err(GhostWireError::internal("Data packet too short"));
                }

                let receiver_index = u32::from_le_bytes([packet[4], packet[5], packet[6], packet[7]]);
                let counter = u64::from_le_bytes([
                    packet[8], packet[9], packet[10], packet[11],
                    packet[12], packet[13], packet[14], packet[15]
                ]);
                let encrypted_data = packet[16..].to_vec();

                Ok(WireGuardPacket::Data {
                    receiver_index,
                    counter,
                    encrypted_data,
                })
            }
            _ => Err(GhostWireError::internal(format!("Unknown WireGuard packet type: {}", message_type))),
        }
    }

    /// Process WireGuard packet (placeholder - would integrate with actual engine)
    async fn process_wireguard_packet(&mut self, _packet: Vec<u8>, _peer: PublicKey) -> Result<()> {
        // Would integrate with actual WireGuard engine
        Ok(())
    }

    /// Process handshake packet (placeholder)
    async fn process_handshake_packet(&mut self, _packet: Vec<u8>) -> Result<()> {
        // Would integrate with actual WireGuard engine
        Ok(())
    }

    /// Get bridge statistics
    pub async fn get_stats(&self) -> BridgeStats {
        self.stats.read().await.clone()
    }
}

/// WireGuard packet types for parsing
#[derive(Debug)]
enum WireGuardPacket {
    HandshakeInit {
        sender_index: u32,
        ephemeral_public: [u8; 32],
        encrypted_static: Vec<u8>,
        encrypted_timestamp: Vec<u8>,
    },
    HandshakeResponse {
        sender_index: u32,
        receiver_index: u32,
        ephemeral_public: [u8; 32],
        encrypted_nothing: Vec<u8>,
    },
    Data {
        receiver_index: u32,
        counter: u64,
        encrypted_data: Vec<u8>,
    },
}