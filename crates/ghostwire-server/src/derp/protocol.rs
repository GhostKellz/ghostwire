/// DERP protocol implementation
///
/// Implements the core DERP protocol for relay messaging between nodes
/// including packet framing, authentication, and mesh forwarding.

use ghostwire_common::{
    types::*,
    error::{Result, GhostWireError},
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, Duration};
use uuid::Uuid;

/// DERP protocol version
pub const DERP_VERSION: u8 = 2;

/// Maximum packet size
pub const MAX_PACKET_SIZE: usize = 64 * 1024; // 64KB

/// DERP frame types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameType {
    /// Server info frame
    ServerInfo = 1,
    /// Client info frame
    ClientInfo = 2,
    /// Send packet frame
    SendPacket = 3,
    /// Receive packet frame
    RecvPacket = 4,
    /// Keep alive frame
    KeepAlive = 5,
    /// Note preference frame
    NotePreference = 6,
    /// Ping frame
    Ping = 7,
    /// Pong frame
    Pong = 8,
    /// Health check frame
    Health = 9,
    /// Restarting frame
    Restarting = 10,
    /// Mesh key frame
    MeshKey = 11,
    /// Peer gone frame
    PeerGone = 12,
    /// Forward packet frame
    ForwardPacket = 13,
    /// Watch connection changes
    WatchConnectionChanges = 14,
    /// Close peer frame
    ClosePeer = 15,
}

impl TryFrom<u8> for FrameType {
    type Error = GhostWireError;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            1 => Ok(FrameType::ServerInfo),
            2 => Ok(FrameType::ClientInfo),
            3 => Ok(FrameType::SendPacket),
            4 => Ok(FrameType::RecvPacket),
            5 => Ok(FrameType::KeepAlive),
            6 => Ok(FrameType::NotePreference),
            7 => Ok(FrameType::Ping),
            8 => Ok(FrameType::Pong),
            9 => Ok(FrameType::Health),
            10 => Ok(FrameType::Restarting),
            11 => Ok(FrameType::MeshKey),
            12 => Ok(FrameType::PeerGone),
            13 => Ok(FrameType::ForwardPacket),
            14 => Ok(FrameType::WatchConnectionChanges),
            15 => Ok(FrameType::ClosePeer),
            _ => Err(GhostWireError::protocol(format!("Unknown frame type: {}", value))),
        }
    }
}

/// DERP frame
#[derive(Debug, Clone)]
pub struct DerpFrame {
    /// Frame type
    pub frame_type: FrameType,
    /// Frame payload
    pub payload: Vec<u8>,
}

impl DerpFrame {
    /// Create a new frame
    pub fn new(frame_type: FrameType, payload: Vec<u8>) -> Self {
        Self { frame_type, payload }
    }

    /// Encode frame to bytes
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();

        // Frame type (1 byte)
        bytes.push(self.frame_type as u8);

        // Payload length (4 bytes, big-endian)
        let payload_len = self.payload.len() as u32;
        if payload_len > MAX_PACKET_SIZE as u32 {
            return Err(GhostWireError::protocol(format!(
                "Payload too large: {} bytes (max: {})",
                payload_len, MAX_PACKET_SIZE
            )));
        }
        bytes.extend_from_slice(&payload_len.to_be_bytes());

        // Payload
        bytes.extend_from_slice(&self.payload);

        Ok(bytes)
    }

    /// Decode frame from bytes
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 5 {
            return Err(GhostWireError::protocol("Frame too short"));
        }

        // Parse frame type
        let frame_type = FrameType::try_from(bytes[0])?;

        // Parse payload length
        let payload_len = u32::from_be_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]) as usize;

        if payload_len > MAX_PACKET_SIZE {
            return Err(GhostWireError::protocol(format!(
                "Payload too large: {} bytes", payload_len
            )));
        }

        if bytes.len() < 5 + payload_len {
            return Err(GhostWireError::protocol("Incomplete frame"));
        }

        // Extract payload
        let payload = bytes[5..5 + payload_len].to_vec();

        Ok(Self { frame_type, payload })
    }
}

/// Server info message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerInfo {
    /// DERP protocol version
    pub version: u8,
    /// Server region ID
    pub region_id: u16,
    /// Server capabilities
    pub capabilities: ServerCapabilities,
    /// Mesh key required
    pub mesh_key_required: bool,
    /// Server start time
    pub start_time: SystemTime,
}

/// Server capabilities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerCapabilities {
    /// Supports mesh forwarding
    pub mesh_forwarding: bool,
    /// Supports QUIC
    pub quic_support: bool,
    /// Supports compression
    pub compression: bool,
    /// Maximum clients
    pub max_clients: u32,
    /// Rate limiting enabled
    pub rate_limiting: bool,
}

/// Client info message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientInfo {
    /// Client node ID
    pub node_id: NodeId,
    /// Client public key
    pub public_key: PublicKey,
    /// Client mesh key (if required)
    pub mesh_key: Option<String>,
    /// Client capabilities
    pub capabilities: ClientCapabilities,
    /// Preferred region
    pub preferred_region: Option<u16>,
}

/// Client capabilities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientCapabilities {
    /// Supports compression
    pub compression: bool,
    /// Supports mesh forwarding
    pub mesh_forwarding: bool,
    /// Client version
    pub client_version: String,
    /// Operating system
    pub operating_system: String,
}

/// Send packet message
#[derive(Debug, Clone)]
pub struct SendPacket {
    /// Destination node ID
    pub dst_node_id: NodeId,
    /// Packet data
    pub data: Vec<u8>,
}

impl SendPacket {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();

        // Destination node ID (16 bytes)
        bytes.extend_from_slice(self.dst_node_id.as_bytes());

        // Packet data
        bytes.extend_from_slice(&self.data);

        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 16 {
            return Err(GhostWireError::protocol("SendPacket frame too short"));
        }

        // Parse destination node ID
        let dst_node_id = Uuid::from_slice(&bytes[0..16])
            .map_err(|_| GhostWireError::protocol("Invalid destination node ID"))?;

        // Extract packet data
        let data = bytes[16..].to_vec();

        Ok(Self { dst_node_id, data })
    }
}

/// Receive packet message
#[derive(Debug, Clone)]
pub struct RecvPacket {
    /// Source node ID
    pub src_node_id: NodeId,
    /// Packet data
    pub data: Vec<u8>,
}

impl RecvPacket {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();

        // Source node ID (16 bytes)
        bytes.extend_from_slice(self.src_node_id.as_bytes());

        // Packet data
        bytes.extend_from_slice(&self.data);

        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 16 {
            return Err(GhostWireError::protocol("RecvPacket frame too short"));
        }

        // Parse source node ID
        let src_node_id = Uuid::from_slice(&bytes[0..16])
            .map_err(|_| GhostWireError::protocol("Invalid source node ID"))?;

        // Extract packet data
        let data = bytes[16..].to_vec();

        Ok(Self { src_node_id, data })
    }
}

/// Note preference message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotePreference {
    /// Preferred region
    pub preferred_region: u16,
    /// Secondary regions
    pub secondary_regions: Vec<u16>,
    /// Connection quality metrics
    pub quality_metrics: Option<ConnectionQuality>,
}

/// Connection quality metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionQuality {
    /// Round-trip time (ms)
    pub rtt_ms: u32,
    /// Packet loss percentage
    pub packet_loss: f32,
    /// Jitter (ms)
    pub jitter_ms: u32,
    /// Bandwidth estimate (bytes/sec)
    pub bandwidth_bps: u64,
}

/// Ping message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ping {
    /// Ping ID
    pub ping_id: u32,
    /// Timestamp
    pub timestamp: SystemTime,
    /// Optional payload
    pub payload: Option<Vec<u8>>,
}

/// Pong message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pong {
    /// Original ping ID
    pub ping_id: u32,
    /// Server timestamp
    pub server_timestamp: SystemTime,
    /// Optional payload echo
    pub payload: Option<Vec<u8>>,
}

/// Health check response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Health {
    /// Server healthy
    pub healthy: bool,
    /// Active connections
    pub active_connections: u32,
    /// Server load (0.0 - 1.0)
    pub server_load: f32,
    /// Optional status message
    pub status_message: Option<String>,
}

/// Mesh key message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshKey {
    /// Mesh key
    pub key: String,
    /// Key validity period
    pub valid_until: SystemTime,
    /// Regional scope
    pub regions: Vec<u16>,
}

/// Peer gone notification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerGone {
    /// Node ID that disconnected
    pub node_id: NodeId,
    /// Reason for disconnection
    pub reason: DisconnectReason,
    /// Timestamp
    pub timestamp: SystemTime,
}

/// Disconnect reason
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisconnectReason {
    /// Client disconnected normally
    ClientDisconnect,
    /// Connection timeout
    Timeout,
    /// Authentication failure
    AuthFailure,
    /// Rate limit exceeded
    RateLimit,
    /// Server restart
    ServerRestart,
    /// Protocol error
    ProtocolError,
    /// Mesh forwarding error
    MeshError,
}

/// Forward packet message (for mesh)
#[derive(Debug, Clone)]
pub struct ForwardPacket {
    /// Original source node ID
    pub src_node_id: NodeId,
    /// Destination node ID
    pub dst_node_id: NodeId,
    /// Packet data
    pub data: Vec<u8>,
    /// Forwarding hop count
    pub hop_count: u8,
}

impl ForwardPacket {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();

        // Source node ID (16 bytes)
        bytes.extend_from_slice(self.src_node_id.as_bytes());

        // Destination node ID (16 bytes)
        bytes.extend_from_slice(self.dst_node_id.as_bytes());

        // Hop count (1 byte)
        bytes.push(self.hop_count);

        // Packet data
        bytes.extend_from_slice(&self.data);

        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 33 {
            return Err(GhostWireError::protocol("ForwardPacket frame too short"));
        }

        // Parse source node ID
        let src_node_id = Uuid::from_slice(&bytes[0..16])
            .map_err(|_| GhostWireError::protocol("Invalid source node ID"))?;

        // Parse destination node ID
        let dst_node_id = Uuid::from_slice(&bytes[16..32])
            .map_err(|_| GhostWireError::protocol("Invalid destination node ID"))?;

        // Parse hop count
        let hop_count = bytes[32];

        // Extract packet data
        let data = bytes[33..].to_vec();

        Ok(Self {
            src_node_id,
            dst_node_id,
            data,
            hop_count,
        })
    }
}

/// Watch connection changes message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchConnectionChanges {
    /// Enable watching
    pub enabled: bool,
    /// Filter by regions
    pub region_filter: Option<Vec<u16>>,
    /// Include detailed metrics
    pub include_metrics: bool,
}

/// Close peer message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClosePeer {
    /// Node ID to close
    pub node_id: NodeId,
    /// Reason for closing
    pub reason: DisconnectReason,
    /// Graceful close
    pub graceful: bool,
}

/// Protocol handler for encoding/decoding messages
pub struct ProtocolHandler;

impl ProtocolHandler {
    /// Create server info frame
    pub fn create_server_info(info: &ServerInfo) -> Result<DerpFrame> {
        let payload = serde_json::to_vec(info)
            .map_err(|e| GhostWireError::protocol(format!("Failed to encode server info: {}", e)))?;

        Ok(DerpFrame::new(FrameType::ServerInfo, payload))
    }

    /// Parse server info frame
    pub fn parse_server_info(frame: &DerpFrame) -> Result<ServerInfo> {
        if frame.frame_type != FrameType::ServerInfo {
            return Err(GhostWireError::protocol("Expected ServerInfo frame"));
        }

        serde_json::from_slice(&frame.payload)
            .map_err(|e| GhostWireError::protocol(format!("Failed to decode server info: {}", e)))
    }

    /// Create client info frame
    pub fn create_client_info(info: &ClientInfo) -> Result<DerpFrame> {
        let payload = serde_json::to_vec(info)
            .map_err(|e| GhostWireError::protocol(format!("Failed to encode client info: {}", e)))?;

        Ok(DerpFrame::new(FrameType::ClientInfo, payload))
    }

    /// Parse client info frame
    pub fn parse_client_info(frame: &DerpFrame) -> Result<ClientInfo> {
        if frame.frame_type != FrameType::ClientInfo {
            return Err(GhostWireError::protocol("Expected ClientInfo frame"));
        }

        serde_json::from_slice(&frame.payload)
            .map_err(|e| GhostWireError::protocol(format!("Failed to decode client info: {}", e)))
    }

    /// Create send packet frame
    pub fn create_send_packet(packet: &SendPacket) -> Result<DerpFrame> {
        let payload = packet.encode()?;
        Ok(DerpFrame::new(FrameType::SendPacket, payload))
    }

    /// Parse send packet frame
    pub fn parse_send_packet(frame: &DerpFrame) -> Result<SendPacket> {
        if frame.frame_type != FrameType::SendPacket {
            return Err(GhostWireError::protocol("Expected SendPacket frame"));
        }

        SendPacket::decode(&frame.payload)
    }

    /// Create receive packet frame
    pub fn create_recv_packet(packet: &RecvPacket) -> Result<DerpFrame> {
        let payload = packet.encode()?;
        Ok(DerpFrame::new(FrameType::RecvPacket, payload))
    }

    /// Parse receive packet frame
    pub fn parse_recv_packet(frame: &DerpFrame) -> Result<RecvPacket> {
        if frame.frame_type != FrameType::RecvPacket {
            return Err(GhostWireError::protocol("Expected RecvPacket frame"));
        }

        RecvPacket::decode(&frame.payload)
    }

    /// Create ping frame
    pub fn create_ping(ping: &Ping) -> Result<DerpFrame> {
        let payload = serde_json::to_vec(ping)
            .map_err(|e| GhostWireError::protocol(format!("Failed to encode ping: {}", e)))?;

        Ok(DerpFrame::new(FrameType::Ping, payload))
    }

    /// Parse ping frame
    pub fn parse_ping(frame: &DerpFrame) -> Result<Ping> {
        if frame.frame_type != FrameType::Ping {
            return Err(GhostWireError::protocol("Expected Ping frame"));
        }

        serde_json::from_slice(&frame.payload)
            .map_err(|e| GhostWireError::protocol(format!("Failed to decode ping: {}", e)))
    }

    /// Create pong frame
    pub fn create_pong(pong: &Pong) -> Result<DerpFrame> {
        let payload = serde_json::to_vec(pong)
            .map_err(|e| GhostWireError::protocol(format!("Failed to encode pong: {}", e)))?;

        Ok(DerpFrame::new(FrameType::Pong, payload))
    }

    /// Parse pong frame
    pub fn parse_pong(frame: &DerpFrame) -> Result<Pong> {
        if frame.frame_type != FrameType::Pong {
            return Err(GhostWireError::protocol("Expected Pong frame"));
        }

        serde_json::from_slice(&frame.payload)
            .map_err(|e| GhostWireError::protocol(format!("Failed to decode pong: {}", e)))
    }

    /// Create keep alive frame
    pub fn create_keep_alive() -> DerpFrame {
        DerpFrame::new(FrameType::KeepAlive, vec![])
    }

    /// Create health frame
    pub fn create_health(health: &Health) -> Result<DerpFrame> {
        let payload = serde_json::to_vec(health)
            .map_err(|e| GhostWireError::protocol(format!("Failed to encode health: {}", e)))?;

        Ok(DerpFrame::new(FrameType::Health, payload))
    }

    /// Parse health frame
    pub fn parse_health(frame: &DerpFrame) -> Result<Health> {
        if frame.frame_type != FrameType::Health {
            return Err(GhostWireError::protocol("Expected Health frame"));
        }

        serde_json::from_slice(&frame.payload)
            .map_err(|e| GhostWireError::protocol(format!("Failed to decode health: {}", e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::SystemTime;

    #[test]
    fn test_frame_type_conversion() {
        assert_eq!(FrameType::try_from(1).unwrap(), FrameType::ServerInfo);
        assert_eq!(FrameType::try_from(3).unwrap(), FrameType::SendPacket);
        assert!(FrameType::try_from(255).is_err());
    }

    #[test]
    fn test_derp_frame_encoding() {
        let frame = DerpFrame::new(FrameType::KeepAlive, vec![1, 2, 3, 4]);
        let encoded = frame.encode().unwrap();

        assert_eq!(encoded[0], FrameType::KeepAlive as u8);
        assert_eq!(u32::from_be_bytes([encoded[1], encoded[2], encoded[3], encoded[4]]), 4);
        assert_eq!(&encoded[5..], &[1, 2, 3, 4]);
    }

    #[test]
    fn test_derp_frame_decoding() {
        let mut bytes = vec![FrameType::KeepAlive as u8];
        bytes.extend_from_slice(&4u32.to_be_bytes());
        bytes.extend_from_slice(&[1, 2, 3, 4]);

        let frame = DerpFrame::decode(&bytes).unwrap();
        assert_eq!(frame.frame_type, FrameType::KeepAlive);
        assert_eq!(frame.payload, vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_send_packet_encoding() {
        let packet = SendPacket {
            dst_node_id: Uuid::new_v4(),
            data: vec![1, 2, 3, 4, 5],
        };

        let encoded = packet.encode().unwrap();
        assert_eq!(encoded.len(), 16 + 5); // UUID + data

        let decoded = SendPacket::decode(&encoded).unwrap();
        assert_eq!(decoded.dst_node_id, packet.dst_node_id);
        assert_eq!(decoded.data, packet.data);
    }

    #[test]
    fn test_recv_packet_encoding() {
        let packet = RecvPacket {
            src_node_id: Uuid::new_v4(),
            data: vec![5, 4, 3, 2, 1],
        };

        let encoded = packet.encode().unwrap();
        assert_eq!(encoded.len(), 16 + 5); // UUID + data

        let decoded = RecvPacket::decode(&encoded).unwrap();
        assert_eq!(decoded.src_node_id, packet.src_node_id);
        assert_eq!(decoded.data, packet.data);
    }

    #[test]
    fn test_forward_packet_encoding() {
        let packet = ForwardPacket {
            src_node_id: Uuid::new_v4(),
            dst_node_id: Uuid::new_v4(),
            data: vec![1, 2, 3],
            hop_count: 5,
        };

        let encoded = packet.encode().unwrap();
        assert_eq!(encoded.len(), 16 + 16 + 1 + 3); // src UUID + dst UUID + hop count + data

        let decoded = ForwardPacket::decode(&encoded).unwrap();
        assert_eq!(decoded.src_node_id, packet.src_node_id);
        assert_eq!(decoded.dst_node_id, packet.dst_node_id);
        assert_eq!(decoded.data, packet.data);
        assert_eq!(decoded.hop_count, packet.hop_count);
    }

    #[test]
    fn test_protocol_handler_server_info() {
        let server_info = ServerInfo {
            version: DERP_VERSION,
            region_id: 1,
            capabilities: ServerCapabilities {
                mesh_forwarding: true,
                quic_support: true,
                compression: true,
                max_clients: 1000,
                rate_limiting: true,
            },
            mesh_key_required: false,
            start_time: SystemTime::now(),
        };

        let frame = ProtocolHandler::create_server_info(&server_info).unwrap();
        let parsed = ProtocolHandler::parse_server_info(&frame).unwrap();

        assert_eq!(parsed.version, server_info.version);
        assert_eq!(parsed.region_id, server_info.region_id);
        assert_eq!(parsed.capabilities.mesh_forwarding, server_info.capabilities.mesh_forwarding);
    }

    #[test]
    fn test_ping_pong_round_trip() {
        let ping = Ping {
            ping_id: 12345,
            timestamp: SystemTime::now(),
            payload: Some(vec![1, 2, 3]),
        };

        let ping_frame = ProtocolHandler::create_ping(&ping).unwrap();
        let parsed_ping = ProtocolHandler::parse_ping(&ping_frame).unwrap();

        assert_eq!(parsed_ping.ping_id, ping.ping_id);
        assert_eq!(parsed_ping.payload, ping.payload);

        let pong = Pong {
            ping_id: parsed_ping.ping_id,
            server_timestamp: SystemTime::now(),
            payload: parsed_ping.payload,
        };

        let pong_frame = ProtocolHandler::create_pong(&pong).unwrap();
        let parsed_pong = ProtocolHandler::parse_pong(&pong_frame).unwrap();

        assert_eq!(parsed_pong.ping_id, pong.ping_id);
        assert_eq!(parsed_pong.payload, pong.payload);
    }
}