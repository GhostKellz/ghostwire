use ghostwire_common::{
    error::{Result, GhostWireError},
    types::PublicKey,
};

/// WireGuard packet format definitions and parsing
///
/// This module handles the binary format of WireGuard packets:
/// - Handshake Initiation (Type 1)
/// - Handshake Response (Type 2)
/// - Cookie Reply (Type 3)
/// - Transport Data (Type 4)

/// WireGuard message types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    HandshakeInitiation = 1,
    HandshakeResponse = 2,
    CookieReply = 3,
    TransportData = 4,
}

impl MessageType {
    pub fn from_u32(value: u32) -> Option<Self> {
        match value {
            1 => Some(MessageType::HandshakeInitiation),
            2 => Some(MessageType::HandshakeResponse),
            3 => Some(MessageType::CookieReply),
            4 => Some(MessageType::TransportData),
            _ => None,
        }
    }
}

/// Parsed WireGuard packet
#[derive(Debug, Clone)]
pub enum WireGuardPacket {
    HandshakeInitiation {
        sender_index: u32,
        ephemeral_public: [u8; 32],
        encrypted_static: [u8; 48],
        encrypted_timestamp: [u8; 28],
        mac1: [u8; 16],
        mac2: [u8; 16],
    },
    HandshakeResponse {
        sender_index: u32,
        receiver_index: u32,
        ephemeral_public: [u8; 32],
        encrypted_nothing: [u8; 16],
        mac1: [u8; 16],
        mac2: [u8; 16],
    },
    CookieReply {
        receiver_index: u32,
        nonce: [u8; 24],
        encrypted_cookie: [u8; 32],
    },
    TransportData {
        receiver_index: u32,
        counter: u64,
        encrypted_data: Vec<u8>,
    },
}

/// WireGuard packet parser
pub struct PacketParser;

impl PacketParser {
    /// Parse raw bytes into WireGuard packet
    pub fn parse(data: &[u8]) -> Result<WireGuardPacket> {
        if data.len() < 4 {
            return Err(GhostWireError::internal("Packet too short"));
        }

        let message_type = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let msg_type = MessageType::from_u32(message_type)
            .ok_or_else(|| GhostWireError::internal(format!("Invalid message type: {}", message_type)))?;

        match msg_type {
            MessageType::HandshakeInitiation => Self::parse_handshake_initiation(&data[4..]),
            MessageType::HandshakeResponse => Self::parse_handshake_response(&data[4..]),
            MessageType::CookieReply => Self::parse_cookie_reply(&data[4..]),
            MessageType::TransportData => Self::parse_transport_data(&data[4..]),
        }
    }

    fn parse_handshake_initiation(data: &[u8]) -> Result<WireGuardPacket> {
        if data.len() < 144 {
            return Err(GhostWireError::internal("Handshake initiation packet too short"));
        }

        let sender_index = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);

        let mut ephemeral_public = [0u8; 32];
        ephemeral_public.copy_from_slice(&data[4..36]);

        let mut encrypted_static = [0u8; 48];
        encrypted_static.copy_from_slice(&data[36..84]);

        let mut encrypted_timestamp = [0u8; 28];
        encrypted_timestamp.copy_from_slice(&data[84..112]);

        let mut mac1 = [0u8; 16];
        mac1.copy_from_slice(&data[112..128]);

        let mut mac2 = [0u8; 16];
        mac2.copy_from_slice(&data[128..144]);

        Ok(WireGuardPacket::HandshakeInitiation {
            sender_index,
            ephemeral_public,
            encrypted_static,
            encrypted_timestamp,
            mac1,
            mac2,
        })
    }

    fn parse_handshake_response(data: &[u8]) -> Result<WireGuardPacket> {
        if data.len() < 88 {
            return Err(GhostWireError::internal("Handshake response packet too short"));
        }

        let sender_index = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let receiver_index = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);

        let mut ephemeral_public = [0u8; 32];
        ephemeral_public.copy_from_slice(&data[8..40]);

        let mut encrypted_nothing = [0u8; 16];
        encrypted_nothing.copy_from_slice(&data[40..56]);

        let mut mac1 = [0u8; 16];
        mac1.copy_from_slice(&data[56..72]);

        let mut mac2 = [0u8; 16];
        mac2.copy_from_slice(&data[72..88]);

        Ok(WireGuardPacket::HandshakeResponse {
            sender_index,
            receiver_index,
            ephemeral_public,
            encrypted_nothing,
            mac1,
            mac2,
        })
    }

    fn parse_cookie_reply(data: &[u8]) -> Result<WireGuardPacket> {
        if data.len() < 60 {
            return Err(GhostWireError::internal("Cookie reply packet too short"));
        }

        let receiver_index = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);

        let mut nonce = [0u8; 24];
        nonce.copy_from_slice(&data[4..28]);

        let mut encrypted_cookie = [0u8; 32];
        encrypted_cookie.copy_from_slice(&data[28..60]);

        Ok(WireGuardPacket::CookieReply {
            receiver_index,
            nonce,
            encrypted_cookie,
        })
    }

    fn parse_transport_data(data: &[u8]) -> Result<WireGuardPacket> {
        if data.len() < 12 {
            return Err(GhostWireError::internal("Transport data packet too short"));
        }

        let receiver_index = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let counter = u64::from_le_bytes([
            data[4], data[5], data[6], data[7],
            data[8], data[9], data[10], data[11]
        ]);

        let encrypted_data = data[12..].to_vec();

        Ok(WireGuardPacket::TransportData {
            receiver_index,
            counter,
            encrypted_data,
        })
    }

    /// Serialize packet back to bytes
    pub fn serialize(packet: &WireGuardPacket) -> Vec<u8> {
        match packet {
            WireGuardPacket::HandshakeInitiation {
                sender_index,
                ephemeral_public,
                encrypted_static,
                encrypted_timestamp,
                mac1,
                mac2,
            } => {
                let mut data = Vec::with_capacity(148);
                data.extend_from_slice(&1u32.to_le_bytes()); // Message type
                data.extend_from_slice(&sender_index.to_le_bytes());
                data.extend_from_slice(ephemeral_public);
                data.extend_from_slice(encrypted_static);
                data.extend_from_slice(encrypted_timestamp);
                data.extend_from_slice(mac1);
                data.extend_from_slice(mac2);
                data
            }
            WireGuardPacket::HandshakeResponse {
                sender_index,
                receiver_index,
                ephemeral_public,
                encrypted_nothing,
                mac1,
                mac2,
            } => {
                let mut data = Vec::with_capacity(92);
                data.extend_from_slice(&2u32.to_le_bytes()); // Message type
                data.extend_from_slice(&sender_index.to_le_bytes());
                data.extend_from_slice(&receiver_index.to_le_bytes());
                data.extend_from_slice(ephemeral_public);
                data.extend_from_slice(encrypted_nothing);
                data.extend_from_slice(mac1);
                data.extend_from_slice(mac2);
                data
            }
            WireGuardPacket::CookieReply {
                receiver_index,
                nonce,
                encrypted_cookie,
            } => {
                let mut data = Vec::with_capacity(64);
                data.extend_from_slice(&3u32.to_le_bytes()); // Message type
                data.extend_from_slice(&receiver_index.to_le_bytes());
                data.extend_from_slice(nonce);
                data.extend_from_slice(encrypted_cookie);
                data
            }
            WireGuardPacket::TransportData {
                receiver_index,
                counter,
                encrypted_data,
            } => {
                let mut data = Vec::with_capacity(16 + encrypted_data.len());
                data.extend_from_slice(&4u32.to_le_bytes()); // Message type
                data.extend_from_slice(&receiver_index.to_le_bytes());
                data.extend_from_slice(&counter.to_le_bytes());
                data.extend_from_slice(encrypted_data);
                data
            }
        }
    }

    /// Extract public key from handshake initiation (if available)
    pub fn extract_public_key(packet: &WireGuardPacket) -> Option<PublicKey> {
        match packet {
            WireGuardPacket::HandshakeInitiation { ephemeral_public, .. } => {
                Some(PublicKey::from_bytes(*ephemeral_public))
            }
            WireGuardPacket::HandshakeResponse { ephemeral_public, .. } => {
                Some(PublicKey::from_bytes(*ephemeral_public))
            }
            _ => None,
        }
    }

    /// Get receiver index from packet
    pub fn get_receiver_index(packet: &WireGuardPacket) -> Option<u32> {
        match packet {
            WireGuardPacket::HandshakeResponse { receiver_index, .. } => Some(*receiver_index),
            WireGuardPacket::CookieReply { receiver_index, .. } => Some(*receiver_index),
            WireGuardPacket::TransportData { receiver_index, .. } => Some(*receiver_index),
            _ => None,
        }
    }

    /// Get sender index from packet
    pub fn get_sender_index(packet: &WireGuardPacket) -> Option<u32> {
        match packet {
            WireGuardPacket::HandshakeInitiation { sender_index, .. } => Some(*sender_index),
            WireGuardPacket::HandshakeResponse { sender_index, .. } => Some(*sender_index),
            _ => None,
        }
    }

    /// Check if packet is a handshake packet
    pub fn is_handshake(packet: &WireGuardPacket) -> bool {
        matches!(
            packet,
            WireGuardPacket::HandshakeInitiation { .. } | WireGuardPacket::HandshakeResponse { .. }
        )
    }

    /// Check if packet is data packet
    pub fn is_data(packet: &WireGuardPacket) -> bool {
        matches!(packet, WireGuardPacket::TransportData { .. })
    }
}