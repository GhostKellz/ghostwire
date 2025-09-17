/// STUN server implementation for NAT traversal
///
/// Provides STUN (Session Traversal Utilities for NAT) functionality
/// integrated with the DERP server for comprehensive NAT traversal support.

use ghostwire_common::{
    types::*,
    error::{Result, GhostWireError},
};
use std::collections::HashMap;
use std::net::{SocketAddr, IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{SystemTime, Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::{RwLock, broadcast};
use tokio::time::{interval, timeout};
use tracing::{debug, warn, error, info};
use uuid::Uuid;
use byteorder::{BigEndian, ByteOrder};
use crc32fast::Hasher;

/// STUN message types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum StunMessageType {
    BindingRequest = 0x0001,
    BindingResponse = 0x0101,
    BindingErrorResponse = 0x0111,
    SharedSecretRequest = 0x0002,
    SharedSecretResponse = 0x0102,
    SharedSecretErrorResponse = 0x0112,
}

impl StunMessageType {
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            0x0001 => Some(Self::BindingRequest),
            0x0101 => Some(Self::BindingResponse),
            0x0111 => Some(Self::BindingErrorResponse),
            0x0002 => Some(Self::SharedSecretRequest),
            0x0102 => Some(Self::SharedSecretResponse),
            0x0112 => Some(Self::SharedSecretErrorResponse),
            _ => None,
        }
    }
}

/// STUN attribute types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum StunAttributeType {
    MappedAddress = 0x0001,
    ResponseAddress = 0x0002,
    ChangeRequest = 0x0003,
    SourceAddress = 0x0004,
    ChangedAddress = 0x0005,
    Username = 0x0006,
    Password = 0x0007,
    MessageIntegrity = 0x0008,
    ErrorCode = 0x0009,
    UnknownAttributes = 0x000A,
    ReflectedFrom = 0x000B,
    XorMappedAddress = 0x0020,
    Fingerprint = 0x8028,
    Software = 0x8022,
}

impl StunAttributeType {
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            0x0001 => Some(Self::MappedAddress),
            0x0002 => Some(Self::ResponseAddress),
            0x0003 => Some(Self::ChangeRequest),
            0x0004 => Some(Self::SourceAddress),
            0x0005 => Some(Self::ChangedAddress),
            0x0006 => Some(Self::Username),
            0x0007 => Some(Self::Password),
            0x0008 => Some(Self::MessageIntegrity),
            0x0009 => Some(Self::ErrorCode),
            0x000A => Some(Self::UnknownAttributes),
            0x000B => Some(Self::ReflectedFrom),
            0x0020 => Some(Self::XorMappedAddress),
            0x8028 => Some(Self::Fingerprint),
            0x8022 => Some(Self::Software),
            _ => None,
        }
    }
}

/// STUN message header
#[derive(Debug, Clone)]
pub struct StunHeader {
    pub message_type: StunMessageType,
    pub message_length: u16,
    pub transaction_id: [u8; 12],
}

/// STUN attribute
#[derive(Debug, Clone)]
pub struct StunAttribute {
    pub attribute_type: StunAttributeType,
    pub length: u16,
    pub value: Vec<u8>,
}

/// STUN message
#[derive(Debug, Clone)]
pub struct StunMessage {
    pub header: StunHeader,
    pub attributes: Vec<StunAttribute>,
}

/// STUN server configuration
#[derive(Debug, Clone)]
pub struct StunServerConfig {
    /// Enable STUN server
    pub enabled: bool,
    /// Listen address
    pub listen_addr: String,
    /// Listen port
    pub listen_port: u16,
    /// Enable fingerprint validation
    pub validate_fingerprint: bool,
    /// Software identifier
    pub software: String,
    /// Rate limiting
    pub rate_limit_per_ip: u32,
    /// Rate limit window (seconds)
    pub rate_limit_window: u64,
}

impl Default for StunServerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            listen_addr: "0.0.0.0".to_string(),
            listen_port: 3478,
            validate_fingerprint: true,
            software: "GhostWire STUN Server".to_string(),
            rate_limit_per_ip: 100,
            rate_limit_window: 60,
        }
    }
}

/// Rate limiting state
#[derive(Debug, Clone)]
struct RateLimitState {
    requests: u32,
    window_start: Instant,
}

/// STUN server statistics
#[derive(Debug, Clone)]
pub struct StunStats {
    pub total_requests: u64,
    pub successful_responses: u64,
    pub error_responses: u64,
    pub rate_limited_requests: u64,
    pub malformed_requests: u64,
    pub binding_requests: u64,
    pub secret_requests: u64,
    pub unique_clients: u64,
}

/// STUN server implementation
pub struct StunServer {
    config: StunServerConfig,
    stats: Arc<RwLock<StunStats>>,
    rate_limits: Arc<RwLock<HashMap<IpAddr, RateLimitState>>>,
    start_time: SystemTime,
}

impl StunServer {
    /// Create a new STUN server
    pub fn new(config: StunServerConfig) -> Self {
        let stats = Arc::new(RwLock::new(StunStats {
            total_requests: 0,
            successful_responses: 0,
            error_responses: 0,
            rate_limited_requests: 0,
            malformed_requests: 0,
            binding_requests: 0,
            secret_requests: 0,
            unique_clients: 0,
        }));

        Self {
            config,
            stats,
            rate_limits: Arc::new(RwLock::new(HashMap::new())),
            start_time: SystemTime::now(),
        }
    }

    /// Handle STUN packet
    pub async fn handle_packet(&self, data: &[u8], client_addr: SocketAddr, socket: &UdpSocket) -> Result<()> {
        // Check rate limiting
        if !self.check_rate_limit(client_addr.ip()).await {
            self.stats.write().await.rate_limited_requests += 1;
            debug!("Rate limited STUN request from {}", client_addr.ip());
            return Ok(());
        }

        // Update statistics
        self.stats.write().await.total_requests += 1;

        // Parse STUN message
        let message = match self.parse_stun_message(data) {
            Ok(msg) => msg,
            Err(e) => {
                self.stats.write().await.malformed_requests += 1;
                debug!("Malformed STUN message from {}: {}", client_addr, e);
                return Ok(());
            }
        };

        // Handle different message types
        match message.header.message_type {
            StunMessageType::BindingRequest => {
                self.stats.write().await.binding_requests += 1;
                self.handle_binding_request(message, client_addr, socket).await?;
            }
            StunMessageType::SharedSecretRequest => {
                self.stats.write().await.secret_requests += 1;
                self.handle_secret_request(message, client_addr, socket).await?;
            }
            _ => {
                debug!("Unsupported STUN message type: {:?}", message.header.message_type);
                self.send_error_response(message, 400, "Bad Request", client_addr, socket).await?;
            }
        }

        Ok(())
    }

    /// Get server statistics
    pub async fn get_stats(&self) -> StunStats {
        self.stats.read().await.clone()
    }

    /// Start rate limit cleanup task
    pub async fn start_cleanup_task(&self, shutdown_rx: broadcast::Receiver<()>) {
        let rate_limits = self.rate_limits.clone();
        let mut shutdown_rx = shutdown_rx;

        tokio::spawn(async move {
            let mut cleanup_interval = interval(Duration::from_secs(60));

            loop {
                tokio::select! {
                    _ = cleanup_interval.tick() => {
                        Self::cleanup_rate_limits(&rate_limits).await;
                    }
                    _ = shutdown_rx.recv() => {
                        debug!("STUN cleanup task stopped");
                        break;
                    }
                }
            }
        });
    }

    // Private implementation methods

    async fn check_rate_limit(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let mut rate_limits = self.rate_limits.write().await;

        let state = rate_limits.entry(ip).or_insert(RateLimitState {
            requests: 0,
            window_start: now,
        });

        // Reset window if it's expired
        if now.duration_since(state.window_start) >= Duration::from_secs(self.config.rate_limit_window) {
            state.requests = 0;
            state.window_start = now;
        }

        // Check if limit exceeded
        if state.requests >= self.config.rate_limit_per_ip {
            return false;
        }

        state.requests += 1;
        true
    }

    async fn cleanup_rate_limits(rate_limits: &Arc<RwLock<HashMap<IpAddr, RateLimitState>>>) {
        let now = Instant::now();
        let mut rate_limits = rate_limits.write().await;

        rate_limits.retain(|_, state| {
            now.duration_since(state.window_start) < Duration::from_secs(300) // Keep for 5 minutes
        });

        debug!("Cleaned up old rate limit entries");
    }

    fn parse_stun_message(&self, data: &[u8]) -> Result<StunMessage> {
        if data.len() < 20 {
            return Err(GhostWireError::protocol("STUN message too short"));
        }

        // Parse header
        let message_type = BigEndian::read_u16(&data[0..2]);
        let message_length = BigEndian::read_u16(&data[2..4]);
        let magic_cookie = BigEndian::read_u32(&data[4..8]);
        let mut transaction_id = [0u8; 12];
        transaction_id.copy_from_slice(&data[8..20]);

        // Validate magic cookie
        if magic_cookie != 0x2112A442 {
            return Err(GhostWireError::protocol("Invalid STUN magic cookie"));
        }

        let message_type = StunMessageType::from_u16(message_type)
            .ok_or_else(|| GhostWireError::protocol("Unknown STUN message type"))?;

        let header = StunHeader {
            message_type,
            message_length,
            transaction_id,
        };

        // Parse attributes
        let mut attributes = Vec::new();
        let mut offset = 20;

        while offset < data.len() && offset < 20 + message_length as usize {
            if offset + 4 > data.len() {
                break;
            }

            let attr_type = BigEndian::read_u16(&data[offset..offset + 2]);
            let attr_length = BigEndian::read_u16(&data[offset + 2..offset + 4]);
            offset += 4;

            if offset + attr_length as usize > data.len() {
                break;
            }

            if let Some(attribute_type) = StunAttributeType::from_u16(attr_type) {
                let value = data[offset..offset + attr_length as usize].to_vec();
                attributes.push(StunAttribute {
                    attribute_type,
                    length: attr_length,
                    value,
                });
            }

            // Attributes are padded to 4-byte boundaries
            offset += ((attr_length as usize + 3) / 4) * 4;
        }

        // Validate fingerprint if present and enabled
        if self.config.validate_fingerprint {
            if let Some(fingerprint_attr) = attributes.iter().find(|a| a.attribute_type == StunAttributeType::Fingerprint) {
                if !self.validate_fingerprint(data, fingerprint_attr)? {
                    return Err(GhostWireError::protocol("Invalid STUN fingerprint"));
                }
            }
        }

        Ok(StunMessage { header, attributes })
    }

    fn validate_fingerprint(&self, data: &[u8], fingerprint_attr: &StunAttribute) -> Result<bool> {
        if fingerprint_attr.value.len() != 4 {
            return Ok(false);
        }

        let received_crc = BigEndian::read_u32(&fingerprint_attr.value);

        // Calculate CRC32 over the message up to (but not including) the fingerprint
        let fingerprint_offset = data.len() - 8; // 4 bytes type/length + 4 bytes value
        let mut hasher = Hasher::new();
        hasher.update(&data[..fingerprint_offset]);
        let calculated_crc = hasher.finalize() ^ 0x5354554e; // XOR with "STUN"

        Ok(received_crc == calculated_crc)
    }

    async fn handle_binding_request(&self, request: StunMessage, client_addr: SocketAddr, socket: &UdpSocket) -> Result<()> {
        debug!("Handling STUN binding request from {}", client_addr);

        // Create response message
        let mut response = StunMessage {
            header: StunHeader {
                message_type: StunMessageType::BindingResponse,
                message_length: 0, // Will be calculated later
                transaction_id: request.header.transaction_id,
            },
            attributes: Vec::new(),
        };

        // Add XOR-MAPPED-ADDRESS attribute
        let xor_mapped_addr = self.create_xor_mapped_address(client_addr, &request.header.transaction_id)?;
        response.attributes.push(xor_mapped_addr);

        // Add SOFTWARE attribute
        let software_attr = StunAttribute {
            attribute_type: StunAttributeType::Software,
            length: self.config.software.len() as u16,
            value: self.config.software.as_bytes().to_vec(),
        };
        response.attributes.push(software_attr);

        // Send response
        self.send_response(response, client_addr, socket).await?;
        self.stats.write().await.successful_responses += 1;

        Ok(())
    }

    async fn handle_secret_request(&self, request: StunMessage, client_addr: SocketAddr, socket: &UdpSocket) -> Result<()> {
        debug!("Handling STUN shared secret request from {}", client_addr);

        // For security reasons, we don't support shared secret requests
        self.send_error_response(request, 405, "Method Not Allowed", client_addr, socket).await?;

        Ok(())
    }

    async fn send_error_response(&self, request: StunMessage, code: u16, reason: &str, client_addr: SocketAddr, socket: &UdpSocket) -> Result<()> {
        let mut response = StunMessage {
            header: StunHeader {
                message_type: match request.header.message_type {
                    StunMessageType::BindingRequest => StunMessageType::BindingErrorResponse,
                    StunMessageType::SharedSecretRequest => StunMessageType::SharedSecretErrorResponse,
                    _ => return Err(GhostWireError::protocol("Invalid request type for error response")),
                },
                message_length: 0,
                transaction_id: request.header.transaction_id,
            },
            attributes: Vec::new(),
        };

        // Add ERROR-CODE attribute
        let mut error_value = vec![0, 0]; // Reserved bytes
        error_value.push((code / 100) as u8); // Class
        error_value.push((code % 100) as u8); // Number
        error_value.extend_from_slice(reason.as_bytes());

        let error_attr = StunAttribute {
            attribute_type: StunAttributeType::ErrorCode,
            length: error_value.len() as u16,
            value: error_value,
        };
        response.attributes.push(error_attr);

        self.send_response(response, client_addr, socket).await?;
        self.stats.write().await.error_responses += 1;

        Ok(())
    }

    fn create_xor_mapped_address(&self, addr: SocketAddr, transaction_id: &[u8; 12]) -> Result<StunAttribute> {
        let mut value = Vec::new();

        // Reserved byte
        value.push(0);

        // Family and XOR'd port
        match addr {
            SocketAddr::V4(v4_addr) => {
                value.push(0x01); // IPv4 family

                // XOR port with magic cookie
                let port = addr.port();
                let xor_port = port ^ 0x2112;
                value.extend_from_slice(&xor_port.to_be_bytes());

                // XOR address with magic cookie
                let ip_bytes = v4_addr.ip().octets();
                let magic_bytes = 0x2112A442u32.to_be_bytes();
                for (i, &byte) in ip_bytes.iter().enumerate() {
                    value.push(byte ^ magic_bytes[i]);
                }
            }
            SocketAddr::V6(v6_addr) => {
                value.push(0x02); // IPv6 family

                // XOR port with magic cookie
                let port = addr.port();
                let xor_port = port ^ 0x2112;
                value.extend_from_slice(&xor_port.to_be_bytes());

                // XOR address with magic cookie + transaction ID
                let ip_bytes = v6_addr.ip().octets();
                let mut xor_key = Vec::new();
                xor_key.extend_from_slice(&0x2112A442u32.to_be_bytes());
                xor_key.extend_from_slice(transaction_id);

                for (i, &byte) in ip_bytes.iter().enumerate() {
                    value.push(byte ^ xor_key[i % xor_key.len()]);
                }
            }
        }

        Ok(StunAttribute {
            attribute_type: StunAttributeType::XorMappedAddress,
            length: value.len() as u16,
            value,
        })
    }

    async fn send_response(&self, mut response: StunMessage, client_addr: SocketAddr, socket: &UdpSocket) -> Result<()> {
        // Calculate message length
        let attr_length: usize = response.attributes.iter()
            .map(|attr| 4 + ((attr.length as usize + 3) / 4) * 4) // 4 bytes header + padded value
            .sum();
        response.header.message_length = attr_length as u16;

        // Add fingerprint if enabled
        if self.config.validate_fingerprint {
            let fingerprint_attr = self.create_fingerprint(&response)?;
            response.attributes.push(fingerprint_attr);
            response.header.message_length += 8; // 4 bytes header + 4 bytes value
        }

        // Encode message
        let data = self.encode_stun_message(&response)?;

        // Send response
        if let Err(e) = socket.send_to(&data, client_addr).await {
            return Err(GhostWireError::network(format!("Failed to send STUN response: {}", e)));
        }

        debug!("Sent STUN response to {}: {} bytes", client_addr, data.len());
        Ok(())
    }

    fn create_fingerprint(&self, message: &StunMessage) -> Result<StunAttribute> {
        // Encode message without fingerprint
        let mut temp_message = message.clone();
        temp_message.attributes.retain(|attr| attr.attribute_type != StunAttributeType::Fingerprint);

        let data = self.encode_stun_message(&temp_message)?;

        // Calculate CRC32
        let mut hasher = Hasher::new();
        hasher.update(&data);
        let crc = hasher.finalize() ^ 0x5354554e; // XOR with "STUN"

        Ok(StunAttribute {
            attribute_type: StunAttributeType::Fingerprint,
            length: 4,
            value: crc.to_be_bytes().to_vec(),
        })
    }

    fn encode_stun_message(&self, message: &StunMessage) -> Result<Vec<u8>> {
        let mut data = Vec::new();

        // Encode header
        data.extend_from_slice(&(message.header.message_type as u16).to_be_bytes());
        data.extend_from_slice(&message.header.message_length.to_be_bytes());
        data.extend_from_slice(&0x2112A442u32.to_be_bytes()); // Magic cookie
        data.extend_from_slice(&message.header.transaction_id);

        // Encode attributes
        for attr in &message.attributes {
            data.extend_from_slice(&(attr.attribute_type as u16).to_be_bytes());
            data.extend_from_slice(&attr.length.to_be_bytes());
            data.extend_from_slice(&attr.value);

            // Pad to 4-byte boundary
            let padding = (4 - (attr.value.len() % 4)) % 4;
            data.extend_from_slice(&vec![0; padding]);
        }

        Ok(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stun_message_type_conversion() {
        assert_eq!(StunMessageType::from_u16(0x0001), Some(StunMessageType::BindingRequest));
        assert_eq!(StunMessageType::from_u16(0x0101), Some(StunMessageType::BindingResponse));
        assert_eq!(StunMessageType::from_u16(0x9999), None);
    }

    #[test]
    fn test_stun_attribute_type_conversion() {
        assert_eq!(StunAttributeType::from_u16(0x0001), Some(StunAttributeType::MappedAddress));
        assert_eq!(StunAttributeType::from_u16(0x0020), Some(StunAttributeType::XorMappedAddress));
        assert_eq!(StunAttributeType::from_u16(0x9999), None);
    }

    #[tokio::test]
    async fn test_stun_server_creation() {
        let config = StunServerConfig::default();
        let server = StunServer::new(config);

        let stats = server.get_stats().await;
        assert_eq!(stats.total_requests, 0);
        assert_eq!(stats.successful_responses, 0);
    }

    #[tokio::test]
    async fn test_rate_limiting() {
        let mut config = StunServerConfig::default();
        config.rate_limit_per_ip = 2;
        config.rate_limit_window = 60;

        let server = StunServer::new(config);
        let test_ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        // First two requests should be allowed
        assert!(server.check_rate_limit(test_ip).await);
        assert!(server.check_rate_limit(test_ip).await);

        // Third request should be rate limited
        assert!(!server.check_rate_limit(test_ip).await);
    }
}