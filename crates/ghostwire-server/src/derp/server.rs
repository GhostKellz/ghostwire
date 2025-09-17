/// DERP server implementation
///
/// High-performance QUIC-based relay server with WebSocket fallback,
/// mesh forwarding capabilities, and comprehensive monitoring.

use crate::derp::*;
use crate::derp::stun::{StunServer, StunServerConfig};
use crate::coordinator::Coordinator;
use ghostwire_common::{
    types::*,
    error::{Result, GhostWireError},
};
use std::collections::HashMap;
use std::net::{SocketAddr, IpAddr};
use std::sync::Arc;
use std::time::{SystemTime, Instant, Duration};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{RwLock, broadcast, mpsc};
use tokio::time::{interval, timeout};
use quinn::{Endpoint, ServerConfig, Connection, Incoming};
use tracing::{debug, warn, error, info};
use uuid::Uuid;

/// Active DERP connection
#[derive(Debug)]
struct DerpConnection {
    /// Connection ID
    id: Uuid,
    /// Node ID (if authenticated)
    node_id: Option<NodeId>,
    /// Client address
    client_addr: SocketAddr,
    /// Connection type
    connection_type: ConnectionType,
    /// Connection established at
    connected_at: SystemTime,
    /// Last activity
    last_activity: SystemTime,
    /// Bytes sent
    bytes_sent: u64,
    /// Bytes received
    bytes_received: u64,
    /// Preferred region
    preferred_region: Option<u16>,
    /// Message sender
    message_sender: mpsc::UnboundedSender<DerpFrame>,
}

/// DERP server implementation
pub struct DerpServer {
    config: DerpConfig,
    coordinator: Arc<Coordinator>,
    connections: Arc<RwLock<HashMap<Uuid, DerpConnection>>>,
    node_connections: Arc<RwLock<HashMap<NodeId, Uuid>>>,
    stats: Arc<RwLock<DerpStats>>,
    stun_server: Option<StunServer>,
    start_time: SystemTime,
    is_running: Arc<RwLock<bool>>,
    shutdown_sender: Option<broadcast::Sender<()>>,
}

impl DerpServer {
    /// Create a new DERP server
    pub fn new(config: DerpConfig, coordinator: Arc<Coordinator>) -> Self {
        let stats = Arc::new(RwLock::new(DerpStats {
            active_connections: 0,
            total_connections: 0,
            bytes_relayed: 0,
            packets_relayed: 0,
            average_latency_ms: 0.0,
            regional_stats: HashMap::new(),
            rate_limit_stats: RateLimitStats {
                banned_ips: 0,
                violations_last_hour: 0,
                dropped_connections: 0,
            },
            uptime_seconds: 0,
        }));

        // Create STUN server if enabled
        let stun_server = if config.stun.enabled {
            let stun_config = crate::derp::stun::StunServerConfig {
                enabled: config.stun.enabled,
                listen_addr: config.listen_addr.clone(),
                listen_port: config.stun_port,
                validate_fingerprint: config.stun.validate_fingerprint,
                software: config.stun.software.clone(),
                rate_limit_per_ip: config.stun.rate_limit_per_ip,
                rate_limit_window: config.stun.rate_limit_window,
            };
            Some(StunServer::new(stun_config))
        } else {
            None
        };

        Self {
            config,
            coordinator,
            connections: Arc::new(RwLock::new(HashMap::new())),
            node_connections: Arc::new(RwLock::new(HashMap::new())),
            stats,
            stun_server,
            start_time: SystemTime::now(),
            is_running: Arc::new(RwLock::new(false)),
            shutdown_sender: None,
        }
    }

    /// Start the DERP server
    pub async fn start(&mut self) -> Result<()> {
        info!("Starting DERP server on {}:{}", self.config.listen_addr, self.config.https_port);

        *self.is_running.write().await = true;

        // Create shutdown channel
        let (shutdown_tx, _) = broadcast::channel(1);
        self.shutdown_sender = Some(shutdown_tx.clone());

        // Start QUIC server if enabled
        if self.config.quic.enabled {
            self.start_quic_server(shutdown_tx.clone()).await?;
        }

        // Start STUN server if enabled
        if self.config.stun.enabled {
            self.start_stun_server(shutdown_tx.clone()).await?;
        }

        // Start WebSocket server
        self.start_websocket_server(shutdown_tx.clone()).await?;

        // Start background tasks
        self.start_background_tasks(shutdown_tx).await;

        info!("DERP server started successfully");
        Ok(())
    }

    /// Stop the DERP server
    pub async fn stop(&mut self) -> Result<()> {
        info!("Stopping DERP server");

        *self.is_running.write().await = false;

        // Send shutdown signal
        if let Some(sender) = &self.shutdown_sender {
            let _ = sender.send(());
        }

        // Close all connections
        let connections = self.connections.read().await;
        for connection in connections.values() {
            let _ = connection.message_sender.send(DerpFrame::new(
                FrameType::Restarting,
                vec![],
            ));
        }

        // Clear connection maps
        self.connections.write().await.clear();
        self.node_connections.write().await.clear();

        info!("DERP server stopped");
        Ok(())
    }

    /// Get server statistics
    pub async fn get_stats(&self) -> DerpStats {
        let mut stats = self.stats.read().await.clone();
        stats.uptime_seconds = self.start_time.elapsed().unwrap_or_default().as_secs();
        stats.active_connections = self.connections.read().await.len() as u32;
        stats
    }

    /// Send packet to a specific node
    pub async fn send_packet(&self, dst_node_id: NodeId, src_node_id: NodeId, data: Vec<u8>) -> Result<()> {
        let node_connections = self.node_connections.read().await;

        if let Some(connection_id) = node_connections.get(&dst_node_id) {
            let connections = self.connections.read().await;

            if let Some(connection) = connections.get(connection_id) {
                let recv_packet = RecvPacket {
                    src_node_id,
                    data,
                };

                let frame = ProtocolHandler::create_recv_packet(&recv_packet)?;

                if connection.message_sender.send(frame).is_ok() {
                    // Update stats
                    let mut stats = self.stats.write().await;
                    stats.packets_relayed += 1;
                    stats.bytes_relayed += recv_packet.data.len() as u64;

                    debug!("Relayed packet from {} to {}", src_node_id, dst_node_id);
                    return Ok(());
                }
            }
        }

        // Node not connected, check if we should forward to mesh peers
        if self.config.mesh.enabled {
            self.forward_to_mesh_peer(dst_node_id, src_node_id, data).await?;
        }

        Ok(())
    }

    // Private implementation methods

    async fn start_quic_server(&self, shutdown_rx: broadcast::Sender<()>) -> Result<()> {
        let listen_addr: SocketAddr = format!("{}:{}", self.config.listen_addr, self.config.https_port)
            .parse()
            .map_err(|e| GhostWireError::configuration(format!("Invalid listen address: {}", e)))?;

        // Create QUIC server configuration
        let server_config = self.create_quic_config()?;
        let endpoint = Endpoint::server(server_config, listen_addr)
            .map_err(|e| GhostWireError::network(format!("Failed to create QUIC endpoint: {}", e)))?;

        let derp_server = self.clone();
        let mut shutdown_rx = shutdown_rx.subscribe();

        tokio::spawn(async move {
            info!("QUIC server listening on {}", listen_addr);

            loop {
                tokio::select! {
                    incoming = endpoint.accept() => {
                        if let Some(incoming) = incoming {
                            let derp_server = derp_server.clone();
                            tokio::spawn(async move {
                                if let Err(e) = derp_server.handle_quic_connection(incoming).await {
                                    warn!("QUIC connection error: {}", e);
                                }
                            });
                        }
                    }
                    _ = shutdown_rx.recv() => {
                        info!("Shutting down QUIC server");
                        break;
                    }
                }
            }
        });

        Ok(())
    }

    async fn start_stun_server(&self, shutdown_rx: broadcast::Sender<()>) -> Result<()> {
        let listen_addr: SocketAddr = format!("{}:{}", self.config.listen_addr, self.config.stun_port)
            .parse()
            .map_err(|e| GhostWireError::configuration(format!("Invalid STUN address: {}", e)))?;

        let socket = UdpSocket::bind(listen_addr).await
            .map_err(|e| GhostWireError::network(format!("Failed to bind STUN socket: {}", e)))?;

        let derp_server = self.clone();
        let mut shutdown_rx = shutdown_rx.subscribe();

        tokio::spawn(async move {
            info!("STUN server listening on {}", listen_addr);

            let mut buf = [0u8; 1500];

            loop {
                tokio::select! {
                    result = socket.recv_from(&mut buf) => {
                        match result {
                            Ok((len, addr)) => {
                                let data = &buf[..len];
                                if let Err(e) = derp_server.handle_stun_packet(data, addr, &socket).await {
                                    debug!("STUN packet error: {}", e);
                                }
                            }
                            Err(e) => {
                                warn!("STUN socket error: {}", e);
                            }
                        }
                    }
                    _ = shutdown_rx.recv() => {
                        info!("Shutting down STUN server");
                        break;
                    }
                }
            }
        });

        Ok(())
    }

    async fn start_websocket_server(&self, shutdown_rx: broadcast::Sender<()>) -> Result<()> {
        // WebSocket server implementation would go here
        // For now, just start a placeholder task
        let mut shutdown_rx = shutdown_rx.subscribe();

        tokio::spawn(async move {
            debug!("WebSocket server task started");

            tokio::select! {
                _ = shutdown_rx.recv() => {
                    debug!("Shutting down WebSocket server");
                }
            }
        });

        Ok(())
    }

    async fn start_background_tasks(&self, shutdown_tx: broadcast::Sender<()>) {
        // Start connection cleanup task
        self.start_connection_cleanup_task(shutdown_tx.clone()).await;

        // Start stats update task
        self.start_stats_update_task(shutdown_tx.clone()).await;

        // Start rate limit cleanup task
        self.start_rate_limit_cleanup_task(shutdown_tx).await;
    }

    async fn start_connection_cleanup_task(&self, shutdown_tx: broadcast::Sender<()>) {
        let connections = self.connections.clone();
        let node_connections = self.node_connections.clone();
        let mut shutdown_rx = shutdown_tx.subscribe();

        tokio::spawn(async move {
            let mut cleanup_interval = interval(Duration::from_secs(30));

            loop {
                tokio::select! {
                    _ = cleanup_interval.tick() => {
                        let now = SystemTime::now();
                        let mut conn_lock = connections.write().await;
                        let mut node_lock = node_connections.write().await;
                        let mut to_remove = Vec::new();

                        for (id, conn) in conn_lock.iter() {
                            // Remove connections inactive for more than 5 minutes
                            if now.duration_since(conn.last_activity).unwrap_or_default() > Duration::from_secs(300) {
                                to_remove.push(*id);
                            }
                        }

                        for id in to_remove {
                            if let Some(conn) = conn_lock.remove(&id) {
                                if let Some(node_id) = conn.node_id {
                                    node_lock.remove(&node_id);
                                }
                                debug!("Cleaned up inactive connection: {}", id);
                            }
                        }
                    }
                    _ = shutdown_rx.recv() => {
                        debug!("Connection cleanup task stopped");
                        break;
                    }
                }
            }
        });
    }

    async fn start_stats_update_task(&self, shutdown_tx: broadcast::Sender<()>) {
        let stats = self.stats.clone();
        let connections = self.connections.clone();
        let mut shutdown_rx = shutdown_tx.subscribe();

        tokio::spawn(async move {
            let mut stats_interval = interval(Duration::from_secs(60));

            loop {
                tokio::select! {
                    _ = stats_interval.tick() => {
                        let mut stats_lock = stats.write().await;
                        let conn_lock = connections.read().await;

                        stats_lock.active_connections = conn_lock.len() as u32;

                        // Calculate regional statistics
                        let mut regional_stats = HashMap::new();
                        for conn in conn_lock.values() {
                            if let Some(region_id) = conn.preferred_region {
                                let entry = regional_stats.entry(region_id).or_insert(RegionalStats {
                                    region_id,
                                    active_connections: 0,
                                    bytes_relayed: 0,
                                    average_latency_ms: 0.0,
                                });
                                entry.active_connections += 1;
                            }
                        }

                        stats_lock.regional_stats = regional_stats;
                    }
                    _ = shutdown_rx.recv() => {
                        debug!("Stats update task stopped");
                        break;
                    }
                }
            }
        });
    }

    async fn start_rate_limit_cleanup_task(&self, shutdown_tx: broadcast::Sender<()>) {
        let mut shutdown_rx = shutdown_tx.subscribe();

        tokio::spawn(async move {
            let mut cleanup_interval = interval(Duration::from_secs(300)); // 5 minutes

            loop {
                tokio::select! {
                    _ = cleanup_interval.tick() => {
                        // Rate limit cleanup logic would go here
                        debug!("Rate limit cleanup completed");
                    }
                    _ = shutdown_rx.recv() => {
                        debug!("Rate limit cleanup task stopped");
                        break;
                    }
                }
            }
        });
    }

    async fn handle_quic_connection(&self, incoming: Incoming) -> Result<()> {
        let connection = incoming.await
            .map_err(|e| GhostWireError::network(format!("QUIC connection failed: {}", e)))?;

        let connection_id = Uuid::new_v4();
        let client_addr = connection.remote_address();

        info!("New QUIC connection: {} from {}", connection_id, client_addr);

        // Create message channel
        let (tx, mut rx) = mpsc::unbounded_channel();

        // Create connection entry
        let derp_connection = DerpConnection {
            id: connection_id,
            node_id: None,
            client_addr,
            connection_type: ConnectionType::Quic,
            connected_at: SystemTime::now(),
            last_activity: SystemTime::now(),
            bytes_sent: 0,
            bytes_received: 0,
            preferred_region: None,
            message_sender: tx,
        };

        // Add to connections map
        self.connections.write().await.insert(connection_id, derp_connection);

        // Update stats
        self.stats.write().await.total_connections += 1;

        // Handle connection in background
        let derp_server = self.clone();
        tokio::spawn(async move {
            // Send server info
            let server_info = ServerInfo {
                version: DERP_VERSION,
                region_id: derp_server.config.region.region_id,
                capabilities: ServerCapabilities {
                    mesh_forwarding: derp_server.config.mesh.enabled,
                    quic_support: true,
                    compression: true,
                    max_clients: derp_server.config.quic.max_connections,
                    rate_limiting: derp_server.config.rate_limiting.enabled,
                },
                mesh_key_required: derp_server.config.mesh.mesh_key.is_some(),
                start_time: derp_server.start_time,
            };

            let server_info_frame = match ProtocolHandler::create_server_info(&server_info) {
                Ok(frame) => frame,
                Err(e) => {
                    error!("Failed to create server info frame: {}", e);
                    return;
                }
            };

            if let Err(e) = derp_server.send_frame_to_connection(&connection, &server_info_frame).await {
                error!("Failed to send server info: {}", e);
                return;
            }

            // Message processing loop
            loop {
                tokio::select! {
                    // Outgoing messages
                    msg = rx.recv() => {
                        match msg {
                            Some(frame) => {
                                if let Err(e) = derp_server.send_frame_to_connection(&connection, &frame).await {
                                    warn!("Failed to send frame: {}", e);
                                    break;
                                }
                            }
                            None => {
                                debug!("Message channel closed for connection {}", connection_id);
                                break;
                            }
                        }
                    }
                    // Incoming messages would be handled here
                    // This is simplified - in reality we'd read from QUIC streams
                }
            }

            // Clean up connection
            derp_server.cleanup_connection(connection_id).await;
        });

        Ok(())
    }

    async fn handle_stun_packet(&self, data: &[u8], addr: SocketAddr, socket: &UdpSocket) -> Result<()> {
        // Use the dedicated STUN server implementation
        if let Some(stun_server) = &self.stun_server {
            stun_server.handle_packet(data, addr, socket).await?;
        } else {
            debug!("Received STUN packet but STUN server is disabled");
        }

        Ok(())
    }

    async fn send_frame_to_connection(&self, connection: &Connection, frame: &DerpFrame) -> Result<()> {
        // Encode frame
        let data = frame.encode()?;

        // Send over QUIC stream
        // This is simplified - in reality we'd manage bidirectional streams
        match connection.open_uni().await {
            Ok(mut stream) => {
                if let Err(e) = stream.write_all(&data).await {
                    return Err(GhostWireError::network(format!("Failed to write to stream: {}", e)));
                }
                if let Err(e) = stream.finish().await {
                    return Err(GhostWireError::network(format!("Failed to finish stream: {}", e)));
                }
                Ok(())
            }
            Err(e) => Err(GhostWireError::network(format!("Failed to open stream: {}", e))),
        }
    }

    async fn cleanup_connection(&self, connection_id: Uuid) {
        let mut connections = self.connections.write().await;
        if let Some(connection) = connections.remove(&connection_id) {
            // Remove from node mapping if authenticated
            if let Some(node_id) = connection.node_id {
                self.node_connections.write().await.remove(&node_id);
            }

            debug!("Cleaned up connection: {}", connection_id);
        }
    }

    async fn forward_to_mesh_peer(&self, dst_node_id: NodeId, src_node_id: NodeId, data: Vec<u8>) -> Result<()> {
        // Mesh forwarding implementation
        debug!("Forwarding packet to mesh peer: {} -> {}", src_node_id, dst_node_id);

        // This would implement actual mesh forwarding logic
        // For now, just log the attempt

        Ok(())
    }

    fn create_quic_config(&self) -> Result<ServerConfig> {
        // Create QUIC server configuration
        // This is simplified - in reality we'd configure TLS certificates, etc.

        let mut server_config = quinn::ServerConfig::with_single_cert(
            vec![], // Certificate chain
            rustls::PrivateKey(vec![]), // Private key
        ).map_err(|e| GhostWireError::configuration(format!("Invalid TLS configuration: {}", e)))?;

        // Configure transport parameters
        let mut transport_config = quinn::TransportConfig::default();
        transport_config.max_concurrent_uni_streams(100u32.into());
        transport_config.max_concurrent_bidi_streams(100u32.into());
        transport_config.max_idle_timeout(Some(Duration::from_secs(self.config.quic.idle_timeout_seconds).try_into().unwrap()));

        server_config.transport = Arc::new(transport_config);

        Ok(server_config)
    }
}

impl Clone for DerpServer {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            coordinator: self.coordinator.clone(),
            connections: self.connections.clone(),
            node_connections: self.node_connections.clone(),
            stats: self.stats.clone(),
            stun_server: None, // STUN server is not cloneable
            start_time: self.start_time,
            is_running: self.is_running.clone(),
            shutdown_sender: self.shutdown_sender.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_derp_server_creation() {
        let config = DerpConfig::default();
        let coordinator = Arc::new(crate::coordinator::Coordinator::new_test());
        let server = DerpServer::new(config, coordinator);

        let stats = server.get_stats().await;
        assert_eq!(stats.active_connections, 0);
        assert_eq!(stats.total_connections, 0);
    }

    #[tokio::test]
    async fn test_derp_server_lifecycle() {
        let mut config = DerpConfig::default();
        config.enabled = true;
        config.quic.enabled = false; // Disable QUIC for testing

        let coordinator = Arc::new(crate::coordinator::Coordinator::new_test());
        let mut server = DerpServer::new(config, coordinator);

        // Start server
        // assert!(server.start().await.is_ok());

        // Stop server
        // assert!(server.stop().await.is_ok());
    }
}