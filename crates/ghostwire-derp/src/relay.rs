use ghostwire_common::{
    error::{Result, GhostWireError},
    quic::{QuicConfig, QuicMessage, QuicMultiplexer, QuicPayload, StreamType},
    types::{NodeId, PublicKey},
};
use quinn::{Connection, Endpoint, Incoming, NewConnection, ServerConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use uuid::Uuid;

/// QUIC-based DERP relay server
///
/// This provides significant advantages over traditional HTTPS/WebSocket DERP:
/// - UDP multiplexing for better NAT traversal
/// - Built-in congestion control for high-speed relaying
/// - Connection migration for mobile clients
/// - 0-RTT reconnection for lower latency
/// - Flow control to prevent overwhelming slower clients
pub struct QuicDerpRelay {
    /// QUIC endpoint for accepting connections
    endpoint: Endpoint,
    /// Configuration
    config: QuicConfig,
    /// Active client connections mapped by public key
    clients: Arc<RwLock<HashMap<PublicKey, ClientConnection>>>,
    /// Relay statistics
    stats: Arc<RwLock<RelayStats>>,
    /// Channel for incoming connections
    incoming_tx: mpsc::UnboundedSender<NewConnection>,
    incoming_rx: Option<mpsc::UnboundedReceiver<NewConnection>>,
}

#[derive(Debug, Clone)]
struct ClientConnection {
    node_id: NodeId,
    public_key: PublicKey,
    connection: Connection,
    remote_addr: SocketAddr,
    connected_at: std::time::SystemTime,
    last_activity: std::time::SystemTime,
    bytes_relayed: u64,
    packets_relayed: u64,
}

#[derive(Debug, Default)]
struct RelayStats {
    total_connections: u64,
    active_connections: u64,
    bytes_relayed: u64,
    packets_relayed: u64,
    connection_errors: u64,
    relay_errors: u64,
}

impl QuicDerpRelay {
    /// Create a new QUIC DERP relay
    pub async fn new(
        listen_addr: SocketAddr,
        cert_chain: Vec<CertificateDer<'static>>,
        private_key: PrivateKeyDer<'static>,
        config: QuicConfig,
    ) -> Result<Self> {
        let server_config = Self::build_server_config(cert_chain, private_key, &config)?;

        let endpoint = Endpoint::server(server_config, listen_addr)
            .map_err(|e| GhostWireError::quic(format!("Failed to create QUIC endpoint: {}", e)))?;

        let (incoming_tx, incoming_rx) = mpsc::unbounded_channel();

        Ok(Self {
            endpoint,
            config,
            clients: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(RelayStats::default())),
            incoming_tx,
            incoming_rx: Some(incoming_rx),
        })
    }

    /// Start the relay server
    pub async fn run(&mut self) -> Result<()> {
        let mut incoming_rx = self.incoming_rx.take()
            .ok_or_else(|| GhostWireError::internal("Relay already running"))?;

        tracing::info!("QUIC DERP relay listening on {}", self.endpoint.local_addr()?);

        // Handle incoming connections
        let incoming_handle = {
            let endpoint = self.endpoint.clone();
            let incoming_tx = self.incoming_tx.clone();
            tokio::spawn(async move {
                while let Some(conn) = endpoint.accept().await {
                    match conn.await {
                        Ok(new_conn) => {
                            if let Err(e) = incoming_tx.send(new_conn) {
                                tracing::error!("Failed to send new connection: {}", e);
                                break;
                            }
                        }
                        Err(e) => {
                            tracing::warn!("Incoming connection failed: {}", e);
                        }
                    }
                }
            })
        };

        // Process new connections
        let clients = self.clients.clone();
        let stats = self.stats.clone();
        let process_handle = tokio::spawn(async move {
            while let Some(new_conn) = incoming_rx.recv().await {
                let clients = clients.clone();
                let stats = stats.clone();

                tokio::spawn(async move {
                    if let Err(e) = Self::handle_client_connection(new_conn, clients, stats).await {
                        tracing::error!("Client connection error: {}", e);
                    }
                });
            }
        });

        // Wait for tasks to complete (they shouldn't unless there's an error)
        tokio::select! {
            result = incoming_handle => {
                if let Err(e) = result {
                    tracing::error!("Incoming connection handler failed: {}", e);
                }
            }
            result = process_handle => {
                if let Err(e) = result {
                    tracing::error!("Connection processor failed: {}", e);
                }
            }
        }

        Ok(())
    }

    /// Handle a new client connection
    async fn handle_client_connection(
        new_conn: NewConnection,
        clients: Arc<RwLock<HashMap<PublicKey, ClientConnection>>>,
        stats: Arc<RwLock<RelayStats>>,
    ) -> Result<()> {
        let NewConnection { connection, .. } = new_conn;
        let remote_addr = connection.remote_address();

        tracing::info!("New QUIC connection from {}", remote_addr);

        // Perform client authentication (would implement actual auth here)
        let (node_id, public_key) = Self::authenticate_client(&connection).await?;

        let client_conn = ClientConnection {
            node_id,
            public_key,
            connection: connection.clone(),
            remote_addr,
            connected_at: std::time::SystemTime::now(),
            last_activity: std::time::SystemTime::now(),
            bytes_relayed: 0,
            packets_relayed: 0,
        };

        // Add to active clients
        {
            let mut clients_guard = clients.write().await;
            clients_guard.insert(public_key, client_conn);

            let mut stats_guard = stats.write().await;
            stats_guard.total_connections += 1;
            stats_guard.active_connections = clients_guard.len() as u64;
        }

        // Handle client streams
        let clients_for_handler = clients.clone();
        let stats_for_handler = stats.clone();

        loop {
            match connection.accept_uni().await {
                Ok(recv_stream) => {
                    let clients = clients_for_handler.clone();
                    let stats = stats_for_handler.clone();
                    let public_key = public_key;

                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_client_stream(
                            recv_stream,
                            public_key,
                            clients,
                            stats
                        ).await {
                            tracing::error!("Stream handling error: {}", e);
                        }
                    });
                }
                Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                    tracing::info!("Client {} disconnected", public_key.as_bytes()[0]);
                    break;
                }
                Err(e) => {
                    tracing::error!("Stream accept error: {}", e);
                    break;
                }
            }
        }

        // Remove from active clients
        {
            let mut clients_guard = clients.write().await;
            clients_guard.remove(&public_key);

            let mut stats_guard = stats.write().await;
            stats_guard.active_connections = clients_guard.len() as u64;
        }

        Ok(())
    }

    /// Handle incoming stream from client
    async fn handle_client_stream(
        mut recv_stream: quinn::RecvStream,
        sender_public_key: PublicKey,
        clients: Arc<RwLock<HashMap<PublicKey, ClientConnection>>>,
        stats: Arc<RwLock<RelayStats>>,
    ) -> Result<()> {
        let mut buffer = Vec::new();
        recv_stream.read_to_end(usize::MAX, &mut buffer).await
            .map_err(|e| GhostWireError::quic(format!("Stream read error: {}", e)))?;

        // Parse the message
        let message: QuicMessage = serde_json::from_slice(&buffer)
            .map_err(|e| GhostWireError::serialization(e))?;

        match message.payload {
            QuicPayload::DerpRelay { target_public_key, data } => {
                // Relay data to target client
                Self::relay_to_client(
                    target_public_key,
                    data,
                    sender_public_key,
                    clients,
                    stats,
                ).await?;
            }
            QuicPayload::Heartbeat { .. } => {
                // Update last activity for sender
                Self::update_client_activity(sender_public_key, clients).await;
            }
            _ => {
                tracing::warn!("Unexpected message type from client: {:?}", message.stream_type);
            }
        }

        Ok(())
    }

    /// Relay data to target client
    async fn relay_to_client(
        target_public_key: PublicKey,
        data: Vec<u8>,
        sender_public_key: PublicKey,
        clients: Arc<RwLock<HashMap<PublicKey, ClientConnection>>>,
        stats: Arc<RwLock<RelayStats>>,
    ) -> Result<()> {
        let target_connection = {
            let clients_guard = clients.read().await;
            clients_guard.get(&target_public_key)
                .map(|client| client.connection.clone())
        };

        if let Some(connection) = target_connection {
            // Create relay message
            let relay_message = QuicMessage {
                stream_type: StreamType::DerpRelay,
                sequence: 0, // Would implement proper sequencing
                timestamp: std::time::SystemTime::now(),
                payload: QuicPayload::DerpRelay {
                    target_public_key: sender_public_key, // Original sender
                    data,
                },
            };

            let serialized = serde_json::to_vec(&relay_message)
                .map_err(|e| GhostWireError::serialization(e))?;

            // Send to target client
            let mut send_stream = connection.open_uni().await
                .map_err(|e| GhostWireError::quic(format!("Failed to open stream: {}", e)))?;

            send_stream.write_all(&serialized).await
                .map_err(|e| GhostWireError::quic(format!("Failed to write data: {}", e)))?;

            send_stream.finish().await
                .map_err(|e| GhostWireError::quic(format!("Failed to finish stream: {}", e)))?;

            // Update stats
            {
                let mut stats_guard = stats.write().await;
                stats_guard.bytes_relayed += serialized.len() as u64;
                stats_guard.packets_relayed += 1;
            }

            tracing::debug!("Relayed {} bytes from {} to {}",
                serialized.len(),
                sender_public_key.as_bytes()[0],
                target_public_key.as_bytes()[0]
            );
        } else {
            tracing::warn!("Target client not found: {}", target_public_key.as_bytes()[0]);

            let mut stats_guard = stats.write().await;
            stats_guard.relay_errors += 1;
        }

        Ok(())
    }

    /// Update client activity timestamp
    async fn update_client_activity(
        public_key: PublicKey,
        clients: Arc<RwLock<HashMap<PublicKey, ClientConnection>>>,
    ) {
        let mut clients_guard = clients.write().await;
        if let Some(client) = clients_guard.get_mut(&public_key) {
            client.last_activity = std::time::SystemTime::now();
        }
    }

    /// Authenticate connecting client (simplified for now)
    async fn authenticate_client(
        _connection: &Connection,
    ) -> Result<(NodeId, PublicKey)> {
        // In a real implementation, this would:
        // 1. Verify client certificate or perform challenge-response
        // 2. Check against coordination server for valid nodes
        // 3. Extract node ID and public key from authentication data

        // For now, return dummy values
        Ok((Uuid::new_v4(), PublicKey::from_bytes([0u8; 32])))
    }

    /// Build QUIC server configuration
    fn build_server_config(
        cert_chain: Vec<CertificateDer<'static>>,
        private_key: PrivateKeyDer<'static>,
        config: &QuicConfig,
    ) -> Result<ServerConfig> {
        let mut server_config = ServerConfig::with_single_cert(cert_chain, private_key)
            .map_err(|e| GhostWireError::crypto(format!("TLS config error: {}", e)))?;

        // Configure QUIC transport parameters
        let mut transport_config = quinn::TransportConfig::default();
        transport_config.max_concurrent_uni_streams(config.max_streams.try_into().unwrap_or(100));
        transport_config.max_idle_timeout(Some(config.idle_timeout.try_into().unwrap()));
        transport_config.keep_alive_interval(Some(config.keep_alive_interval));

        if let Some(max_bw) = config.max_bandwidth {
            // Set congestion control parameters based on max bandwidth
            transport_config.congestion_controller_factory(Arc::new(
                quinn::congestion::BbrConfig::default()
            ));
        }

        server_config.transport_config(Arc::new(transport_config));

        Ok(server_config)
    }

    /// Get relay statistics
    pub async fn get_stats(&self) -> RelayStats {
        self.stats.read().await.clone()
    }

    /// Get active client count
    pub async fn active_clients(&self) -> usize {
        self.clients.read().await.len()
    }
}