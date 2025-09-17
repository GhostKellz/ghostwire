/// GhostWire client integration for desktop application
///
/// Provides the bridge between the desktop UI and the core GhostWire client functionality.

use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{info, warn, error, debug};

use crate::config::AppConfig;
use crate::types::{ConnectionStatus, ConnectionInfo, Machine, Route, NetworkStats};

pub struct GhostWireClient {
    config: AppConfig,
    http_client: reqwest::Client,
    connection_status: ConnectionStatus,
    last_update: Instant,
    machines: Vec<Machine>,
    routes: Vec<Route>,
    network_stats: NetworkStats,
}

impl GhostWireClient {
    pub async fn new(config: AppConfig) -> Result<Self, ClientError> {
        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent(format!("GhostWire-Desktop/{}", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(ClientError::HttpClient)?;

        Ok(Self {
            config,
            http_client,
            connection_status: ConnectionStatus::Disconnected,
            last_update: Instant::now(),
            machines: Vec::new(),
            routes: Vec::new(),
            network_stats: NetworkStats::default(),
        })
    }

    pub async fn connect(&mut self) -> Result<(), ClientError> {
        info!("Initiating connection to GhostWire server");
        self.connection_status = ConnectionStatus::Connecting;

        // Validate configuration
        self.config.validate().map_err(ClientError::Config)?;

        // Test server connectivity
        match self.test_server_connection().await {
            Ok(_) => {
                info!("Server connectivity test passed");
            }
            Err(e) => {
                error!("Server connectivity test failed: {}", e);
                self.connection_status = ConnectionStatus::Error(e.to_string());
                return Err(e);
            }
        }

        // Simulate connection process (in real implementation, this would involve:)
        // 1. Authentication with the server
        // 2. Key exchange
        // 3. Network configuration
        // 4. Starting the VPN tunnel

        tokio::time::sleep(Duration::from_millis(1500)).await;

        let connection_info = ConnectionInfo {
            server_url: self.config.server_url.clone(),
            connected_at: chrono::Utc::now(),
            local_ip: "100.64.0.1".parse().unwrap(), // Mock IP
            public_key: "mock-public-key".to_string(),
            endpoint: "203.0.113.1:41641".to_string(),
            latency: Some(45),
        };

        self.connection_status = ConnectionStatus::Connected(connection_info);
        info!("Successfully connected to GhostWire network");

        // Start background tasks for data synchronization
        self.start_background_sync().await?;

        Ok(())
    }

    pub async fn disconnect(&mut self) -> Result<(), ClientError> {
        info!("Disconnecting from GhostWire network");

        // In real implementation, this would:
        // 1. Stop the VPN tunnel
        // 2. Clean up network configuration
        // 3. Notify the server

        self.connection_status = ConnectionStatus::Disconnected;
        self.machines.clear();
        self.routes.clear();
        self.network_stats = NetworkStats::default();

        info!("Disconnected from GhostWire network");
        Ok(())
    }

    pub fn connection_status(&self) -> &ConnectionStatus {
        &self.connection_status
    }

    pub fn machines(&self) -> &[Machine] {
        &self.machines
    }

    pub fn routes(&self) -> &[Route] {
        &self.routes
    }

    pub fn network_stats(&self) -> &NetworkStats {
        &self.network_stats
    }

    pub async fn refresh_data(&mut self) -> Result<(), ClientError> {
        if !matches!(self.connection_status, ConnectionStatus::Connected(_)) {
            return Ok(());
        }

        debug!("Refreshing network data");

        // Fetch machines
        match self.fetch_machines().await {
            Ok(machines) => {
                self.machines = machines;
                debug!("Updated {} machines", self.machines.len());
            }
            Err(e) => {
                warn!("Failed to fetch machines: {}", e);
            }
        }

        // Fetch routes
        match self.fetch_routes().await {
            Ok(routes) => {
                self.routes = routes;
                debug!("Updated {} routes", self.routes.len());
            }
            Err(e) => {
                warn!("Failed to fetch routes: {}", e);
            }
        }

        // Update network stats
        self.update_network_stats().await?;

        self.last_update = Instant::now();
        Ok(())
    }

    async fn test_server_connection(&self) -> Result<(), ClientError> {
        let url = format!("{}/health", self.config.server_api_url());

        let mut request = self.http_client.get(&url);

        if let Some(auth_header) = self.config.auth_header() {
            request = request.header("Authorization", auth_header);
        }

        let response = request
            .send()
            .await
            .map_err(ClientError::HttpRequest)?;

        if !response.status().is_success() {
            return Err(ClientError::ServerError(format!(
                "Server returned status: {}",
                response.status()
            )));
        }

        Ok(())
    }

    async fn fetch_machines(&self) -> Result<Vec<Machine>, ClientError> {
        let url = format!("{}/machines", self.config.server_api_url());

        let mut request = self.http_client.get(&url);

        if let Some(auth_header) = self.config.auth_header() {
            request = request.header("Authorization", auth_header);
        }

        let response = request
            .send()
            .await
            .map_err(ClientError::HttpRequest)?;

        if !response.status().is_success() {
            return Err(ClientError::ServerError(format!(
                "Failed to fetch machines: {}",
                response.status()
            )));
        }

        // For now, return mock data
        // In real implementation, parse the JSON response
        Ok(self.create_mock_machines())
    }

    async fn fetch_routes(&self) -> Result<Vec<Route>, ClientError> {
        let url = format!("{}/routes", self.config.server_api_url());

        let mut request = self.http_client.get(&url);

        if let Some(auth_header) = self.config.auth_header() {
            request = request.header("Authorization", auth_header);
        }

        let response = request
            .send()
            .await
            .map_err(ClientError::HttpRequest)?;

        if !response.status().is_success() {
            return Err(ClientError::ServerError(format!(
                "Failed to fetch routes: {}",
                response.status()
            )));
        }

        // For now, return mock data
        Ok(self.create_mock_routes())
    }

    async fn update_network_stats(&mut self) -> Result<(), ClientError> {
        // In real implementation, this would gather stats from the network interface
        // For now, simulate some activity
        self.network_stats.bytes_sent += 1024 * 100; // 100KB
        self.network_stats.bytes_received += 1024 * 500; // 500KB
        self.network_stats.packets_sent += 50;
        self.network_stats.packets_received += 200;
        self.network_stats.connections_active = self.machines.iter().filter(|m| m.online).count() as u32;
        self.network_stats.last_handshake = Some(chrono::Utc::now());

        Ok(())
    }

    async fn start_background_sync(&self) -> Result<(), ClientError> {
        // In real implementation, this would start background tasks for:
        // - Periodic data synchronization
        // - Connection health monitoring
        // - Network event handling
        info!("Background sync tasks started");
        Ok(())
    }

    // Mock data generators for testing
    fn create_mock_machines(&self) -> Vec<Machine> {
        use std::net::IpAddr;

        vec![
            Machine {
                id: "machine-1".to_string(),
                name: "laptop-alice".to_string(),
                hostname: "alice-laptop".to_string(),
                user: "alice@example.com".to_string(),
                online: true,
                ip_addresses: vec!["100.64.0.2".parse::<IpAddr>().unwrap()],
                os: Some("macOS".to_string()),
                last_seen: Some(chrono::Utc::now() - chrono::Duration::minutes(2)),
                tags: vec!["user:alice".to_string(), "device:laptop".to_string()],
                routes: vec!["192.168.1.0/24".to_string()],
                endpoints: vec!["203.0.113.5:41641".to_string()],
                relay_node: None,
                direct_connection: true,
                latency: Some(23),
            },
            Machine {
                id: "machine-2".to_string(),
                name: "server-prod".to_string(),
                hostname: "prod-server-01".to_string(),
                user: "system@example.com".to_string(),
                online: true,
                ip_addresses: vec!["100.64.0.3".parse::<IpAddr>().unwrap()],
                os: Some("Ubuntu 22.04".to_string()),
                last_seen: Some(chrono::Utc::now() - chrono::Duration::minutes(1)),
                tags: vec!["environment:production".to_string(), "role:server".to_string()],
                routes: vec!["10.0.0.0/8".to_string()],
                endpoints: vec!["203.0.113.10:41641".to_string()],
                relay_node: Some("us-east-1".to_string()),
                direct_connection: false,
                latency: Some(67),
            },
            Machine {
                id: "machine-3".to_string(),
                name: "phone-bob".to_string(),
                hostname: "bobs-iphone".to_string(),
                user: "bob@example.com".to_string(),
                online: false,
                ip_addresses: vec!["100.64.0.4".parse::<IpAddr>().unwrap()],
                os: Some("iOS".to_string()),
                last_seen: Some(chrono::Utc::now() - chrono::Duration::hours(3)),
                tags: vec!["user:bob".to_string(), "device:mobile".to_string()],
                routes: vec![],
                endpoints: vec![],
                relay_node: None,
                direct_connection: false,
                latency: None,
            },
        ]
    }

    fn create_mock_routes(&self) -> Vec<Route> {
        vec![
            Route {
                destination: "192.168.1.0/24".to_string(),
                gateway: "100.64.0.2".to_string(),
                advertiser: "machine-1".to_string(),
                enabled: true,
                primary: true,
            },
            Route {
                destination: "10.0.0.0/8".to_string(),
                gateway: "100.64.0.3".to_string(),
                advertiser: "machine-2".to_string(),
                enabled: true,
                primary: true,
            },
        ]
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("Configuration error: {0}")]
    Config(#[from] crate::config::ConfigError),
    #[error("HTTP client error: {0}")]
    HttpClient(#[from] reqwest::Error),
    #[error("HTTP request error: {0}")]
    HttpRequest(reqwest::Error),
    #[error("Server error: {0}")]
    ServerError(String),
    #[error("Network error: {0}")]
    NetworkError(String),
    #[error("Authentication error: {0}")]
    AuthError(String),
    #[error("Connection timeout")]
    Timeout,
}