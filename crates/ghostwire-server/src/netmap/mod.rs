/// Network map generation and distribution system
///
/// Provides comprehensive network map generation for the GhostWire mesh,
/// including node information, routes, DNS configuration, and security policies.
/// Supports real-time updates and efficient delta distribution.

pub mod generator;
pub mod distributor;
pub mod types;

pub use generator::NetworkMapGenerator;
pub use distributor::NetworkMapDistributor;
pub use types::*;

use ghostwire_common::{
    types::*,
    error::{Result, GhostWireError},
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{SystemTime, Duration};
use uuid::Uuid;

/// Network map configuration
#[derive(Debug, Clone, Deserialize)]
pub struct NetworkMapConfig {
    /// Enable network map generation
    pub enabled: bool,

    /// Update interval in seconds
    pub update_interval_seconds: u64,

    /// Include DNS configuration in network map
    pub include_dns: bool,

    /// Include routes in network map
    pub include_routes: bool,

    /// Include ACL policies in network map
    pub include_policies: bool,

    /// Enable delta updates (only send changes)
    pub enable_deltas: bool,

    /// Maximum delta history to keep
    pub max_delta_history: usize,

    /// Compression settings
    pub compression: CompressionConfig,

    /// Distribution settings
    pub distribution: DistributionConfig,
}

impl Default for NetworkMapConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            update_interval_seconds: 30,
            include_dns: true,
            include_routes: true,
            include_policies: true,
            enable_deltas: true,
            max_delta_history: 100,
            compression: CompressionConfig::default(),
            distribution: DistributionConfig::default(),
        }
    }
}

/// Compression configuration
#[derive(Debug, Clone, Deserialize)]
pub struct CompressionConfig {
    /// Enable compression
    pub enabled: bool,

    /// Compression algorithm
    pub algorithm: CompressionAlgorithm,

    /// Compression level (1-9)
    pub level: u8,

    /// Minimum size threshold for compression
    pub min_size_bytes: usize,
}

impl Default for CompressionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            algorithm: CompressionAlgorithm::Zstd,
            level: 6,
            min_size_bytes: 1024,
        }
    }
}

/// Distribution configuration
#[derive(Debug, Clone, Deserialize)]
pub struct DistributionConfig {
    /// Maximum concurrent distributions
    pub max_concurrent: usize,

    /// Distribution timeout
    pub timeout_seconds: u64,

    /// Retry attempts for failed distributions
    pub retry_attempts: u32,

    /// Retry backoff multiplier
    pub retry_backoff_multiplier: f64,

    /// Enable push notifications
    pub enable_push: bool,

    /// Enable WebSocket streaming
    pub enable_websocket: bool,
}

impl Default for DistributionConfig {
    fn default() -> Self {
        Self {
            max_concurrent: 100,
            timeout_seconds: 30,
            retry_attempts: 3,
            retry_backoff_multiplier: 2.0,
            enable_push: true,
            enable_websocket: true,
        }
    }
}

/// Compression algorithms
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CompressionAlgorithm {
    None,
    Gzip,
    Zstd,
    Lz4,
}

/// Network map service
pub struct NetworkMapService {
    config: NetworkMapConfig,
    generator: NetworkMapGenerator,
    distributor: NetworkMapDistributor,
    current_map: std::sync::Arc<std::sync::RwLock<Option<NetworkMap>>>,
    delta_history: std::sync::Arc<std::sync::RwLock<Vec<NetworkMapDelta>>>,
    is_running: std::sync::Arc<std::sync::RwLock<bool>>,
}

impl NetworkMapService {
    /// Create a new network map service
    pub fn new(config: NetworkMapConfig) -> Self {
        let generator = NetworkMapGenerator::new(config.clone());
        let distributor = NetworkMapDistributor::new(config.clone());

        Self {
            config,
            generator,
            distributor,
            current_map: std::sync::Arc::new(std::sync::RwLock::new(None)),
            delta_history: std::sync::Arc::new(std::sync::RwLock::new(Vec::new())),
            is_running: std::sync::Arc::new(std::sync::RwLock::new(false)),
        }
    }

    /// Start the network map service
    pub async fn start(&self) -> Result<()> {
        tracing::info!("Starting network map service");

        *self.is_running.write().unwrap() = true;

        // Start periodic update task
        if self.config.update_interval_seconds > 0 {
            self.start_update_task().await;
        }

        // Start distribution service
        self.distributor.start().await?;

        tracing::info!("Network map service started");
        Ok(())
    }

    /// Stop the network map service
    pub async fn stop(&self) -> Result<()> {
        tracing::info!("Stopping network map service");

        *self.is_running.write().unwrap() = false;

        // Stop distribution service
        self.distributor.stop().await?;

        tracing::info!("Network map service stopped");
        Ok(())
    }

    /// Generate and distribute a new network map
    pub async fn generate_and_distribute(&self, coordinator: &crate::coordinator::Coordinator) -> Result<NetworkMap> {
        let network_map = self.generator.generate(coordinator).await?;

        // Update current map
        let mut current_map = self.current_map.write().unwrap();
        let previous_map = current_map.clone();
        *current_map = Some(network_map.clone());

        // Generate delta if we have a previous map
        if self.config.enable_deltas {
            if let Some(prev_map) = previous_map {
                let delta = self.generator.generate_delta(&prev_map, &network_map)?;
                self.add_delta_to_history(delta.clone());

                // Distribute delta
                self.distributor.distribute_delta(delta).await?;
            } else {
                // First map generation - distribute full map
                self.distributor.distribute_full_map(network_map.clone()).await?;
            }
        } else {
            // Always distribute full map
            self.distributor.distribute_full_map(network_map.clone()).await?;
        }

        Ok(network_map)
    }

    /// Get the current network map
    pub async fn get_current_map(&self) -> Option<NetworkMap> {
        self.current_map.read().unwrap().clone()
    }

    /// Get network map for a specific node
    pub async fn get_map_for_node(&self, node_id: &NodeId) -> Result<Option<NetworkMap>> {
        if let Some(current_map) = self.get_current_map().await {
            // Filter map for specific node (apply ACL, etc.)
            let filtered_map = self.generator.filter_map_for_node(&current_map, node_id).await?;
            Ok(Some(filtered_map))
        } else {
            Ok(None)
        }
    }

    /// Get delta history for a node
    pub async fn get_deltas_since(&self, since_version: u64, node_id: &NodeId) -> Result<Vec<NetworkMapDelta>> {
        let delta_history = self.delta_history.read().unwrap();

        let filtered_deltas = delta_history
            .iter()
            .filter(|delta| delta.version > since_version)
            .filter_map(|delta| {
                // Filter delta for specific node
                self.generator.filter_delta_for_node(delta, node_id).ok()
            })
            .collect();

        Ok(filtered_deltas)
    }

    /// Force a network map update
    pub async fn force_update(&self, coordinator: &crate::coordinator::Coordinator) -> Result<()> {
        tracing::info!("Forcing network map update");
        self.generate_and_distribute(coordinator).await?;
        Ok(())
    }

    /// Add a delta to the history
    fn add_delta_to_history(&self, delta: NetworkMapDelta) {
        let mut history = self.delta_history.write().unwrap();
        history.push(delta);

        // Trim history if it exceeds maximum size
        if history.len() > self.config.max_delta_history {
            history.drain(0..history.len() - self.config.max_delta_history);
        }
    }

    /// Start the periodic update task
    async fn start_update_task(&self) {
        let config = self.config.clone();
        let service = self.clone();
        let is_running = self.is_running.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(config.update_interval_seconds));

            loop {
                interval.tick().await;

                if !*is_running.read().unwrap() {
                    break;
                }

                // This would need coordinator reference - simplified for now
                tracing::debug!("Network map periodic update triggered");

                // In real implementation, we'd need to get coordinator reference
                // and call service.generate_and_distribute(coordinator).await
            }

            tracing::debug!("Network map update task stopped");
        });
    }

    /// Get service statistics
    pub async fn get_stats(&self) -> NetworkMapStats {
        let current_map = self.current_map.read().unwrap();
        let delta_history = self.delta_history.read().unwrap();

        let (nodes_count, routes_count, dns_records_count) = if let Some(ref map) = *current_map {
            (
                map.nodes.len(),
                map.routes.iter().map(|r| r.routes.len()).sum::<usize>(),
                map.dns_config.as_ref().map_or(0, |dns| dns.records.len()),
            )
        } else {
            (0, 0, 0)
        };

        NetworkMapStats {
            current_version: current_map.as_ref().map(|m| m.version).unwrap_or(0),
            nodes_count,
            routes_count,
            dns_records_count,
            delta_history_size: delta_history.len(),
            last_update: current_map.as_ref().map(|m| m.generated_at),
            distribution_stats: self.distributor.get_stats().await,
        }
    }
}

impl Clone for NetworkMapService {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            generator: self.generator.clone(),
            distributor: self.distributor.clone(),
            current_map: self.current_map.clone(),
            delta_history: self.delta_history.clone(),
            is_running: self.is_running.clone(),
        }
    }
}

/// Network map statistics
#[derive(Debug, Clone, Serialize)]
pub struct NetworkMapStats {
    pub current_version: u64,
    pub nodes_count: usize,
    pub routes_count: usize,
    pub dns_records_count: usize,
    pub delta_history_size: usize,
    pub last_update: Option<SystemTime>,
    pub distribution_stats: DistributionStats,
}

/// Distribution statistics
#[derive(Debug, Clone, Serialize)]
pub struct DistributionStats {
    pub total_distributions: u64,
    pub successful_distributions: u64,
    pub failed_distributions: u64,
    pub average_distribution_time_ms: f64,
    pub active_subscriptions: usize,
    pub pending_distributions: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_map_config_default() {
        let config = NetworkMapConfig::default();
        assert!(config.enabled);
        assert_eq!(config.update_interval_seconds, 30);
        assert!(config.include_dns);
        assert!(config.include_routes);
        assert!(config.enable_deltas);
    }

    #[test]
    fn test_compression_config_default() {
        let config = CompressionConfig::default();
        assert!(config.enabled);
        assert!(matches!(config.algorithm, CompressionAlgorithm::Zstd));
        assert_eq!(config.level, 6);
        assert_eq!(config.min_size_bytes, 1024);
    }

    #[test]
    fn test_distribution_config_default() {
        let config = DistributionConfig::default();
        assert_eq!(config.max_concurrent, 100);
        assert_eq!(config.timeout_seconds, 30);
        assert_eq!(config.retry_attempts, 3);
        assert!(config.enable_push);
        assert!(config.enable_websocket);
    }

    #[tokio::test]
    async fn test_network_map_service_lifecycle() {
        let config = NetworkMapConfig::default();
        let service = NetworkMapService::new(config);

        // Service should start successfully
        assert!(service.start().await.is_ok());

        // Service should stop successfully
        assert!(service.stop().await.is_ok());
    }

    #[tokio::test]
    async fn test_network_map_service_stats() {
        let config = NetworkMapConfig::default();
        let service = NetworkMapService::new(config);

        let stats = service.get_stats().await;
        assert_eq!(stats.current_version, 0);
        assert_eq!(stats.nodes_count, 0);
        assert_eq!(stats.routes_count, 0);
        assert_eq!(stats.delta_history_size, 0);
    }
}