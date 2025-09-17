/// Network map distributor
///
/// Handles distribution of network maps to connected nodes using various
/// transport mechanisms including WebSocket streaming, HTTP polling,
/// and gRPC streaming with support for compression and retry logic.

use crate::netmap::types::*;
use crate::netmap::NetworkMapConfig;
use ghostwire_common::{
    types::*,
    error::{Result, GhostWireError},
};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, Duration, Instant};
use tokio::sync::{RwLock, broadcast, mpsc};
use tokio::time::{sleep, timeout};
use tracing::{debug, warn, error, info};
use serde::{Serialize, Deserialize};
use uuid::Uuid;

/// Distribution method
#[derive(Debug, Clone)]
pub enum DistributionMethod {
    /// WebSocket streaming
    WebSocket,
    /// HTTP polling
    HttpPolling,
    /// gRPC streaming
    GrpcStream,
    /// Push notification
    PushNotification,
}

/// Node subscription for network map updates
#[derive(Debug, Clone)]
pub struct NodeSubscription {
    /// Node ID
    pub node_id: NodeId,

    /// Distribution method
    pub method: DistributionMethod,

    /// Last map version received
    pub last_version: u64,

    /// Subscription created at
    pub created_at: SystemTime,

    /// Last update sent
    pub last_update: Option<SystemTime>,

    /// Subscription active
    pub active: bool,

    /// Distribution options
    pub options: DistributionOptions,
}

/// Distribution options
#[derive(Debug, Clone)]
pub struct DistributionOptions {
    /// Prefer delta updates
    pub prefer_deltas: bool,

    /// Compression enabled
    pub enable_compression: bool,

    /// Maximum update frequency (seconds)
    pub max_update_frequency: u64,

    /// Include offline nodes
    pub include_offline: bool,

    /// Custom filters
    pub filters: Vec<String>,
}

impl Default for DistributionOptions {
    fn default() -> Self {
        Self {
            prefer_deltas: true,
            enable_compression: true,
            max_update_frequency: 10,
            include_offline: false,
            filters: vec![],
        }
    }
}

/// Distribution task
#[derive(Debug, Clone)]
pub struct DistributionTask {
    /// Task ID
    pub id: Uuid,

    /// Target node ID
    pub node_id: NodeId,

    /// Distribution method
    pub method: DistributionMethod,

    /// Task type
    pub task_type: DistributionTaskType,

    /// Created at
    pub created_at: Instant,

    /// Retry count
    pub retry_count: u32,

    /// Task status
    pub status: DistributionTaskStatus,
}

/// Distribution task type
#[derive(Debug, Clone)]
pub enum DistributionTaskType {
    /// Full network map
    FullMap(NetworkMap),
    /// Delta update
    Delta(NetworkMapDelta),
    /// Subscription acknowledgment
    SubscriptionAck,
}

/// Distribution task status
#[derive(Debug, Clone, PartialEq)]
pub enum DistributionTaskStatus {
    Pending,
    InProgress,
    Completed,
    Failed,
    Retrying,
}

/// Network map distributor
#[derive(Clone)]
pub struct NetworkMapDistributor {
    config: NetworkMapConfig,
    subscriptions: Arc<RwLock<HashMap<NodeId, NodeSubscription>>>,
    distribution_queue: Arc<RwLock<Vec<DistributionTask>>>,
    stats: Arc<RwLock<DistributionStats>>,
    broadcast_sender: Arc<RwLock<Option<broadcast::Sender<NetworkMapUpdate>>>>,
    is_running: Arc<RwLock<bool>>,
}

/// Network map update message
#[derive(Debug, Clone)]
pub struct NetworkMapUpdate {
    /// Update type
    pub update_type: NetworkMapUpdateType,
    /// Target node (None for broadcast)
    pub target_node: Option<NodeId>,
    /// Timestamp
    pub timestamp: SystemTime,
}

/// Network map update type
#[derive(Debug, Clone)]
pub enum NetworkMapUpdateType {
    /// Full map update
    FullMap(NetworkMap),
    /// Delta update
    Delta(NetworkMapDelta),
    /// Subscription request
    Subscribe(NodeId, DistributionOptions),
    /// Unsubscribe request
    Unsubscribe(NodeId),
}

impl NetworkMapDistributor {
    /// Create a new network map distributor
    pub fn new(config: NetworkMapConfig) -> Self {
        Self {
            config,
            subscriptions: Arc::new(RwLock::new(HashMap::new())),
            distribution_queue: Arc::new(RwLock::new(Vec::new())),
            stats: Arc::new(RwLock::new(DistributionStats {
                total_distributions: 0,
                successful_distributions: 0,
                failed_distributions: 0,
                average_distribution_time_ms: 0.0,
                active_subscriptions: 0,
                pending_distributions: 0,
            })),
            broadcast_sender: Arc::new(RwLock::new(None)),
            is_running: Arc::new(RwLock::new(false)),
        }
    }

    /// Start the distributor
    pub async fn start(&self) -> Result<()> {
        info!("Starting network map distributor");

        *self.is_running.write().await = true;

        // Create broadcast channel
        let (tx, _) = broadcast::channel(1000);
        *self.broadcast_sender.write().await = Some(tx);

        // Start distribution worker tasks
        self.start_distribution_workers().await;

        // Start subscription cleanup task
        self.start_cleanup_task().await;

        info!("Network map distributor started");
        Ok(())
    }

    /// Stop the distributor
    pub async fn stop(&self) -> Result<()> {
        info!("Stopping network map distributor");

        *self.is_running.write().await = false;

        // Clear broadcast sender
        *self.broadcast_sender.write().await = None;

        // Clear subscriptions
        self.subscriptions.write().await.clear();

        // Clear distribution queue
        self.distribution_queue.write().await.clear();

        info!("Network map distributor stopped");
        Ok(())
    }

    /// Subscribe a node to network map updates
    pub async fn subscribe(
        &self,
        node_id: NodeId,
        method: DistributionMethod,
        options: DistributionOptions,
    ) -> Result<()> {
        debug!("Subscribing node {} to network map updates", node_id);

        let subscription = NodeSubscription {
            node_id,
            method,
            last_version: 0,
            created_at: SystemTime::now(),
            last_update: None,
            active: true,
            options,
        };

        self.subscriptions.write().await.insert(node_id, subscription);

        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.active_subscriptions = self.subscriptions.read().await.len();
        }

        // Send subscription update
        if let Some(sender) = self.broadcast_sender.read().await.as_ref() {
            let update = NetworkMapUpdate {
                update_type: NetworkMapUpdateType::Subscribe(node_id, options),
                target_node: Some(node_id),
                timestamp: SystemTime::now(),
            };

            if sender.send(update).is_err() {
                warn!("Failed to send subscription update for node {}", node_id);
            }
        }

        debug!("Node {} subscribed successfully", node_id);
        Ok(())
    }

    /// Unsubscribe a node from network map updates
    pub async fn unsubscribe(&self, node_id: &NodeId) -> Result<bool> {
        debug!("Unsubscribing node {} from network map updates", node_id);

        let removed = self.subscriptions.write().await.remove(node_id).is_some();

        if removed {
            // Update stats
            {
                let mut stats = self.stats.write().await;
                stats.active_subscriptions = self.subscriptions.read().await.len();
            }

            // Send unsubscribe update
            if let Some(sender) = self.broadcast_sender.read().await.as_ref() {
                let update = NetworkMapUpdate {
                    update_type: NetworkMapUpdateType::Unsubscribe(*node_id),
                    target_node: Some(*node_id),
                    timestamp: SystemTime::now(),
                };

                if sender.send(update).is_err() {
                    warn!("Failed to send unsubscribe update for node {}", node_id);
                }
            }

            debug!("Node {} unsubscribed successfully", node_id);
        } else {
            debug!("Node {} was not subscribed", node_id);
        }

        Ok(removed)
    }

    /// Distribute a full network map
    pub async fn distribute_full_map(&self, network_map: NetworkMap) -> Result<()> {
        debug!("Distributing full network map version {}", network_map.version);

        let subscriptions = self.subscriptions.read().await.clone();

        for (node_id, subscription) in subscriptions {
            if !subscription.active {
                continue;
            }

            // Check update frequency limits
            if let Some(last_update) = subscription.last_update {
                let elapsed = SystemTime::now()
                    .duration_since(last_update)
                    .unwrap_or_default()
                    .as_secs();

                if elapsed < subscription.options.max_update_frequency {
                    debug!("Skipping update for node {} due to frequency limit", node_id);
                    continue;
                }
            }

            // Create distribution task
            let task = DistributionTask {
                id: Uuid::new_v4(),
                node_id,
                method: subscription.method.clone(),
                task_type: DistributionTaskType::FullMap(network_map.clone()),
                created_at: Instant::now(),
                retry_count: 0,
                status: DistributionTaskStatus::Pending,
            };

            self.distribution_queue.write().await.push(task);
        }

        // Send broadcast update
        if let Some(sender) = self.broadcast_sender.read().await.as_ref() {
            let update = NetworkMapUpdate {
                update_type: NetworkMapUpdateType::FullMap(network_map),
                target_node: None,
                timestamp: SystemTime::now(),
            };

            if sender.send(update).is_err() {
                warn!("Failed to send full map broadcast update");
            }
        }

        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.pending_distributions = self.distribution_queue.read().await.len();
        }

        debug!("Full network map distribution queued for {} subscribers", subscriptions.len());
        Ok(())
    }

    /// Distribute a network map delta
    pub async fn distribute_delta(&self, delta: NetworkMapDelta) -> Result<()> {
        debug!("Distributing network map delta version {}", delta.version);

        let subscriptions = self.subscriptions.read().await.clone();

        for (node_id, subscription) in subscriptions {
            if !subscription.active {
                continue;
            }

            // Check if node can receive deltas
            if !subscription.options.prefer_deltas {
                continue;
            }

            // Check if delta applies to this node's last version
            if subscription.last_version != delta.previous_version {
                debug!("Skipping delta for node {}: version mismatch", node_id);
                continue;
            }

            // Check update frequency limits
            if let Some(last_update) = subscription.last_update {
                let elapsed = SystemTime::now()
                    .duration_since(last_update)
                    .unwrap_or_default()
                    .as_secs();

                if elapsed < subscription.options.max_update_frequency {
                    debug!("Skipping delta for node {} due to frequency limit", node_id);
                    continue;
                }
            }

            // Create distribution task
            let task = DistributionTask {
                id: Uuid::new_v4(),
                node_id,
                method: subscription.method.clone(),
                task_type: DistributionTaskType::Delta(delta.clone()),
                created_at: Instant::now(),
                retry_count: 0,
                status: DistributionTaskStatus::Pending,
            };

            self.distribution_queue.write().await.push(task);
        }

        // Send broadcast update
        if let Some(sender) = self.broadcast_sender.read().await.as_ref() {
            let update = NetworkMapUpdate {
                update_type: NetworkMapUpdateType::Delta(delta),
                target_node: None,
                timestamp: SystemTime::now(),
            };

            if sender.send(update).is_err() {
                warn!("Failed to send delta broadcast update");
            }
        }

        debug!("Network map delta distribution queued");
        Ok(())
    }

    /// Get statistics
    pub async fn get_stats(&self) -> DistributionStats {
        self.stats.read().await.clone()
    }

    /// Get active subscriptions
    pub async fn get_subscriptions(&self) -> Vec<NodeSubscription> {
        self.subscriptions.read().await.values().cloned().collect()
    }

    /// Get distribution queue status
    pub async fn get_queue_status(&self) -> Vec<DistributionTask> {
        self.distribution_queue.read().await.clone()
    }

    /// Create a broadcast receiver
    pub async fn create_receiver(&self) -> Option<broadcast::Receiver<NetworkMapUpdate>> {
        if let Some(sender) = self.broadcast_sender.read().await.as_ref() {
            Some(sender.subscribe())
        } else {
            None
        }
    }

    // Private helper methods

    async fn start_distribution_workers(&self) {
        let worker_count = self.config.distribution.max_concurrent;

        for worker_id in 0..worker_count {
            let distributor = self.clone();
            let is_running = self.is_running.clone();

            tokio::spawn(async move {
                debug!("Starting distribution worker {}", worker_id);

                while *is_running.read().await {
                    if let Some(task) = distributor.get_next_task().await {
                        distributor.process_distribution_task(task).await;
                    } else {
                        // No tasks available, sleep briefly
                        sleep(Duration::from_millis(100)).await;
                    }
                }

                debug!("Distribution worker {} stopped", worker_id);
            });
        }
    }

    async fn start_cleanup_task(&self) {
        let distributor = self.clone();
        let is_running = self.is_running.clone();

        tokio::spawn(async move {
            debug!("Starting subscription cleanup task");

            let mut interval = tokio::time::interval(Duration::from_secs(300)); // 5 minutes

            while *is_running.read().await {
                interval.tick().await;
                distributor.cleanup_inactive_subscriptions().await;
            }

            debug!("Subscription cleanup task stopped");
        });
    }

    async fn get_next_task(&self) -> Option<DistributionTask> {
        let mut queue = self.distribution_queue.write().await;

        // Find the first pending task
        if let Some(index) = queue.iter().position(|task| task.status == DistributionTaskStatus::Pending) {
            let mut task = queue.remove(index);
            task.status = DistributionTaskStatus::InProgress;
            Some(task)
        } else {
            None
        }
    }

    async fn process_distribution_task(&self, mut task: DistributionTask) {
        let start_time = Instant::now();

        debug!("Processing distribution task {} for node {}", task.id, task.node_id);

        let result = match &task.method {
            DistributionMethod::WebSocket => self.distribute_via_websocket(&task).await,
            DistributionMethod::HttpPolling => self.distribute_via_http(&task).await,
            DistributionMethod::GrpcStream => self.distribute_via_grpc(&task).await,
            DistributionMethod::PushNotification => self.distribute_via_push(&task).await,
        };

        let duration = start_time.elapsed();

        match result {
            Ok(_) => {
                task.status = DistributionTaskStatus::Completed;

                // Update subscription last version and update time
                if let Some(subscription) = self.subscriptions.write().await.get_mut(&task.node_id) {
                    match &task.task_type {
                        DistributionTaskType::FullMap(map) => {
                            subscription.last_version = map.version;
                        }
                        DistributionTaskType::Delta(delta) => {
                            subscription.last_version = delta.version;
                        }
                        _ => {}
                    }
                    subscription.last_update = Some(SystemTime::now());
                }

                // Update stats
                {
                    let mut stats = self.stats.write().await;
                    stats.total_distributions += 1;
                    stats.successful_distributions += 1;

                    // Update average distribution time
                    let total_successful = stats.successful_distributions as f64;
                    let current_avg = stats.average_distribution_time_ms;
                    let new_time = duration.as_millis() as f64;

                    stats.average_distribution_time_ms =
                        (current_avg * (total_successful - 1.0) + new_time) / total_successful;
                }

                debug!("Distribution task {} completed in {}ms", task.id, duration.as_millis());
            }
            Err(e) => {
                warn!("Distribution task {} failed: {}", task.id, e);

                task.retry_count += 1;

                if task.retry_count < self.config.distribution.retry_attempts {
                    task.status = DistributionTaskStatus::Retrying;

                    // Calculate backoff delay
                    let backoff_delay = Duration::from_secs(
                        (task.retry_count as f64 * self.config.distribution.retry_backoff_multiplier) as u64
                    );

                    // Re-queue task after delay
                    let distributor = self.clone();
                    tokio::spawn(async move {
                        sleep(backoff_delay).await;
                        task.status = DistributionTaskStatus::Pending;
                        distributor.distribution_queue.write().await.push(task);
                    });
                } else {
                    task.status = DistributionTaskStatus::Failed;

                    // Update stats
                    {
                        let mut stats = self.stats.write().await;
                        stats.total_distributions += 1;
                        stats.failed_distributions += 1;
                    }

                    error!("Distribution task {} failed permanently after {} retries", task.id, task.retry_count);
                }
            }
        }
    }

    async fn distribute_via_websocket(&self, task: &DistributionTask) -> Result<()> {
        // In a real implementation, this would send the update via WebSocket
        debug!("Distributing via WebSocket to node {}", task.node_id);

        // Simulate distribution
        sleep(Duration::from_millis(10)).await;

        Ok(())
    }

    async fn distribute_via_http(&self, task: &DistributionTask) -> Result<()> {
        // In a real implementation, this would make an HTTP request
        debug!("Distributing via HTTP to node {}", task.node_id);

        // Simulate distribution
        sleep(Duration::from_millis(50)).await;

        Ok(())
    }

    async fn distribute_via_grpc(&self, task: &DistributionTask) -> Result<()> {
        // In a real implementation, this would send via gRPC stream
        debug!("Distributing via gRPC to node {}", task.node_id);

        // Simulate distribution
        sleep(Duration::from_millis(20)).await;

        Ok(())
    }

    async fn distribute_via_push(&self, task: &DistributionTask) -> Result<()> {
        // In a real implementation, this would send a push notification
        debug!("Distributing via push notification to node {}", task.node_id);

        // Simulate distribution
        sleep(Duration::from_millis(100)).await;

        Ok(())
    }

    async fn cleanup_inactive_subscriptions(&self) {
        debug!("Cleaning up inactive subscriptions");

        let mut subscriptions = self.subscriptions.write().await;
        let now = SystemTime::now();
        let inactive_threshold = Duration::from_secs(3600); // 1 hour

        let initial_count = subscriptions.len();

        subscriptions.retain(|_, subscription| {
            if let Some(last_update) = subscription.last_update {
                now.duration_since(last_update).unwrap_or_default() < inactive_threshold
            } else {
                now.duration_since(subscription.created_at).unwrap_or_default() < inactive_threshold
            }
        });

        let removed_count = initial_count - subscriptions.len();

        if removed_count > 0 {
            info!("Cleaned up {} inactive subscriptions", removed_count);

            // Update stats
            if let Ok(mut stats) = self.stats.try_write() {
                stats.active_subscriptions = subscriptions.len();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_config() -> NetworkMapConfig {
        crate::netmap::NetworkMapConfig::default()
    }

    #[tokio::test]
    async fn test_distributor_lifecycle() {
        let config = create_test_config();
        let distributor = NetworkMapDistributor::new(config);

        // Start distributor
        assert!(distributor.start().await.is_ok());

        // Stop distributor
        assert!(distributor.stop().await.is_ok());
    }

    #[tokio::test]
    async fn test_subscription_management() {
        let config = create_test_config();
        let distributor = NetworkMapDistributor::new(config);

        distributor.start().await.unwrap();

        let node_id = Uuid::new_v4();
        let options = DistributionOptions::default();

        // Subscribe node
        assert!(distributor.subscribe(node_id, DistributionMethod::WebSocket, options).await.is_ok());

        // Check subscription exists
        let subscriptions = distributor.get_subscriptions().await;
        assert_eq!(subscriptions.len(), 1);
        assert_eq!(subscriptions[0].node_id, node_id);

        // Unsubscribe node
        assert!(distributor.unsubscribe(&node_id).await.unwrap());

        // Check subscription removed
        let subscriptions = distributor.get_subscriptions().await;
        assert_eq!(subscriptions.len(), 0);

        distributor.stop().await.unwrap();
    }

    #[tokio::test]
    async fn test_broadcast_receiver() {
        let config = create_test_config();
        let distributor = NetworkMapDistributor::new(config);

        distributor.start().await.unwrap();

        let receiver = distributor.create_receiver().await;
        assert!(receiver.is_some());

        distributor.stop().await.unwrap();
    }

    #[tokio::test]
    async fn test_distribution_stats() {
        let config = create_test_config();
        let distributor = NetworkMapDistributor::new(config);

        let stats = distributor.get_stats().await;
        assert_eq!(stats.total_distributions, 0);
        assert_eq!(stats.successful_distributions, 0);
        assert_eq!(stats.failed_distributions, 0);
        assert_eq!(stats.active_subscriptions, 0);
    }
}