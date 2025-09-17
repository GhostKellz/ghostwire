/// Heartbeat monitoring and node health tracking
///
/// Monitors node connectivity and health with:
/// - Periodic heartbeat tracking
/// - Automatic offline detection
/// - Grace period handling
/// - Health status updates

use super::node_manager::NodeManager;
use crate::database::{DatabaseConnection, MetricsOperations};
use ghostwire_common::{
    error::{Result, GhostWireError},
    types::*,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// Heartbeat monitor
pub struct HeartbeatMonitor {
    database: Arc<DatabaseConnection>,
    node_manager: Arc<NodeManager>,
    heartbeats: Arc<RwLock<HashMap<NodeId, HeartbeatInfo>>>,
    keepalive_interval: Duration,
    stop_signal: Arc<RwLock<bool>>,
}

/// Node heartbeat information
#[derive(Debug, Clone)]
struct HeartbeatInfo {
    node_id: NodeId,
    last_heartbeat: SystemTime,
    consecutive_misses: u32,
    grace_period_end: Option<SystemTime>,
    is_online: bool,
}

impl HeartbeatMonitor {
    /// Create new heartbeat monitor
    pub fn new(
        database: Arc<DatabaseConnection>,
        node_manager: Arc<NodeManager>,
        keepalive_interval: Duration,
    ) -> Self {
        Self {
            database,
            node_manager,
            heartbeats: Arc::new(RwLock::new(HashMap::new())),
            keepalive_interval,
            stop_signal: Arc::new(RwLock::new(false)),
        }
    }

    /// Start heartbeat monitoring
    pub async fn start(&self) -> Result<()> {
        info!("Starting heartbeat monitor with {}s interval",
              self.keepalive_interval.as_secs());

        // Load existing online nodes
        let online_nodes = self.node_manager.get_online_nodes().await?;
        let mut heartbeats = self.heartbeats.write().await;

        for node in online_nodes {
            heartbeats.insert(node.id, HeartbeatInfo {
                node_id: node.id,
                last_heartbeat: node.last_seen,
                consecutive_misses: 0,
                grace_period_end: None,
                is_online: true,
            });
        }

        drop(heartbeats);

        // Start monitoring task
        self.start_monitor_task().await;

        Ok(())
    }

    /// Stop heartbeat monitoring
    pub async fn stop(&self) -> Result<()> {
        *self.stop_signal.write().await = true;
        info!("Heartbeat monitor stopped");
        Ok(())
    }

    /// Record a heartbeat from a node
    pub async fn record_heartbeat(&self, node_id: &NodeId) -> Result<()> {
        let now = SystemTime::now();
        let mut heartbeats = self.heartbeats.write().await;

        match heartbeats.get_mut(node_id) {
            Some(info) => {
                info.last_heartbeat = now;
                info.consecutive_misses = 0;
                info.grace_period_end = None;

                if !info.is_online {
                    // Node came back online
                    info.is_online = true;
                    self.node_manager.mark_online(node_id).await?;
                    info!("Node {} came back online", node_id);
                }
            }
            None => {
                // New node heartbeat
                heartbeats.insert(*node_id, HeartbeatInfo {
                    node_id: *node_id,
                    last_heartbeat: now,
                    consecutive_misses: 0,
                    grace_period_end: None,
                    is_online: true,
                });
                debug!("Started monitoring heartbeat for node {}", node_id);
            }
        }

        // Record metrics
        self.record_heartbeat_metric(node_id).await?;

        Ok(())
    }

    /// Remove node from monitoring
    pub async fn remove_node(&self, node_id: &NodeId) {
        self.heartbeats.write().await.remove(node_id);
        debug!("Stopped monitoring heartbeat for node {}", node_id);
    }

    /// Get node health status
    pub async fn get_node_health(&self, node_id: &NodeId) -> Option<NodeHealth> {
        let heartbeats = self.heartbeats.read().await;

        heartbeats.get(node_id).map(|info| {
            let now = SystemTime::now();
            let time_since_last = now.duration_since(info.last_heartbeat)
                .unwrap_or_default();

            NodeHealth {
                node_id: *node_id,
                is_online: info.is_online,
                last_seen: info.last_heartbeat,
                time_since_last_heartbeat: time_since_last,
                consecutive_misses: info.consecutive_misses,
                in_grace_period: info.grace_period_end.map_or(false, |end| now < end),
            }
        })
    }

    /// Start the background monitoring task
    async fn start_monitor_task(&self) {
        let database = Arc::clone(&self.database);
        let node_manager = Arc::clone(&self.node_manager);
        let heartbeats = Arc::clone(&self.heartbeats);
        let stop_signal = Arc::clone(&self.stop_signal);
        let keepalive_interval = self.keepalive_interval;

        tokio::spawn(async move {
            // Check every 30 seconds, regardless of keepalive interval
            let mut interval = tokio::time::interval(Duration::from_secs(30));

            loop {
                interval.tick().await;

                // Check stop signal
                if *stop_signal.read().await {
                    break;
                }

                // Check for missed heartbeats
                Self::check_missed_heartbeats(
                    &heartbeats,
                    &node_manager,
                    keepalive_interval,
                ).await;
            }

            info!("Heartbeat monitor task stopped");
        });
    }

    /// Check for missed heartbeats and handle offline nodes
    async fn check_missed_heartbeats(
        heartbeats: &Arc<RwLock<HashMap<NodeId, HeartbeatInfo>>>,
        node_manager: &Arc<NodeManager>,
        keepalive_interval: Duration,
    ) {
        let now = SystemTime::now();
        let timeout_threshold = keepalive_interval * 3; // 3x keepalive = timeout
        let grace_period = Duration::from_secs(60); // 1 minute grace period

        let mut heartbeats_guard = heartbeats.write().await;
        let mut nodes_to_mark_offline = Vec::new();

        for (node_id, info) in heartbeats_guard.iter_mut() {
            let time_since_last = now.duration_since(info.last_heartbeat)
                .unwrap_or_default();

            if time_since_last > keepalive_interval * 2 {
                info.consecutive_misses += 1;

                if time_since_last > timeout_threshold {
                    if info.is_online {
                        if info.grace_period_end.is_none() {
                            // Start grace period
                            info.grace_period_end = Some(now + grace_period);
                            warn!("Node {} missed heartbeat, starting grace period", node_id);
                        } else if now > info.grace_period_end.unwrap() {
                            // Grace period expired, mark offline
                            info.is_online = false;
                            nodes_to_mark_offline.push(*node_id);
                            warn!("Node {} marked as offline after {} consecutive misses",
                                  node_id, info.consecutive_misses);
                        }
                    }
                }
            }
        }

        drop(heartbeats_guard);

        // Mark nodes as offline
        for node_id in nodes_to_mark_offline {
            if let Err(e) = node_manager.mark_offline(&node_id).await {
                warn!("Failed to mark node {} as offline: {}", node_id, e);
            }
        }
    }

    /// Record heartbeat metric
    async fn record_heartbeat_metric(&self, node_id: &NodeId) -> Result<()> {
        let metrics = NodeMetrics {
            node_id: *node_id,
            timestamp: SystemTime::now(),
            rx_bytes: 0, // Will be updated by actual metrics
            tx_bytes: 0,
            rx_packets: 0,
            tx_packets: 0,
            latency_ms: None,
            packet_loss: None,
            bandwidth_bps: None,
        };

        // This is just a heartbeat metric - actual traffic metrics come from elsewhere
        MetricsOperations::record_metrics(&self.database, node_id, &metrics).await?;

        Ok(())
    }
}

/// Node health information
#[derive(Debug, Clone)]
pub struct NodeHealth {
    pub node_id: NodeId,
    pub is_online: bool,
    pub last_seen: SystemTime,
    pub time_since_last_heartbeat: Duration,
    pub consecutive_misses: u32,
    pub in_grace_period: bool,
}

impl NodeHealth {
    /// Get health status as string
    pub fn status(&self) -> &'static str {
        if self.is_online {
            "online"
        } else if self.in_grace_period {
            "grace_period"
        } else {
            "offline"
        }
    }

    /// Check if node is considered healthy
    pub fn is_healthy(&self) -> bool {
        self.is_online && self.consecutive_misses < 2
    }
}