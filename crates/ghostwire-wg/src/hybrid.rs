use crate::engine::{
    WireGuardEngine, WgInterface, WgConfig, WgPeer, WgStats,
    PerformanceTier, EngineSelectionCriteria, QuicWgContext,
};
use crate::optimized::OptimizedWireGuard;
use crate::quic_bridge::QuicWireGuardBridge;
use ghostwire_common::{
    error::{Result, GhostWireError},
    quic::QuicMessage,
    types::PublicKey,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, info, warn};

#[cfg(feature = "kernel-fallback")]
use crate::kernel::KernelWireGuard;

/// Hybrid WireGuard engine that automatically selects the best available implementation
///
/// Selection priority:
/// 1. Kernel WireGuard (if available and sufficient privileges)
/// 2. Optimized userspace (SIMD + multi-threaded)
/// 3. Pure boringtun (compatibility fallback)
pub struct HybridWireGuard {
    /// Currently active engine
    active_engine: Box<dyn WireGuardEngine>,
    /// Engine tier being used
    active_tier: PerformanceTier,
    /// Selection criteria
    criteria: EngineSelectionCriteria,
    /// Available engines (lazy loaded)
    available_engines: Arc<RwLock<AvailableEngines>>,
    /// QUIC bridge if enabled
    quic_bridge: Option<QuicWireGuardBridge>,
}

#[derive(Default)]
struct AvailableEngines {
    #[cfg(feature = "kernel-fallback")]
    kernel: Option<KernelWireGuard>,
    optimized: Option<OptimizedWireGuard>,
    boringtun: Option<BoringTunEngine>,
}

/// Compatibility wrapper for boringtun
struct BoringTunEngine {
    // Would wrap boringtun implementation
}

impl HybridWireGuard {
    /// Create a new hybrid WireGuard engine with automatic selection
    pub async fn new(criteria: EngineSelectionCriteria) -> Result<Self> {
        let available_engines = Arc::new(RwLock::new(AvailableEngines::default()));

        // Select the best available engine
        let (active_engine, active_tier) = Self::select_best_engine(&criteria, &available_engines).await?;

        info!("Selected WireGuard engine: {:?} tier", active_tier);

        Ok(Self {
            active_engine,
            active_tier,
            criteria,
            available_engines,
            quic_bridge: None,
        })
    }

    /// Create with specific engine preference
    pub async fn with_preferred_tier(tier: PerformanceTier) -> Result<Self> {
        let criteria = EngineSelectionCriteria {
            required_throughput: match tier {
                PerformanceTier::Compatibility => Some(500_000_000),
                PerformanceTier::Optimized => Some(2_000_000_000),
                PerformanceTier::Kernel => Some(5_000_000_000),
            },
            prefer_kernel: tier == PerformanceTier::Kernel,
            require_user_mode: tier != PerformanceTier::Kernel,
            enable_optimizations: tier >= PerformanceTier::Optimized,
            max_latency_ms: Some(5.0),
        };

        Self::new(criteria).await
    }

    /// Select the best available engine based on criteria
    async fn select_best_engine(
        criteria: &EngineSelectionCriteria,
        available_engines: &Arc<RwLock<AvailableEngines>>,
    ) -> Result<(Box<dyn WireGuardEngine>, PerformanceTier)> {
        let mut engines = available_engines.write().await;

        // Try kernel WireGuard first (if preferred and available)
        #[cfg(feature = "kernel-fallback")]
        if criteria.prefer_kernel && !criteria.require_user_mode {
            if engines.kernel.is_none() {
                engines.kernel = Some(KernelWireGuard::new().await.ok());
            }

            if let Some(ref kernel_engine) = engines.kernel {
                if kernel_engine.is_available() {
                    debug!("Selected kernel WireGuard engine");
                    return Ok((
                        Box::new(kernel_engine.clone()),
                        PerformanceTier::Kernel,
                    ));
                }
            }
        }

        // Try optimized userspace engine
        if criteria.enable_optimizations {
            if engines.optimized.is_none() {
                match OptimizedWireGuard::new().await {
                    Ok(engine) => engines.optimized = Some(engine),
                    Err(e) => warn!("Failed to initialize optimized engine: {}", e),
                }
            }

            if let Some(ref optimized_engine) = engines.optimized {
                if optimized_engine.is_available() {
                    // Check if it meets throughput requirements
                    if let Some(required_throughput) = criteria.required_throughput {
                        if optimized_engine.max_throughput() >= required_throughput {
                            debug!("Selected optimized userspace WireGuard engine");
                            return Ok((
                                Box::new(optimized_engine.clone()),
                                PerformanceTier::Optimized,
                            ));
                        }
                    } else {
                        debug!("Selected optimized userspace WireGuard engine");
                        return Ok((
                            Box::new(optimized_engine.clone()),
                            PerformanceTier::Optimized,
                        ));
                    }
                }
            }
        }

        // Fallback to boringtun (compatibility)
        if engines.boringtun.is_none() {
            engines.boringtun = Some(BoringTunEngine::new().await?);
        }

        if let Some(ref boringtun_engine) = engines.boringtun {
            debug!("Selected boringtun compatibility engine");
            return Ok((
                Box::new(boringtun_engine.clone()),
                PerformanceTier::Compatibility,
            ));
        }

        Err(GhostWireError::internal("No WireGuard engine available"))
    }

    /// Enable QUIC bridge for this interface
    pub async fn enable_quic_bridge(
        &mut self,
        interface: &WgInterface,
        quic_tx: mpsc::UnboundedSender<QuicMessage>,
        quic_rx: mpsc::UnboundedReceiver<QuicMessage>,
    ) -> Result<()> {
        use crate::quic_bridge::BridgeConfig;

        let bridge_config = BridgeConfig::default();
        let bridge = QuicWireGuardBridge::new(
            interface.clone(),
            quic_tx,
            quic_rx,
            bridge_config,
        );

        self.quic_bridge = Some(bridge);
        info!("QUIC bridge enabled for interface {}", interface.name);

        Ok(())
    }

    /// Start QUIC bridge processing (if enabled)
    pub async fn start_quic_bridge(&mut self) -> Result<()> {
        if let Some(ref mut bridge) = self.quic_bridge {
            tokio::spawn(async move {
                if let Err(e) = bridge.run().await {
                    tracing::error!("QUIC bridge error: {}", e);
                }
            });
        }

        Ok(())
    }

    /// Get current engine performance tier
    pub fn current_tier(&self) -> PerformanceTier {
        self.active_tier
    }

    /// Check if engine meets performance criteria
    pub fn meets_criteria(&self, required_throughput: u64) -> bool {
        match self.active_tier {
            PerformanceTier::Compatibility => required_throughput <= 500_000_000,
            PerformanceTier::Optimized => required_throughput <= 2_000_000_000,
            PerformanceTier::Kernel => true, // Kernel can handle anything
        }
    }

    /// Attempt to upgrade to a higher performance tier
    pub async fn try_upgrade(&mut self, target_tier: PerformanceTier) -> Result<bool> {
        if self.active_tier >= target_tier {
            return Ok(false); // Already at or above target tier
        }

        let criteria = EngineSelectionCriteria {
            required_throughput: Some(match target_tier {
                PerformanceTier::Compatibility => 500_000_000,
                PerformanceTier::Optimized => 2_000_000_000,
                PerformanceTier::Kernel => 5_000_000_000,
            }),
            prefer_kernel: target_tier == PerformanceTier::Kernel,
            require_user_mode: target_tier != PerformanceTier::Kernel,
            enable_optimizations: target_tier >= PerformanceTier::Optimized,
            max_latency_ms: Some(5.0),
        };

        // Try to select a better engine
        match Self::select_best_engine(&criteria, &self.available_engines).await {
            Ok((new_engine, new_tier)) if new_tier > self.active_tier => {
                info!("Upgraded WireGuard engine from {:?} to {:?}", self.active_tier, new_tier);
                self.active_engine = new_engine;
                self.active_tier = new_tier;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    /// Get detailed engine information
    pub fn engine_info(&self) -> EngineInfo {
        EngineInfo {
            tier: self.active_tier,
            max_throughput: match self.active_tier {
                PerformanceTier::Compatibility => 500_000_000,
                PerformanceTier::Optimized => 2_000_000_000,
                PerformanceTier::Kernel => 10_000_000_000,
            },
            features: self.get_engine_features(),
            quic_bridge_enabled: self.quic_bridge.is_some(),
        }
    }

    fn get_engine_features(&self) -> Vec<String> {
        let mut features = Vec::new();

        match self.active_tier {
            PerformanceTier::Compatibility => {
                features.push("Memory Safe".to_string());
                features.push("Cross Platform".to_string());
            }
            PerformanceTier::Optimized => {
                features.push("SIMD Optimized".to_string());
                features.push("Multi-threaded".to_string());
                features.push("Zero-copy QUIC".to_string());
                features.push("Batch Processing".to_string());
            }
            PerformanceTier::Kernel => {
                features.push("Kernel Bypass".to_string());
                features.push("Maximum Performance".to_string());
                features.push("Hardware Offload".to_string());
            }
        }

        if self.quic_bridge.is_some() {
            features.push("QUIC Bridge".to_string());
        }

        features
    }
}

#[async_trait::async_trait]
impl WireGuardEngine for HybridWireGuard {
    async fn create_interface(&mut self, config: WgConfig) -> Result<WgInterface> {
        let mut interface = self.active_engine.create_interface(config.clone()).await?;
        interface.engine_tier = self.active_tier;

        // Enable QUIC bridge if requested
        if config.enable_quic_bridge {
            let (quic_tx, quic_rx) = mpsc::unbounded_channel();
            self.enable_quic_bridge(&interface, quic_tx, quic_rx).await?;
        }

        Ok(interface)
    }

    async fn send_packet(&mut self, interface: &WgInterface, data: &[u8]) -> Result<()> {
        self.active_engine.send_packet(interface, data).await
    }

    async fn receive_packet(&mut self, interface: &WgInterface) -> Result<Vec<u8>> {
        self.active_engine.receive_packet(interface).await
    }

    async fn add_peer(&mut self, interface: &WgInterface, peer: WgPeer) -> Result<()> {
        self.active_engine.add_peer(interface, peer).await
    }

    async fn remove_peer(&mut self, interface: &WgInterface, public_key: &PublicKey) -> Result<()> {
        self.active_engine.remove_peer(interface, public_key).await
    }

    async fn update_peer_endpoint(
        &mut self,
        interface: &WgInterface,
        public_key: &PublicKey,
        endpoint: SocketAddr,
    ) -> Result<()> {
        self.active_engine.update_peer_endpoint(interface, public_key, endpoint).await
    }

    async fn get_stats(&self, interface: &WgInterface) -> Result<WgStats> {
        let mut stats = self.active_engine.get_stats(interface).await?;

        // Add QUIC bridge stats if available
        if let Some(ref bridge) = self.quic_bridge {
            let bridge_stats = bridge.get_stats().await;
            stats.quic_bytes_relayed = bridge_stats.bytes_bridged;
        }

        Ok(stats)
    }

    fn is_available(&self) -> bool {
        self.active_engine.is_available()
    }

    fn performance_tier(&self) -> PerformanceTier {
        self.active_tier
    }

    async fn send_via_quic(
        &mut self,
        interface: &WgInterface,
        data: &[u8],
        quic_sender: &mut mpsc::UnboundedSender<QuicMessage>,
    ) -> Result<()> {
        if let Some(ref mut bridge) = self.quic_bridge {
            use ghostwire_common::quic::StreamType;
            use ghostwire_common::types::PublicKey;

            // Extract target peer from data (simplified)
            let target_peer = PublicKey::from_bytes([0u8; 32]); // Would extract properly

            bridge.send_wireguard_over_quic(data, target_peer, StreamType::WireGuardData).await
        } else {
            self.active_engine.send_via_quic(interface, data, quic_sender).await
        }
    }

    async fn receive_via_quic(
        &mut self,
        interface: &WgInterface,
        quic_data: &[u8],
    ) -> Result<Vec<u8>> {
        self.active_engine.receive_via_quic(interface, quic_data).await
    }
}

/// Engine information for debugging and monitoring
#[derive(Debug, Clone)]
pub struct EngineInfo {
    pub tier: PerformanceTier,
    pub max_throughput: u64,
    pub features: Vec<String>,
    pub quic_bridge_enabled: bool,
}

impl BoringTunEngine {
    async fn new() -> Result<Self> {
        // Would initialize boringtun wrapper
        Ok(Self {})
    }
}

#[async_trait::async_trait]
impl WireGuardEngine for BoringTunEngine {
    async fn create_interface(&mut self, _config: WgConfig) -> Result<WgInterface> {
        // Would implement boringtun interface creation
        Err(GhostWireError::internal("BoringTun implementation pending"))
    }

    async fn send_packet(&mut self, _interface: &WgInterface, _data: &[u8]) -> Result<()> {
        Err(GhostWireError::internal("BoringTun implementation pending"))
    }

    async fn receive_packet(&mut self, _interface: &WgInterface) -> Result<Vec<u8>> {
        Err(GhostWireError::internal("BoringTun implementation pending"))
    }

    async fn add_peer(&mut self, _interface: &WgInterface, _peer: WgPeer) -> Result<()> {
        Err(GhostWireError::internal("BoringTun implementation pending"))
    }

    async fn remove_peer(&mut self, _interface: &WgInterface, _public_key: &PublicKey) -> Result<()> {
        Err(GhostWireError::internal("BoringTun implementation pending"))
    }

    async fn update_peer_endpoint(
        &mut self,
        _interface: &WgInterface,
        _public_key: &PublicKey,
        _endpoint: SocketAddr,
    ) -> Result<()> {
        Err(GhostWireError::internal("BoringTun implementation pending"))
    }

    async fn get_stats(&self, _interface: &WgInterface) -> Result<WgStats> {
        Ok(WgStats::default())
    }

    fn is_available(&self) -> bool {
        true // boringtun should always be available
    }

    fn performance_tier(&self) -> PerformanceTier {
        PerformanceTier::Compatibility
    }

    async fn send_via_quic(
        &mut self,
        _interface: &WgInterface,
        _data: &[u8],
        _quic_sender: &mut mpsc::UnboundedSender<QuicMessage>,
    ) -> Result<()> {
        Err(GhostWireError::internal("QUIC not supported in compatibility mode"))
    }

    async fn receive_via_quic(
        &mut self,
        _interface: &WgInterface,
        _quic_data: &[u8],
    ) -> Result<Vec<u8>> {
        Err(GhostWireError::internal("QUIC not supported in compatibility mode"))
    }
}

impl Clone for BoringTunEngine {
    fn clone(&self) -> Self {
        Self {}
    }
}