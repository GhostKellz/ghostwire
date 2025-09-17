/// API layer for GhostWire coordination server
///
/// Provides both gRPC and REST endpoints for:
/// - Node registration and management
/// - Heartbeat processing
/// - Network map distribution
/// - Administrative operations
///
/// ## Architecture
///
/// ```
/// ┌─────────────────┐    ┌─────────────────┐
/// │   gRPC Server   │    │   REST Server   │
/// │   (Port 8080)   │    │   (Port 8081)   │
/// └─────────┬───────┘    └─────────┬───────┘
///           │                      │
///           └──────────┬───────────┘
///                      │
///              ┌───────▼──────┐
///              │ API Handlers │
///              └───────┬──────┘
///                      │
///              ┌───────▼──────┐
///              │ Coordinator  │
///              └──────────────┘
/// ```

pub mod grpc;
pub mod rest;
pub mod handlers;
pub mod middleware;
pub mod types;

// Re-export key types and structs for external use
pub use grpc::{GrpcCoordinationService, GrpcServer};
pub use rest::{RestApiService, RestServer, create_router};
pub use handlers::{RequestValidator, ResponseFormatter, AuthHandler, AuditLogger};
pub use middleware::{AuthContext, AuthLevel, RateLimiter, RateLimitConfig, MetricsCollector};
pub use types::*;

use crate::coordinator::Coordinator;
use ghostwire_common::{
    config::ServerConfig,
    error::Result,
};
use std::sync::Arc;
use tracing::{info, error};

/// API server that hosts both gRPC and REST endpoints
pub struct ApiServer {
    config: Arc<ServerConfig>,
    coordinator: Arc<Coordinator>,
}

impl ApiServer {
    /// Create new API server
    pub fn new(config: Arc<ServerConfig>, coordinator: Arc<Coordinator>) -> Self {
        Self {
            config,
            coordinator,
        }
    }

    /// Start both gRPC and REST servers
    pub async fn start(&self) -> Result<()> {
        info!("Starting API servers");

        // Parse listen addresses
        let grpc_addr = format!("{}:8080", self.extract_host(&self.config.server.listen_addr));
        let rest_addr = format!("{}:8081", self.extract_host(&self.config.server.listen_addr));

        // Start gRPC server
        let grpc_server = grpc::GrpcServer::new(
            self.coordinator.clone(),
            grpc_addr.parse().map_err(|e| {
                ghostwire_common::error::GhostWireError::config(format!("Invalid gRPC address: {}", e))
            })?,
        );

        // Start REST server
        let rest_server = rest::RestServer::new(
            self.coordinator.clone(),
            rest_addr.parse().map_err(|e| {
                ghostwire_common::error::GhostWireError::config(format!("Invalid REST address: {}", e))
            })?,
        );

        // Run both servers concurrently
        let grpc_handle = tokio::spawn(async move {
            if let Err(e) = grpc_server.serve().await {
                error!("gRPC server error: {}", e);
            }
        });

        let rest_handle = tokio::spawn(async move {
            if let Err(e) = rest_server.serve().await {
                error!("REST server error: {}", e);
            }
        });

        info!("API servers started:");
        info!("  gRPC: {}", grpc_addr);
        info!("  REST: {}", rest_addr);

        // Wait for both servers
        tokio::try_join!(grpc_handle, rest_handle)?;

        Ok(())
    }

    /// Extract host from listen address
    fn extract_host(&self, addr: &str) -> &str {
        if let Some(colon_pos) = addr.rfind(':') {
            &addr[..colon_pos]
        } else {
            addr
        }
    }
}