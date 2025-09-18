/// High-performance database layer using zqlite
///
/// This module provides:
/// - Advanced connection management with pooling
/// - Schema management with migrations
/// - Type-safe database models with compression
/// - High-performance CRUD operations optimized for zqlite
/// - Spatial indexing for CIDR operations
/// - Time-series support for metrics
/// - Bitmap indexing for ACL evaluation

pub mod connection;
pub mod zqlite_connection;
pub mod schema;
pub mod migrations;
pub mod models;
pub mod operations;

// Re-export commonly used types - now using ZQLite
pub use zqlite_connection::{ZQLiteDatabaseConnection as DatabaseConnection, ZQLiteTransaction, HealthCheckResult};
pub use models::*;
pub use operations::*;