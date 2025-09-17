/// REST API server implementation for GhostWire coordination
///
/// Provides HTTP/JSON endpoints for:
/// - Administrative operations and management
/// - Web dashboard integration
/// - CLI tool integration
/// - Status and health monitoring

use std::{net::SocketAddr, sync::Arc};
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::Json,
    routing::{get, post, delete, put},
    Router,
};
use serde::{Deserialize, Serialize};
use tracing::{info, warn, error, debug};
use tower::ServiceBuilder;
use tower_http::{
    cors::CorsLayer,
    compression::CompressionLayer,
    trace::TraceLayer,
    timeout::TimeoutLayer,
};
use std::time::Duration;

use crate::coordinator::Coordinator;
use ghostwire_common::{
    types::*,
    error::{Result, GhostWireError},
};

/// REST API service
pub struct RestApiService {
    coordinator: Arc<Coordinator>,
}

impl RestApiService {
    pub fn new(coordinator: Arc<Coordinator>) -> Self {
        Self { coordinator }
    }

    /// Extract API key from headers
    fn extract_api_key(&self, headers: &HeaderMap) -> Result<Option<String>> {
        Ok(headers
            .get("x-api-key")
            .and_then(|value| value.to_str().ok())
            .map(|key| key.to_string()))
    }

    /// Extract bearer token from authorization header
    fn extract_bearer_token(&self, headers: &HeaderMap) -> Result<Option<String>> {
        Ok(headers
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .and_then(|auth| auth.strip_prefix("Bearer "))
            .map(|token| token.to_string()))
    }
}

/// API state shared across handlers
#[derive(Clone)]
pub struct ApiState {
    coordinator: Arc<Coordinator>,
}

/// Node information for REST responses
#[derive(Serialize, Deserialize)]
pub struct NodeInfo {
    pub id: String,
    pub name: String,
    pub user_id: String,
    pub ipv4: String,
    pub ipv6: Option<String>,
    pub online: bool,
    pub created_at: String,
    pub last_seen: String,
    pub expires_at: Option<String>,
    pub endpoints: Vec<EndpointInfo>,
    pub routes: Vec<RouteInfo>,
    pub tags: Vec<String>,
}

#[derive(Serialize, Deserialize)]
pub struct EndpointInfo {
    pub addr: String,
    pub endpoint_type: String,
    pub preference: u32,
}

#[derive(Serialize, Deserialize)]
pub struct RouteInfo {
    pub id: String,
    pub prefix: String,
    pub advertised: bool,
    pub enabled: bool,
    pub is_primary: bool,
}

/// User information for REST responses
#[derive(Serialize, Deserialize)]
pub struct UserInfo {
    pub id: String,
    pub name: String,
    pub email: Option<String>,
    pub created_at: String,
    pub node_count: usize,
}

/// Network statistics
#[derive(Serialize, Deserialize)]
pub struct NetworkStats {
    pub total_nodes: usize,
    pub online_nodes: usize,
    pub total_users: usize,
    pub total_routes: usize,
    pub version: u64,
}

/// Error response format
#[derive(Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub code: String,
    pub details: Option<String>,
}

/// Success response format
#[derive(Serialize)]
pub struct SuccessResponse<T> {
    pub success: bool,
    pub data: T,
}

/// Pagination parameters
#[derive(Deserialize)]
pub struct PaginationQuery {
    pub page: Option<u32>,
    pub per_page: Option<u32>,
}

/// Node filter parameters
#[derive(Deserialize)]
pub struct NodeFilter {
    pub user_id: Option<String>,
    pub online: Option<bool>,
    pub tag: Option<String>,
}

// API Handlers

/// Get server health status
async fn health_handler() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "healthy",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "version": env!("CARGO_PKG_VERSION")
    }))
}

/// Get network statistics
async fn stats_handler(State(state): State<ApiState>) -> Result<Json<NetworkStats>, StatusCode> {
    // TODO: Implement stats collection from coordinator
    let stats = NetworkStats {
        total_nodes: 0,
        online_nodes: 0,
        total_users: 0,
        total_routes: 0,
        version: 1,
    };

    Ok(Json(stats))
}

/// List all nodes with filtering and pagination
async fn list_nodes_handler(
    State(state): State<ApiState>,
    Query(filter): Query<NodeFilter>,
    Query(pagination): Query<PaginationQuery>,
    headers: HeaderMap,
) -> Result<Json<SuccessResponse<Vec<NodeInfo>>>, StatusCode> {
    // TODO: Implement authentication check

    // TODO: Get nodes from coordinator with filtering
    let nodes = vec![];

    Ok(Json(SuccessResponse {
        success: true,
        data: nodes,
    }))
}

/// Get specific node details
async fn get_node_handler(
    State(state): State<ApiState>,
    Path(node_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<NodeInfo>, StatusCode> {
    let node_id = NodeId::parse(&node_id)
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    // TODO: Get node from coordinator

    Err(StatusCode::NOT_FOUND)
}

/// Delete a node
async fn delete_node_handler(
    State(state): State<ApiState>,
    Path(node_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<SuccessResponse<()>>, StatusCode> {
    let node_id = NodeId::parse(&node_id)
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    // TODO: Authenticate admin user

    match state.coordinator.unregister_node(&node_id).await {
        Ok(()) => Ok(Json(SuccessResponse {
            success: true,
            data: (),
        })),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

/// List all users
async fn list_users_handler(
    State(state): State<ApiState>,
    Query(pagination): Query<PaginationQuery>,
    headers: HeaderMap,
) -> Result<Json<SuccessResponse<Vec<UserInfo>>>, StatusCode> {
    // TODO: Implement authentication check

    // TODO: Get users from database
    let users = vec![];

    Ok(Json(SuccessResponse {
        success: true,
        data: users,
    }))
}

/// Create a new user
#[derive(Deserialize)]
pub struct CreateUserRequest {
    pub name: String,
    pub email: Option<String>,
}

async fn create_user_handler(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(req): Json<CreateUserRequest>,
) -> Result<Json<SuccessResponse<UserInfo>>, StatusCode> {
    // TODO: Implement authentication check

    // TODO: Create user via database operations

    Err(StatusCode::NOT_IMPLEMENTED)
}

/// Get specific user details
async fn get_user_handler(
    State(state): State<ApiState>,
    Path(user_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<UserInfo>, StatusCode> {
    let user_id = UserId::parse(&user_id)
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    // TODO: Get user from database

    Err(StatusCode::NOT_FOUND)
}

/// Delete a user
async fn delete_user_handler(
    State(state): State<ApiState>,
    Path(user_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<SuccessResponse<()>>, StatusCode> {
    let user_id = UserId::parse(&user_id)
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    // TODO: Authenticate admin user
    // TODO: Delete user via database operations

    Err(StatusCode::NOT_IMPLEMENTED)
}

/// Get network map for a specific node
async fn get_network_map_handler(
    State(state): State<ApiState>,
    Path(node_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let node_id = NodeId::parse(&node_id)
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    // TODO: Validate node authentication

    match state.coordinator.get_network_map(&node_id, None).await {
        Ok((network_map, _)) => {
            // Convert network map to JSON representation
            // TODO: Implement proper serialization
            Ok(Json(serde_json::json!({})))
        }
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

/// Handle authentication middleware
async fn auth_middleware() {
    // TODO: Implement authentication middleware
}

/// Create the REST API router
pub fn create_router(coordinator: Arc<Coordinator>) -> Router {
    let state = ApiState { coordinator };

    Router::new()
        // Health and status endpoints
        .route("/health", get(health_handler))
        .route("/stats", get(stats_handler))

        // Node management endpoints
        .route("/api/v1/nodes", get(list_nodes_handler))
        .route("/api/v1/nodes/:id", get(get_node_handler))
        .route("/api/v1/nodes/:id", delete(delete_node_handler))
        .route("/api/v1/nodes/:id/network-map", get(get_network_map_handler))

        // User management endpoints
        .route("/api/v1/users", get(list_users_handler))
        .route("/api/v1/users", post(create_user_handler))
        .route("/api/v1/users/:id", get(get_user_handler))
        .route("/api/v1/users/:id", delete(delete_user_handler))

        // Add middleware layers
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(CompressionLayer::new())
                .layer(TimeoutLayer::new(Duration::from_secs(30)))
                .layer(CorsLayer::permissive())
        )
        .with_state(state)
}

/// REST server wrapper
pub struct RestServer {
    coordinator: Arc<Coordinator>,
    addr: SocketAddr,
}

impl RestServer {
    pub fn new(coordinator: Arc<Coordinator>, addr: SocketAddr) -> Self {
        Self { coordinator, addr }
    }

    /// Start the REST server
    pub async fn serve(self) -> Result<()> {
        let app = create_router(self.coordinator);

        info!("Starting REST API server on {}", self.addr);

        let listener = tokio::net::TcpListener::bind(self.addr).await
            .map_err(|e| GhostWireError::network(format!("Failed to bind REST server: {}", e)))?;

        axum::serve(listener, app).await
            .map_err(|e| GhostWireError::network(format!("REST server failed: {}", e)))?;

        Ok(())
    }
}