/// Dashboard and visualization for GhostWire observability
///
/// Provides web-based dashboards for monitoring metrics, alerts, and system health.

use std::collections::HashMap;
use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Json},
    routing::get,
    Router,
};
use serde::{Deserialize, Serialize};
use anyhow::Result;

use crate::{GhostWireMetrics, HealthChecker, alerts::AlertManager};

#[derive(Clone)]
pub struct DashboardState {
    metrics: Arc<GhostWireMetrics>,
    health_checker: Arc<tokio::sync::RwLock<HealthChecker>>,
    alert_manager: Option<Arc<AlertManager>>,
}

pub fn create_dashboard_router(
    metrics: Arc<GhostWireMetrics>,
    health_checker: Arc<tokio::sync::RwLock<HealthChecker>>,
    alert_manager: Option<Arc<AlertManager>>,
) -> Router {
    let state = DashboardState {
        metrics,
        health_checker,
        alert_manager,
    };

    Router::new()
        .route("/", get(dashboard_index))
        .route("/api/metrics/summary", get(metrics_summary))
        .route("/api/health", get(health_status))
        .route("/api/alerts", get(alerts_list))
        .route("/api/system", get(system_info))
        .route("/dashboard/:view", get(dashboard_view))
        .with_state(state)
}

/// Main dashboard page
async fn dashboard_index() -> impl IntoResponse {
    Html(include_str!("templates/dashboard.html"))
}

/// Specific dashboard view
async fn dashboard_view(Path(view): Path<String>) -> impl IntoResponse {
    match view.as_str() {
        "metrics" => Html(include_str!("templates/metrics.html")),
        "alerts" => Html(include_str!("templates/alerts.html")),
        "health" => Html(include_str!("templates/health.html")),
        "network" => Html(include_str!("templates/network.html")),
        _ => (StatusCode::NOT_FOUND, Html("<h1>Dashboard view not found</h1>")),
    }
}

/// Metrics summary API endpoint
async fn metrics_summary(
    State(state): State<DashboardState>,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let time_range = params.get("range").unwrap_or(&"1h".to_string()).clone();

    let summary = MetricsSummary {
        uptime_seconds: state.metrics.uptime_seconds(),
        time_range,
        connections: ConnectionMetrics {
            total: 156, // Mock data
            active: 42,
            failed: 3,
            average_latency_ms: 45.2,
        },
        network: NetworkMetrics {
            bytes_sent: 1024 * 1024 * 512,    // 512 MB
            bytes_received: 1024 * 1024 * 256, // 256 MB
            packets_sent: 125000,
            packets_received: 230000,
        },
        system: SystemMetrics {
            cpu_usage_percent: 23.5,
            memory_usage_percent: 67.2,
            disk_usage_percent: 45.8,
            load_average: 1.2,
        },
        derp: DerpMetrics {
            regions_active: 3,
            total_relayed_bytes: 1024 * 1024 * 128, // 128 MB
            average_latency_ms: 67.3,
        },
    };

    Json(summary)
}

/// Health status API endpoint
async fn health_status(State(state): State<DashboardState>) -> impl IntoResponse {
    let health_checker = state.health_checker.read().await;
    let status = health_checker.status();
    let summary = health_checker.summary();

    let response = HealthResponse {
        overall_status: summary.overall_status,
        total_checks: summary.total_checks,
        healthy_checks: summary.healthy_checks,
        degraded_checks: summary.degraded_checks,
        unhealthy_checks: summary.unhealthy_checks,
        last_updated: summary.last_updated,
        system_info: status.system_info.clone(),
        checks: health_checker
            .all_checks()
            .iter()
            .map(|(name, check)| CheckStatus {
                name: name.clone(),
                status: check.status.clone(),
                last_run: check.last_run,
                consecutive_failures: check.consecutive_failures,
                last_error: check.last_error.clone(),
            })
            .collect(),
    };

    Json(response)
}

/// Alerts list API endpoint
async fn alerts_list(State(state): State<DashboardState>) -> impl IntoResponse {
    if let Some(alert_manager) = &state.alert_manager {
        let active_alerts = alert_manager.get_active_alerts().await;
        let alert_stats = alert_manager.get_alert_stats().await;

        let response = AlertsResponse {
            stats: alert_stats,
            active_alerts,
        };

        Json(response)
    } else {
        Json(AlertsResponse {
            stats: crate::alerts::AlertStats {
                total_alerts: 0,
                firing_alerts: 0,
                resolved_alerts: 0,
                silenced_alerts: 0,
                critical_alerts: 0,
            },
            active_alerts: vec![],
        })
    }
}

/// System information API endpoint
async fn system_info(State(state): State<DashboardState>) -> impl IntoResponse {
    let health_checker = state.health_checker.read().await;
    let system_info = &health_checker.status().system_info;

    let response = SystemInfoResponse {
        hostname: system_info.hostname.clone(),
        os: system_info.os.clone(),
        arch: system_info.arch.clone(),
        cpu_cores: system_info.cpu_cores,
        total_memory: system_info.total_memory,
        used_memory: system_info.used_memory,
        uptime: system_info.uptime,
        version: system_info.version.clone(),
        service_uptime: state.metrics.uptime_seconds(),
    };

    Json(response)
}

#[derive(Debug, Serialize)]
struct MetricsSummary {
    uptime_seconds: f64,
    time_range: String,
    connections: ConnectionMetrics,
    network: NetworkMetrics,
    system: SystemMetrics,
    derp: DerpMetrics,
}

#[derive(Debug, Serialize)]
struct ConnectionMetrics {
    total: u64,
    active: u64,
    failed: u64,
    average_latency_ms: f64,
}

#[derive(Debug, Serialize)]
struct NetworkMetrics {
    bytes_sent: u64,
    bytes_received: u64,
    packets_sent: u64,
    packets_received: u64,
}

#[derive(Debug, Serialize)]
struct SystemMetrics {
    cpu_usage_percent: f64,
    memory_usage_percent: f64,
    disk_usage_percent: f64,
    load_average: f64,
}

#[derive(Debug, Serialize)]
struct DerpMetrics {
    regions_active: u32,
    total_relayed_bytes: u64,
    average_latency_ms: f64,
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    overall_status: crate::health::HealthStatus,
    total_checks: usize,
    healthy_checks: usize,
    degraded_checks: usize,
    unhealthy_checks: usize,
    last_updated: std::time::SystemTime,
    system_info: crate::health::SystemInfo,
    checks: Vec<CheckStatus>,
}

#[derive(Debug, Serialize)]
struct CheckStatus {
    name: String,
    status: crate::health::HealthStatus,
    last_run: Option<std::time::SystemTime>,
    consecutive_failures: u32,
    last_error: Option<String>,
}

#[derive(Debug, Serialize)]
struct AlertsResponse {
    stats: crate::alerts::AlertStats,
    active_alerts: Vec<crate::alerts::Alert>,
}

#[derive(Debug, Serialize)]
struct SystemInfoResponse {
    hostname: String,
    os: String,
    arch: String,
    cpu_cores: usize,
    total_memory: u64,
    used_memory: u64,
    uptime: std::time::Duration,
    version: String,
    service_uptime: f64,
}