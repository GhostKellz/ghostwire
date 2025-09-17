/// Metrics exporter for GhostWire observability
///
/// Provides HTTP endpoints for Prometheus scraping and push gateway integration.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use tower::ServiceBuilder;
use tower_http::{trace::TraceLayer, cors::CorsLayer};
use anyhow::Result;
use tracing::{info, error};

use crate::{GhostWireMetrics, MetricsConfig};

#[derive(Clone)]
pub struct MetricsExporter {
    config: MetricsConfig,
    metrics: Arc<GhostWireMetrics>,
}

impl MetricsExporter {
    /// Create a new metrics exporter
    pub async fn new(config: MetricsConfig, metrics: Arc<GhostWireMetrics>) -> Result<Self> {
        Ok(Self { config, metrics })
    }

    /// Start the metrics HTTP server
    pub async fn start(&self) -> Result<()> {
        let app = self.create_app();

        info!("Starting metrics server on {}", self.config.listen_addr);

        let listener = tokio::net::TcpListener::bind(self.config.listen_addr).await?;

        axum::serve(listener, app)
            .await
            .map_err(|e| anyhow::anyhow!("Metrics server error: {}", e))?;

        Ok(())
    }

    fn create_app(&self) -> Router {
        let state = AppState {
            metrics: self.metrics.clone(),
        };

        Router::new()
            .route("/metrics", get(metrics_handler))
            .route("/health", get(health_handler))
            .route("/ready", get(ready_handler))
            .route("/", get(index_handler))
            .layer(
                ServiceBuilder::new()
                    .layer(TraceLayer::new_for_http())
                    .layer(CorsLayer::permissive())
                    .into_inner(),
            )
            .with_state(state)
    }
}

#[derive(Clone)]
struct AppState {
    metrics: Arc<GhostWireMetrics>,
}

/// Prometheus metrics endpoint
async fn metrics_handler(State(state): State<AppState>) -> impl IntoResponse {
    match state.metrics.export() {
        Ok(metrics) => (StatusCode::OK, metrics),
        Err(e) => {
            error!("Failed to export metrics: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Failed to export metrics".to_string())
        }
    }
}

/// Health check endpoint
async fn health_handler() -> impl IntoResponse {
    (StatusCode::OK, "OK")
}

/// Readiness check endpoint
async fn ready_handler() -> impl IntoResponse {
    (StatusCode::OK, "Ready")
}

/// Index page with basic information
async fn index_handler(State(state): State<AppState>) -> impl IntoResponse {
    let uptime = state.metrics.uptime_seconds();
    let content = format!(
        r#"
<!DOCTYPE html>
<html>
<head>
    <title>GhostWire Metrics</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 40px; }}
        .header {{ border-bottom: 1px solid #eee; padding-bottom: 20px; margin-bottom: 20px; }}
        .metric {{ margin: 10px 0; }}
        .value {{ font-weight: bold; color: #2563eb; }}
        .endpoints {{ margin-top: 30px; }}
        .endpoint {{ margin: 5px 0; }}
        a {{ color: #2563eb; text-decoration: none; }}
        a:hover {{ text-decoration: underline; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔗 GhostWire Metrics Server</h1>
        <p>Prometheus-compatible metrics for GhostWire mesh VPN</p>
    </div>

    <div class="metrics">
        <h2>System Status</h2>
        <div class="metric">Uptime: <span class="value">{:.1} hours</span></div>
        <div class="metric">Version: <span class="value">{}</span></div>
        <div class="metric">Service: <span class="value">GhostWire Observability</span></div>
    </div>

    <div class="endpoints">
        <h2>Available Endpoints</h2>
        <div class="endpoint">📊 <a href="/metrics">/metrics</a> - Prometheus metrics</div>
        <div class="endpoint">❤️ <a href="/health">/health</a> - Health check</div>
        <div class="endpoint">✅ <a href="/ready">/ready</a> - Readiness check</div>
    </div>

    <div style="margin-top: 30px; font-size: 0.9em; color: #666;">
        <p>For more information about GhostWire, visit the <a href="https://github.com/ghostkellz/ghostwire">GitHub repository</a>.</p>
    </div>
</body>
</html>
        "#,
        uptime / 3600.0,
        env!("CARGO_PKG_VERSION")
    );

    (StatusCode::OK, [("content-type", "text/html")], content)
}

/// Push metrics to a push gateway
pub async fn push_to_gateway(
    gateway_url: &str,
    job_name: &str,
    instance: &str,
    metrics: &str,
) -> Result<()> {
    let client = reqwest::Client::new();
    let url = format!("{}/metrics/job/{}/instance/{}", gateway_url, job_name, instance);

    let response = client
        .post(&url)
        .header("Content-Type", "text/plain")
        .body(metrics.to_string())
        .send()
        .await?;

    if response.status().is_success() {
        info!("Successfully pushed metrics to gateway");
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "Failed to push metrics: {}",
            response.status()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MetricsConfig;

    #[tokio::test]
    async fn test_exporter_creation() {
        let config = MetricsConfig {
            enabled: true,
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            scrape_interval: Duration::from_secs(15),
            retention: Duration::from_secs(86400),
            push_gateway: None,
            labels: std::collections::HashMap::new(),
        };

        let metrics = Arc::new(GhostWireMetrics::new(&config).unwrap());
        let exporter = MetricsExporter::new(config, metrics).await;
        assert!(exporter.is_ok());
    }
}