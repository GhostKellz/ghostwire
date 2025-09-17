/// Distributed tracing integration for GhostWire
///
/// Provides OpenTelemetry integration for distributed tracing across the mesh network.

use anyhow::Result;
use opentelemetry::{global, trace::TracerProvider as _, KeyValue};
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{
    trace::{self, RandomIdGenerator, Sampler, TracerProvider},
    Resource,
};
use tracing::{info, error};
use tracing_opentelemetry::OpenTelemetryLayer;
use tracing_subscriber::{layer::SubscriberExt, Registry};

use crate::TracingConfig;

/// Initialize distributed tracing
pub async fn init_tracing(config: &TracingConfig) -> Result<()> {
    if !config.enabled {
        info!("Distributed tracing is disabled");
        return Ok();
    }

    let endpoint = config.endpoint.as_ref()
        .ok_or_else(|| anyhow::anyhow!("Tracing endpoint is required when tracing is enabled"))?;

    info!("Initializing distributed tracing with endpoint: {}", endpoint);

    // Create resource with service information
    let resource = Resource::new(vec![
        KeyValue::new("service.name", config.service_name.clone()),
        KeyValue::new("service.version", config.service_version.clone()),
        KeyValue::new("service.environment", config.environment.clone()),
        KeyValue::new("service.namespace", "ghostwire"),
    ]);

    // Create OTLP exporter
    let exporter = opentelemetry_otlp::new_exporter()
        .tonic()
        .with_endpoint(endpoint);

    // Create tracer provider
    let tracer_provider = TracerProvider::builder()
        .with_batch_exporter(exporter, trace::runtime::Tokio)
        .with_resource(resource)
        .with_id_generator(RandomIdGenerator::default())
        .with_sampler(Sampler::TraceIdRatioBased(config.sample_rate))
        .build();

    // Set as global provider
    global::set_tracer_provider(tracer_provider.clone())?;

    // Create OpenTelemetry layer
    let tracer = tracer_provider.tracer("ghostwire");
    let telemetry_layer = OpenTelemetryLayer::new(tracer);

    // This would typically be combined with the existing subscriber
    // For now, we just create the layer
    info!("Distributed tracing initialized successfully");

    Ok(())
}

/// Shutdown tracing gracefully
pub async fn shutdown_tracing() {
    info!("Shutting down distributed tracing");
    global::shutdown_tracer_provider();
}

/// Create a custom span for network operations
#[macro_export]
macro_rules! trace_network_operation {
    ($operation:expr, $source:expr, $destination:expr, $protocol:expr) => {
        tracing::info_span!(
            "network_operation",
            operation = $operation,
            source = $source,
            destination = $destination,
            protocol = $protocol,
            otel.kind = "client"
        )
    };
}

/// Create a custom span for authentication operations
#[macro_export]
macro_rules! trace_auth_operation {
    ($operation:expr, $user:expr, $method:expr) => {
        tracing::info_span!(
            "auth_operation",
            operation = $operation,
            user = $user,
            method = $method,
            otel.kind = "server"
        )
    };
}

/// Create a custom span for DERP relay operations
#[macro_export]
macro_rules! trace_derp_operation {
    ($operation:expr, $region:expr, $relay:expr) => {
        tracing::info_span!(
            "derp_operation",
            operation = $operation,
            region = $region,
            relay = $relay,
            component = "derp",
            otel.kind = "internal"
        )
    };
}

/// Instrument a function with tracing
pub fn trace_function<F, R>(name: &str, f: F) -> R
where
    F: FnOnce() -> R,
{
    let span = tracing::info_span!("function", name = name);
    let _enter = span.enter();
    f()
}

/// Instrument an async function with tracing
pub async fn trace_async_function<F, R>(name: &str, f: F) -> R
where
    F: std::future::Future<Output = R>,
{
    let span = tracing::info_span!("async_function", name = name);
    tracing::Instrument::instrument(f, span).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn test_tracing_disabled() {
        let config = TracingConfig {
            enabled: false,
            endpoint: None,
            service_name: "test".to_string(),
            service_version: "1.0.0".to_string(),
            environment: "test".to_string(),
            sample_rate: 1.0,
        };

        let result = init_tracing(&config).await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_trace_function() {
        let result = trace_function("test_function", || {
            42
        });
        assert_eq!(result, 42);
    }

    #[tokio::test]
    async fn test_trace_async_function() {
        let result = trace_async_function("test_async", async {
            tokio::time::sleep(Duration::from_millis(1)).await;
            "done"
        }).await;
        assert_eq!(result, "done");
    }
}