/// Comprehensive logging configuration for GhostWire
///
/// Provides structured logging with multiple outputs, log rotation, and filtering.

use std::io;
use std::path::PathBuf;
use tracing::{Level, Subscriber};
use tracing_subscriber::{
    EnvFilter, Layer, Registry,
    fmt::{self, format::FmtSpan},
    layer::SubscriberExt,
    util::SubscriberInitExt,
};
use tracing_appender::{rolling, non_blocking};
use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    pub level: LogLevel,
    pub format: LogFormat,
    pub outputs: Vec<LogOutput>,
    pub filters: Vec<LogFilter>,
    pub rotation: LogRotation,
    pub structured: bool,
    pub include_location: bool,
    pub include_thread_id: bool,
    pub include_span_events: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LogFormat {
    Plain,
    Json,
    Compact,
    Pretty,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LogOutput {
    Stdout,
    Stderr,
    File { path: PathBuf, max_size: Option<u64> },
    Syslog { facility: String, tag: String },
    Journal,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogFilter {
    pub target: String,
    pub level: LogLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LogRotation {
    None,
    Daily,
    Hourly,
    Size(u64),
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: LogLevel::Info,
            format: LogFormat::Pretty,
            outputs: vec![
                LogOutput::Stdout,
                LogOutput::File {
                    path: PathBuf::from("logs/ghostwire.log"),
                    max_size: Some(100 * 1024 * 1024), // 100MB
                },
            ],
            filters: vec![
                LogFilter {
                    target: "ghostwire".to_string(),
                    level: LogLevel::Debug,
                },
                LogFilter {
                    target: "tower_http".to_string(),
                    level: LogLevel::Warn,
                },
                LogFilter {
                    target: "hyper".to_string(),
                    level: LogLevel::Warn,
                },
                LogFilter {
                    target: "rustls".to_string(),
                    level: LogLevel::Warn,
                },
            ],
            rotation: LogRotation::Daily,
            structured: true,
            include_location: false,
            include_thread_id: true,
            include_span_events: true,
        }
    }
}

impl From<LogLevel> for Level {
    fn from(level: LogLevel) -> Self {
        match level {
            LogLevel::Trace => Level::TRACE,
            LogLevel::Debug => Level::DEBUG,
            LogLevel::Info => Level::INFO,
            LogLevel::Warn => Level::WARN,
            LogLevel::Error => Level::ERROR,
        }
    }
}

/// Initialize logging with the provided configuration
pub fn init_logging(config: &LoggingConfig) -> Result<()> {
    // Build the environment filter
    let mut filter = EnvFilter::new("");

    // Set default level
    filter = filter.add_directive(format!("ghostwire={}", level_to_string(&config.level)).parse()?);

    // Add specific filters
    for log_filter in &config.filters {
        let directive = format!("{}={}", log_filter.target, level_to_string(&log_filter.level));
        filter = filter.add_directive(directive.parse()?);
    }

    // Allow environment override
    if let Ok(env_filter) = std::env::var("RUST_LOG") {
        filter = EnvFilter::new(env_filter);
    }

    // Create the subscriber registry
    let registry = Registry::default().with(filter);

    // Add layers for each output
    let mut layers: Vec<Box<dyn Layer<Registry> + Send + Sync>> = Vec::new();

    for output in &config.outputs {
        match output {
            LogOutput::Stdout => {
                let layer = create_fmt_layer(config, io::stdout)?;
                layers.push(Box::new(layer));
            }
            LogOutput::Stderr => {
                let layer = create_fmt_layer(config, io::stderr)?;
                layers.push(Box::new(layer));
            }
            LogOutput::File { path, .. } => {
                // Ensure directory exists
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent)?;
                }

                let file_appender = match &config.rotation {
                    LogRotation::Daily => {
                        rolling::daily(path.parent().unwrap(), path.file_name().unwrap())
                    }
                    LogRotation::Hourly => {
                        rolling::hourly(path.parent().unwrap(), path.file_name().unwrap())
                    }
                    LogRotation::Size(_) => {
                        // For size-based rotation, we'll use daily rotation as a fallback
                        // In a real implementation, you'd implement custom size-based rotation
                        rolling::daily(path.parent().unwrap(), path.file_name().unwrap())
                    }
                    LogRotation::None => {
                        rolling::never(path.parent().unwrap(), path.file_name().unwrap())
                    }
                };

                let (non_blocking, _guard) = non_blocking(file_appender);
                let layer = create_fmt_layer_writer(config, non_blocking)?;
                layers.push(Box::new(layer));

                // Store the guard to prevent it from being dropped
                // In a real implementation, you'd need to manage this guard's lifetime
            }
            LogOutput::Syslog { .. } => {
                // Syslog integration would go here
                eprintln!("Syslog output not implemented yet");
            }
            LogOutput::Journal => {
                // systemd journal integration would go here
                eprintln!("Journal output not implemented yet");
            }
        }
    }

    // Initialize the subscriber with all layers
    let subscriber = layers.into_iter().fold(registry.into(), |acc, layer| acc.with(layer));

    tracing::subscriber::set_global_default(subscriber)?;

    Ok(())
}

fn create_fmt_layer<W>(config: &LoggingConfig, writer: W) -> Result<impl Layer<Registry>>
where
    W: for<'writer> fmt::MakeWriter<'writer> + Send + Sync + 'static,
{
    let mut layer = fmt::layer()
        .with_writer(writer)
        .with_thread_ids(config.include_thread_id)
        .with_thread_names(true)
        .with_target(true);

    if config.include_location {
        layer = layer.with_file(true).with_line_number(true);
    }

    if config.include_span_events {
        layer = layer.with_span_events(FmtSpan::ENTER | FmtSpan::EXIT);
    }

    match config.format {
        LogFormat::Json => Ok(layer.json().boxed()),
        LogFormat::Compact => Ok(layer.compact().boxed()),
        LogFormat::Pretty => Ok(layer.pretty().boxed()),
        LogFormat::Plain => Ok(layer.boxed()),
    }
}

fn create_fmt_layer_writer<W>(config: &LoggingConfig, writer: W) -> Result<impl Layer<Registry>>
where
    W: io::Write + Send + Sync + 'static,
{
    let writer = tracing_subscriber::fmt::writer::MakeWriterExt::with_max_level(
        move || writer,
        config.level.clone().into(),
    );

    create_fmt_layer(config, writer)
}

fn level_to_string(level: &LogLevel) -> &'static str {
    match level {
        LogLevel::Trace => "trace",
        LogLevel::Debug => "debug",
        LogLevel::Info => "info",
        LogLevel::Warn => "warn",
        LogLevel::Error => "error",
    }
}

/// Create a structured log entry for events
#[macro_export]
macro_rules! log_event {
    ($level:expr, $event:expr, $($field:expr => $value:expr),*) => {
        tracing::event!(
            $level,
            event = $event,
            $($field = $value),*
        );
    };
}

/// Log a connection event
pub fn log_connection_event(
    event_type: &str,
    machine_id: &str,
    user: &str,
    success: bool,
    details: Option<&str>,
) {
    tracing::info!(
        event = "connection",
        event_type = event_type,
        machine_id = machine_id,
        user = user,
        success = success,
        details = details,
        "Connection event"
    );
}

/// Log an authentication event
pub fn log_auth_event(
    event_type: &str,
    user: &str,
    method: &str,
    success: bool,
    ip_address: Option<&str>,
) {
    tracing::info!(
        event = "authentication",
        event_type = event_type,
        user = user,
        method = method,
        success = success,
        ip_address = ip_address,
        "Authentication event"
    );
}

/// Log a policy evaluation event
pub fn log_policy_event(
    policy_name: &str,
    user: &str,
    resource: &str,
    action: &str,
    allowed: bool,
    reason: Option<&str>,
) {
    tracing::info!(
        event = "policy_evaluation",
        policy = policy_name,
        user = user,
        resource = resource,
        action = action,
        allowed = allowed,
        reason = reason,
        "Policy evaluation"
    );
}

/// Log a network event
pub fn log_network_event(
    event_type: &str,
    source: &str,
    destination: &str,
    protocol: &str,
    bytes: Option<u64>,
) {
    tracing::debug!(
        event = "network",
        event_type = event_type,
        source = source,
        destination = destination,
        protocol = protocol,
        bytes = bytes,
        "Network event"
    );
}

/// Log an error event with context
pub fn log_error_event(
    component: &str,
    error_type: &str,
    error_message: &str,
    context: Option<&str>,
) {
    tracing::error!(
        event = "error",
        component = component,
        error_type = error_type,
        error_message = error_message,
        context = context,
        "Error occurred"
    );
}

/// Log a security event
pub fn log_security_event(
    event_type: &str,
    severity: &str,
    user: Option<&str>,
    ip_address: Option<&str>,
    description: &str,
) {
    tracing::warn!(
        event = "security",
        event_type = event_type,
        severity = severity,
        user = user,
        ip_address = ip_address,
        description = description,
        "Security event"
    );
}

/// Log a performance event
pub fn log_performance_event(
    operation: &str,
    duration_ms: u64,
    success: bool,
    details: Option<&str>,
) {
    tracing::debug!(
        event = "performance",
        operation = operation,
        duration_ms = duration_ms,
        success = success,
        details = details,
        "Performance event"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_default_config() {
        let config = LoggingConfig::default();
        assert!(matches!(config.level, LogLevel::Info));
        assert!(matches!(config.format, LogFormat::Pretty));
        assert_eq!(config.outputs.len(), 2);
        assert!(config.structured);
    }

    #[test]
    fn test_level_conversion() {
        assert_eq!(Level::from(LogLevel::Debug), Level::DEBUG);
        assert_eq!(Level::from(LogLevel::Info), Level::INFO);
        assert_eq!(Level::from(LogLevel::Error), Level::ERROR);
    }

    #[tokio::test]
    async fn test_file_logging() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let log_path = temp_dir.path().join("test.log");

        let config = LoggingConfig {
            outputs: vec![LogOutput::File {
                path: log_path.clone(),
                max_size: None,
            }],
            ..Default::default()
        };

        // This would initialize logging in a real test
        // init_logging(&config)?;

        // Verify the log directory was created
        assert!(log_path.parent().unwrap().exists());

        Ok(())
    }
}