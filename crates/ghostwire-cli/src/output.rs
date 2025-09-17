/// Output formatting and display utilities for gwctl
///
/// Provides consistent formatting across all gwctl commands with support
/// for multiple output formats (table, JSON, YAML) and styling.

use anyhow::Result;
use clap::ValueEnum;
use colored::{ColoredString, Colorize};
use serde::{Deserialize, Serialize};
use std::fmt;
use tabled::{Table, Tabled, settings::{Style, Alignment, Modify, object::{Rows, Columns}}};

#[derive(ValueEnum, Clone, Debug, Serialize, Deserialize)]
pub enum OutputFormat {
    /// Human-readable table format
    Table,
    /// JSON format
    Json,
    /// YAML format
    Yaml,
    /// Compact single-line format
    Compact,
}

impl fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OutputFormat::Table => write!(f, "table"),
            OutputFormat::Json => write!(f, "json"),
            OutputFormat::Yaml => write!(f, "yaml"),
            OutputFormat::Compact => write!(f, "compact"),
        }
    }
}

/// Output configuration
pub struct OutputConfig {
    pub format: OutputFormat,
    pub color: bool,
    pub timestamps: bool,
}

/// Trait for types that can be formatted for output
pub trait Displayable {
    fn to_table(&self) -> Result<Table>;
    fn to_json(&self) -> Result<String>;
    fn to_yaml(&self) -> Result<String>;
    fn to_compact(&self) -> Result<String>;
}

/// Display data with the specified format
pub fn display<T: Displayable>(data: &T, config: &OutputConfig) -> Result<()> {
    let output = match config.format {
        OutputFormat::Table => {
            let mut table = data.to_table()?;
            style_table(&mut table, config.color);
            table.to_string()
        }
        OutputFormat::Json => data.to_json()?,
        OutputFormat::Yaml => data.to_yaml()?,
        OutputFormat::Compact => data.to_compact()?,
    };

    println!("{}", output);
    Ok(())
}

/// Display a list of items
pub fn display_list<T: Displayable>(items: &[T], config: &OutputConfig) -> Result<()> {
    match config.format {
        OutputFormat::Table => {
            if items.is_empty() {
                println!("{}", "No items found".dimmed());
                return Ok(());
            }

            // For table format, we need to combine all items into one table
            // This is a simplified approach - real implementation would be more sophisticated
            for item in items {
                display(item, config)?;
            }
        }
        OutputFormat::Json => {
            let json_items: Vec<serde_json::Value> = items
                .iter()
                .map(|item| serde_json::from_str(&item.to_json().unwrap()).unwrap())
                .collect();
            println!("{}", serde_json::to_string_pretty(&json_items)?);
        }
        OutputFormat::Yaml => {
            let yaml_items: Vec<serde_yaml::Value> = items
                .iter()
                .map(|item| serde_yaml::from_str(&item.to_yaml().unwrap()).unwrap())
                .collect();
            println!("{}", serde_yaml::to_string(&yaml_items)?);
        }
        OutputFormat::Compact => {
            for item in items {
                println!("{}", item.to_compact()?);
            }
        }
    }

    Ok(())
}

/// Style table for better appearance
fn style_table(table: &mut Table, color: bool) {
    table
        .with(Style::rounded())
        .with(Modify::new(Rows::first()).with(Alignment::center()));

    if !color {
        // Remove any coloring if color is disabled
        // This would need more sophisticated implementation
    }
}

/// Status display with color coding
#[derive(Debug, Clone)]
pub enum Status {
    Online,
    Offline,
    Unknown,
    Warning,
    Error,
    Pending,
}

impl Status {
    pub fn colored(&self, enable_color: bool) -> ColoredString {
        let text = format!("{:?}", self).to_uppercase();
        if !enable_color {
            return text.into();
        }

        match self {
            Status::Online => text.green(),
            Status::Offline => text.red(),
            Status::Unknown => text.yellow(),
            Status::Warning => text.yellow(),
            Status::Error => text.red().bold(),
            Status::Pending => text.blue(),
        }
    }
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.colored(true))
    }
}

/// Format bytes in human readable format
pub fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut unit_index = 0;

    while value >= 1024.0 && unit_index < UNITS.len() - 1 {
        value /= 1024.0;
        unit_index += 1;
    }

    if unit_index == 0 {
        format!("{} {}", bytes, UNITS[unit_index])
    } else {
        format!("{:.1} {}", value, UNITS[unit_index])
    }
}

/// Format duration in human readable format
pub fn format_duration(duration: std::time::Duration) -> String {
    let seconds = duration.as_secs();

    if seconds < 60 {
        format!("{}s", seconds)
    } else if seconds < 3600 {
        format!("{}m {}s", seconds / 60, seconds % 60)
    } else if seconds < 86400 {
        let hours = seconds / 3600;
        let minutes = (seconds % 3600) / 60;
        format!("{}h {}m", hours, minutes)
    } else {
        let days = seconds / 86400;
        let hours = (seconds % 86400) / 3600;
        format!("{}d {}h", days, hours)
    }
}

/// Format timestamp for display
pub fn format_timestamp(timestamp: chrono::DateTime<chrono::Utc>, show_relative: bool) -> String {
    if show_relative {
        let now = chrono::Utc::now();
        let diff = now.signed_duration_since(timestamp);

        if diff.num_seconds() < 60 {
            "just now".to_string()
        } else if diff.num_minutes() < 60 {
            format!("{}m ago", diff.num_minutes())
        } else if diff.num_hours() < 24 {
            format!("{}h ago", diff.num_hours())
        } else {
            format!("{}d ago", diff.num_days())
        }
    } else {
        timestamp.format("%Y-%m-%d %H:%M:%S UTC").to_string()
    }
}

/// Progress indicator for long-running operations
pub struct ProgressIndicator {
    spinner: indicatif::ProgressBar,
}

impl ProgressIndicator {
    pub fn new(message: &str) -> Self {
        let spinner = indicatif::ProgressBar::new_spinner();
        spinner.set_style(
            indicatif::ProgressStyle::default_spinner()
                .template("{spinner:.green} {msg}")
                .unwrap()
        );
        spinner.set_message(message.to_string());
        spinner.enable_steady_tick(std::time::Duration::from_millis(120));

        Self { spinner }
    }

    pub fn set_message(&self, message: &str) {
        self.spinner.set_message(message.to_string());
    }

    pub fn finish_with_message(&self, message: &str) {
        self.spinner.finish_with_message(message.to_string());
    }

    pub fn finish(&self) {
        self.spinner.finish_and_clear();
    }
}

/// Success/error message formatting
pub fn success(message: &str, color: bool) -> String {
    if color {
        format!("{} {}", "✅".green(), message)
    } else {
        format!("✅ {}", message)
    }
}

pub fn error(message: &str, color: bool) -> String {
    if color {
        format!("{} {}", "❌".red(), message.red())
    } else {
        format!("❌ {}", message)
    }
}

pub fn warning(message: &str, color: bool) -> String {
    if color {
        format!("{} {}", "⚠️".yellow(), message.yellow())
    } else {
        format!("⚠️ {}", message)
    }
}

pub fn info(message: &str, color: bool) -> String {
    if color {
        format!("{} {}", "ℹ️".blue(), message)
    } else {
        format!("ℹ️ {}", message)
    }
}

/// Example structures for demonstration

#[derive(Tabled, Serialize, Deserialize)]
pub struct NodeInfo {
    #[tabled(rename = "ID")]
    pub id: String,

    #[tabled(rename = "Name")]
    pub name: String,

    #[tabled(rename = "IP Address")]
    pub ip: String,

    #[tabled(rename = "Status")]
    pub status: String,

    #[tabled(rename = "Last Seen")]
    pub last_seen: String,

    #[tabled(rename = "Version")]
    pub version: String,
}

impl Displayable for NodeInfo {
    fn to_table(&self) -> Result<Table> {
        Ok(Table::new([self.clone()]))
    }

    fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    fn to_yaml(&self) -> Result<String> {
        Ok(serde_yaml::to_string(self)?)
    }

    fn to_compact(&self) -> Result<String> {
        Ok(format!("{} {} {} {}", self.id, self.name, self.ip, self.status))
    }
}

#[derive(Tabled, Serialize, Deserialize)]
pub struct ServerInfo {
    #[tabled(rename = "Component")]
    pub component: String,

    #[tabled(rename = "Status")]
    pub status: String,

    #[tabled(rename = "Version")]
    pub version: String,

    #[tabled(rename = "Uptime")]
    pub uptime: String,

    #[tabled(rename = "Memory")]
    pub memory: String,
}

impl Displayable for ServerInfo {
    fn to_table(&self) -> Result<Table> {
        Ok(Table::new([self.clone()]))
    }

    fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    fn to_yaml(&self) -> Result<String> {
        Ok(serde_yaml::to_string(self)?)
    }

    fn to_compact(&self) -> Result<String> {
        Ok(format!("{}: {} ({})", self.component, self.status, self.version))
    }
}

/// Create a simple two-column table for key-value data
pub fn create_kv_table(data: &[(String, String)], color: bool) -> Table {
    let mut table = Table::new(data.iter().map(|(k, v)| (k.clone(), v.clone())).collect::<Vec<_>>());

    table
        .with(Style::rounded())
        .with(Modify::new(Columns::first()).with(Alignment::right()));

    if !color {
        // Remove coloring
    }

    table
}

/// Display help text with proper formatting
pub fn display_help(title: &str, content: &str, color: bool) {
    if color {
        println!("{}", title.bold().underline());
    } else {
        println!("{}", title);
    }
    println!();
    println!("{}", content);
}

/// Additional output types for CLI commands

#[derive(Tabled, Serialize, Deserialize)]
pub struct DerpRelayInfo {
    #[tabled(rename = "ID")]
    pub id: String,

    #[tabled(rename = "Region")]
    pub region: String,

    #[tabled(rename = "Hostname")]
    pub hostname: String,

    #[tabled(rename = "IPv4")]
    pub ipv4: String,

    #[tabled(rename = "IPv6")]
    pub ipv6: String,

    #[tabled(rename = "Port")]
    pub port: String,

    #[tabled(rename = "Status")]
    pub status: String,

    #[tabled(rename = "Latency")]
    pub latency: String,
}

#[derive(Tabled, Serialize, Deserialize)]
pub struct DnsRecordInfo {
    #[tabled(rename = "Name")]
    pub name: String,

    #[tabled(rename = "Type")]
    pub record_type: String,

    #[tabled(rename = "Value")]
    pub value: String,

    #[tabled(rename = "TTL")]
    pub ttl: String,

    #[tabled(rename = "Node")]
    pub node: String,
}

#[derive(Tabled, Serialize, Deserialize)]
pub struct UserInfo {
    #[tabled(rename = "ID")]
    pub id: String,

    #[tabled(rename = "Username")]
    pub username: String,

    #[tabled(rename = "Email")]
    pub email: String,

    #[tabled(rename = "Role")]
    pub role: String,

    #[tabled(rename = "Active")]
    pub active: String,

    #[tabled(rename = "Created")]
    pub created_at: String,

    #[tabled(rename = "Last Login")]
    pub last_login: String,
}

#[derive(Tabled, Serialize, Deserialize)]
pub struct ApiKeyInfo {
    #[tabled(rename = "ID")]
    pub id: String,

    #[tabled(rename = "Name")]
    pub name: String,

    #[tabled(rename = "User")]
    pub user: String,

    #[tabled(rename = "Scopes")]
    pub scopes: String,

    #[tabled(rename = "Created")]
    pub created: String,

    #[tabled(rename = "Expires")]
    pub expires: String,

    #[tabled(rename = "Last Used")]
    pub last_used: String,

    #[tabled(rename = "Active")]
    pub active: String,
}

#[derive(Tabled, Serialize, Deserialize)]
pub struct RouteInfo {
    #[tabled(rename = "ID")]
    pub id: String,

    #[tabled(rename = "Destination")]
    pub destination: String,

    #[tabled(rename = "Node")]
    pub node: String,

    #[tabled(rename = "Metric")]
    pub metric: String,

    #[tabled(rename = "Enabled")]
    pub enabled: String,

    #[tabled(rename = "Advertised")]
    pub advertised: String,

    #[tabled(rename = "Created")]
    pub created: String,
}

#[derive(Tabled, Serialize, Deserialize)]
pub struct MetricInfo {
    #[tabled(rename = "Name")]
    pub name: String,

    #[tabled(rename = "Value")]
    pub value: String,

    #[tabled(rename = "Unit")]
    pub unit: String,

    #[tabled(rename = "Node")]
    pub node: String,

    #[tabled(rename = "Timestamp")]
    pub timestamp: String,
}