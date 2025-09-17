/// Type definitions for the GhostWire desktop client
///
/// Shared data structures and enums used throughout the application.

use std::net::IpAddr;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub enum ConnectionStatus {
    Disconnected,
    Connecting,
    Connected(ConnectionInfo),
    Error(String),
}

#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    pub server_url: String,
    pub connected_at: DateTime<Utc>,
    pub local_ip: IpAddr,
    pub public_key: String,
    pub endpoint: String,
    pub latency: Option<u32>,
}

#[derive(Debug, Clone, Default)]
pub struct NetworkStats {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub connections_active: u32,
    pub last_handshake: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Machine {
    pub id: String,
    pub name: String,
    pub hostname: String,
    pub user: String,
    pub online: bool,
    pub ip_addresses: Vec<IpAddr>,
    pub os: Option<String>,
    pub last_seen: Option<DateTime<Utc>>,
    pub tags: Vec<String>,
    pub routes: Vec<String>,
    pub endpoints: Vec<String>,
    pub relay_node: Option<String>,
    pub direct_connection: bool,
    pub latency: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Route {
    pub destination: String,
    pub gateway: String,
    pub advertiser: String,
    pub enabled: bool,
    pub primary: bool,
}

#[derive(Debug, Clone)]
pub struct TrayState {
    pub visible: bool,
    pub notifications_enabled: bool,
    pub auto_connect: bool,
}

#[derive(Debug, Clone)]
pub enum TrayAction {
    ShowWindow,
    HideWindow,
    Connect,
    Disconnect,
    Quit,
    ToggleNotifications,
}

#[derive(Debug, Clone)]
pub struct NotificationSettings {
    pub enabled: bool,
    pub connection_events: bool,
    pub machine_events: bool,
    pub error_events: bool,
}

#[derive(Debug, Clone)]
pub enum AppEvent {
    ConnectionStatusChanged(ConnectionStatus),
    MachineAdded(Machine),
    MachineRemoved(String),
    MachineUpdated(Machine),
    RouteAdded(Route),
    RouteRemoved(String),
    NetworkStatsUpdated(NetworkStats),
    ShowNotification(String, String),
    TrayAction(TrayAction),
}

// UI-specific types
#[derive(Debug, Clone, PartialEq)]
pub enum Theme {
    Light,
    Dark,
    System,
}

#[derive(Debug, Clone)]
pub struct UIPreferences {
    pub theme: Theme,
    pub show_advanced_features: bool,
    pub minimize_to_tray: bool,
    pub start_minimized: bool,
    pub auto_update_check: bool,
}

impl Default for UIPreferences {
    fn default() -> Self {
        Self {
            theme: Theme::System,
            show_advanced_features: false,
            minimize_to_tray: true,
            start_minimized: false,
            auto_update_check: true,
        }
    }
}

// Connection preferences
#[derive(Debug, Clone)]
pub struct ConnectionPreferences {
    pub auto_connect: bool,
    pub exit_node: Option<String>,
    pub accept_routes: bool,
    pub accept_dns: bool,
    pub use_derp_only: bool,
    pub preferred_derp_region: Option<String>,
}

impl Default for ConnectionPreferences {
    fn default() -> Self {
        Self {
            auto_connect: false,
            exit_node: None,
            accept_routes: true,
            accept_dns: true,
            use_derp_only: false,
            preferred_derp_region: None,
        }
    }
}

impl Machine {
    pub fn status_color(&self) -> egui::Color32 {
        if self.online {
            egui::Color32::from_rgb(34, 197, 94) // Green
        } else {
            egui::Color32::from_rgb(156, 163, 175) // Gray
        }
    }

    pub fn connection_type(&self) -> &str {
        if self.direct_connection {
            "Direct"
        } else if self.relay_node.is_some() {
            "Relay"
        } else {
            "Unknown"
        }
    }

    pub fn primary_ip(&self) -> Option<IpAddr> {
        self.ip_addresses.first().copied()
    }

    pub fn format_last_seen(&self) -> String {
        match self.last_seen {
            Some(time) => {
                let duration = Utc::now().signed_duration_since(time);
                if duration.num_seconds() < 60 {
                    "Just now".to_string()
                } else if duration.num_minutes() < 60 {
                    format!("{}m ago", duration.num_minutes())
                } else if duration.num_hours() < 24 {
                    format!("{}h ago", duration.num_hours())
                } else {
                    format!("{}d ago", duration.num_days())
                }
            }
            None => "Never".to_string(),
        }
    }
}

impl Route {
    pub fn status_color(&self) -> egui::Color32 {
        if self.enabled {
            egui::Color32::from_rgb(34, 197, 94) // Green
        } else {
            egui::Color32::from_rgb(156, 163, 175) // Gray
        }
    }
}