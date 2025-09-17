/// Configuration management for GhostWire Desktop
///
/// Handles loading, saving, and managing application configuration.

use std::path::PathBuf;
use serde::{Deserialize, Serialize};
use tracing::{info, warn, error};

use crate::types::{UIPreferences, ConnectionPreferences, NotificationSettings};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub server_url: String,
    pub api_key: String,
    pub machine_name: String,
    pub config_path: PathBuf,
    pub ui_preferences: UIPreferences,
    pub connection_preferences: ConnectionPreferences,
    pub notification_settings: NotificationSettings,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            server_url: "https://ghostwire.example.com".to_string(),
            api_key: String::new(),
            machine_name: hostname::get()
                .unwrap_or_else(|_| "unknown".into())
                .to_string_lossy()
                .to_string(),
            config_path: Self::default_config_path(),
            ui_preferences: UIPreferences::default(),
            connection_preferences: ConnectionPreferences::default(),
            notification_settings: NotificationSettings {
                enabled: true,
                connection_events: true,
                machine_events: false,
                error_events: true,
            },
        }
    }
}

impl AppConfig {
    pub async fn load() -> Result<Self, Box<dyn std::error::Error>> {
        let config_path = Self::default_config_path();
        let config_file = config_path.join("config.toml");

        if config_file.exists() {
            info!("Loading config from {}", config_file.display());
            let content = tokio::fs::read_to_string(&config_file).await?;
            let mut config: AppConfig = toml::from_str(&content)?;
            config.config_path = config_path;
            Ok(config)
        } else {
            info!("No config file found, creating default config at {}", config_file.display());
            let config = Self::default();
            config.save().await?;
            Ok(config)
        }
    }

    pub async fn save(&self) -> Result<(), Box<dyn std::error::Error>> {
        let config_file = self.config_path.join("config.toml");

        // Ensure config directory exists
        if let Some(parent) = config_file.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        let content = toml::to_string_pretty(self)?;
        tokio::fs::write(&config_file, content).await?;

        info!("Config saved to {}", config_file.display());
        Ok(())
    }

    fn default_config_path() -> PathBuf {
        if let Some(config_dir) = dirs::config_dir() {
            config_dir.join("ghostwire")
        } else {
            // Fallback for systems without config_dir
            #[cfg(windows)]
            {
                PathBuf::from(r"C:\Users\Default\AppData\Roaming\ghostwire")
            }
            #[cfg(not(windows))]
            {
                PathBuf::from("~/.config/ghostwire")
            }
        }
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.server_url.is_empty() {
            return Err(ConfigError::InvalidServerUrl);
        }

        if !self.server_url.starts_with("http://") && !self.server_url.starts_with("https://") {
            return Err(ConfigError::InvalidServerUrl);
        }

        if self.machine_name.is_empty() {
            return Err(ConfigError::InvalidMachineName);
        }

        Ok(())
    }

    pub fn server_api_url(&self) -> String {
        format!("{}/api/v1", self.server_url.trim_end_matches('/'))
    }

    pub fn auth_header(&self) -> Option<String> {
        if !self.api_key.is_empty() {
            Some(format!("Bearer {}", self.api_key))
        } else {
            None
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("Invalid server URL")]
    InvalidServerUrl,
    #[error("Invalid machine name")]
    InvalidMachineName,
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    Serialization(#[from] toml::ser::Error),
    #[error("Deserialization error: {0}")]
    Deserialization(#[from] toml::de::Error),
}

// Helper to get machine name with fallbacks
fn hostname() -> String {
    hostname::get()
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_else(|_| {
            // Try alternative methods
            std::env::var("COMPUTERNAME")
                .or_else(|_| std::env::var("HOSTNAME"))
                .unwrap_or_else(|_| "unknown-machine".to_string())
        })
}