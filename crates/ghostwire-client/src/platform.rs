use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Stdio;
use tokio::process::Command;
use tracing::{debug, error, info, warn};

use crate::config::PlatformConfig;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemInfo {
    pub hostname: String,
    pub os: String,
    pub os_version: String,
    pub arch: String,
    pub interfaces: Vec<NetworkInterface>,
    pub default_routes: Vec<String>,
    pub dns_servers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInterface {
    pub name: String,
    pub mac_address: String,
    pub ip_addresses: Vec<String>,
    pub up: bool,
    pub mtu: u32,
}

#[derive(Debug, Clone)]
pub struct ServiceInfo {
    pub name: String,
    pub description: String,
    pub executable_path: PathBuf,
    pub args: Vec<String>,
    pub auto_start: bool,
    pub user: Option<String>,
}

pub struct PlatformManager {
    config: PlatformConfig,
}

impl PlatformManager {
    pub fn new(config: PlatformConfig) -> Self {
        Self { config }
    }

    pub async fn get_system_info(&self) -> Result<SystemInfo> {
        let hostname = self.get_hostname().await?;
        let os = std::env::consts::OS.to_string();
        let arch = std::env::consts::ARCH.to_string();
        let os_version = self.get_os_version().await?;
        let interfaces = self.get_network_interfaces().await?;
        let default_routes = self.get_default_routes().await?;
        let dns_servers = self.get_dns_servers().await?;

        Ok(SystemInfo {
            hostname,
            os,
            os_version,
            arch,
            interfaces,
            default_routes,
            dns_servers,
        })
    }

    pub async fn install_service(&self, service_info: &ServiceInfo) -> Result<()> {
        info!("Installing service: {}", service_info.name);

        #[cfg(target_os = "linux")]
        {
            self.install_systemd_service(service_info).await
        }

        #[cfg(target_os = "macos")]
        {
            self.install_launchd_service(service_info).await
        }

        #[cfg(target_os = "windows")]
        {
            self.install_windows_service(service_info).await
        }

        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            Err(anyhow::anyhow!("Service installation not supported on this platform"))
        }
    }

    pub async fn uninstall_service(&self, service_name: &str) -> Result<()> {
        info!("Uninstalling service: {}", service_name);

        #[cfg(target_os = "linux")]
        {
            self.uninstall_systemd_service(service_name).await
        }

        #[cfg(target_os = "macos")]
        {
            self.uninstall_launchd_service(service_name).await
        }

        #[cfg(target_os = "windows")]
        {
            self.uninstall_windows_service(service_name).await
        }

        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            Err(anyhow::anyhow!("Service uninstallation not supported on this platform"))
        }
    }

    pub async fn start_service(&self, service_name: &str) -> Result<()> {
        info!("Starting service: {}", service_name);

        #[cfg(target_os = "linux")]
        {
            let output = Command::new("systemctl")
                .args(&["start", service_name])
                .output()
                .await
                .context("failed to start systemd service")?;

            if !output.status.success() {
                return Err(anyhow::anyhow!("Failed to start service: {}",
                    String::from_utf8_lossy(&output.stderr)));
            }
        }

        #[cfg(target_os = "macos")]
        {
            let output = Command::new("launchctl")
                .args(&["load", &format!("/Library/LaunchDaemons/{}.plist", service_name)])
                .output()
                .await
                .context("failed to start launchd service")?;

            if !output.status.success() {
                return Err(anyhow::anyhow!("Failed to start service: {}",
                    String::from_utf8_lossy(&output.stderr)));
            }
        }

        #[cfg(target_os = "windows")]
        {
            let output = Command::new("sc")
                .args(&["start", service_name])
                .output()
                .await
                .context("failed to start Windows service")?;

            if !output.status.success() {
                return Err(anyhow::anyhow!("Failed to start service: {}",
                    String::from_utf8_lossy(&output.stderr)));
            }
        }

        Ok(())
    }

    pub async fn stop_service(&self, service_name: &str) -> Result<()> {
        info!("Stopping service: {}", service_name);

        #[cfg(target_os = "linux")]
        {
            let output = Command::new("systemctl")
                .args(&["stop", service_name])
                .output()
                .await
                .context("failed to stop systemd service")?;

            if !output.status.success() {
                return Err(anyhow::anyhow!("Failed to stop service: {}",
                    String::from_utf8_lossy(&output.stderr)));
            }
        }

        #[cfg(target_os = "macos")]
        {
            let output = Command::new("launchctl")
                .args(&["unload", &format!("/Library/LaunchDaemons/{}.plist", service_name)])
                .output()
                .await
                .context("failed to stop launchd service")?;

            if !output.status.success() {
                return Err(anyhow::anyhow!("Failed to stop service: {}",
                    String::from_utf8_lossy(&output.stderr)));
            }
        }

        #[cfg(target_os = "windows")]
        {
            let output = Command::new("sc")
                .args(&["stop", service_name])
                .output()
                .await
                .context("failed to stop Windows service")?;

            if !output.status.success() {
                return Err(anyhow::anyhow!("Failed to stop service: {}",
                    String::from_utf8_lossy(&output.stderr)));
            }
        }

        Ok(())
    }

    pub async fn get_service_status(&self, service_name: &str) -> Result<bool> {
        #[cfg(target_os = "linux")]
        {
            let output = Command::new("systemctl")
                .args(&["is-active", service_name])
                .output()
                .await
                .context("failed to check systemd service status")?;

            Ok(output.status.success() &&
               String::from_utf8_lossy(&output.stdout).trim() == "active")
        }

        #[cfg(target_os = "macos")]
        {
            let output = Command::new("launchctl")
                .args(&["list", service_name])
                .output()
                .await
                .context("failed to check launchd service status")?;

            Ok(output.status.success())
        }

        #[cfg(target_os = "windows")]
        {
            let output = Command::new("sc")
                .args(&["query", service_name])
                .output()
                .await
                .context("failed to check Windows service status")?;

            let output_str = String::from_utf8_lossy(&output.stdout);
            Ok(output.status.success() && output_str.contains("RUNNING"))
        }

        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            Ok(false)
        }
    }

    pub async fn check_permissions(&self) -> Result<Vec<String>> {
        let mut missing_permissions = Vec::new();

        // Check if running as root/admin
        if !self.is_elevated().await? {
            missing_permissions.push("Administrator/root privileges required".to_string());
        }

        // Check TUN/TAP permissions
        if !self.check_tun_permissions().await? {
            missing_permissions.push("TUN/TAP interface creation permissions".to_string());
        }

        // Check network configuration permissions
        if !self.check_network_permissions().await? {
            missing_permissions.push("Network configuration permissions".to_string());
        }

        Ok(missing_permissions)
    }

    async fn get_hostname(&self) -> Result<String> {
        #[cfg(unix)]
        {
            let output = Command::new("hostname")
                .output()
                .await
                .context("failed to get hostname")?;

            Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
        }

        #[cfg(windows)]
        {
            let output = Command::new("hostname")
                .output()
                .await
                .context("failed to get hostname")?;

            Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
        }
    }

    async fn get_os_version(&self) -> Result<String> {
        #[cfg(target_os = "linux")]
        {
            match tokio::fs::read_to_string("/etc/os-release").await {
                Ok(content) => {
                    for line in content.lines() {
                        if line.starts_with("PRETTY_NAME=") {
                            return Ok(line.split('=').nth(1).unwrap_or("Unknown")
                                .trim_matches('"').to_string());
                        }
                    }
                    Ok("Linux".to_string())
                }
                Err(_) => Ok("Linux".to_string()),
            }
        }

        #[cfg(target_os = "macos")]
        {
            let output = Command::new("sw_vers")
                .args(&["-productVersion"])
                .output()
                .await
                .context("failed to get macOS version")?;

            Ok(format!("macOS {}", String::from_utf8_lossy(&output.stdout).trim()))
        }

        #[cfg(target_os = "windows")]
        {
            let output = Command::new("cmd")
                .args(&["/c", "ver"])
                .output()
                .await
                .context("failed to get Windows version")?;

            Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
        }

        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            Ok("Unknown".to_string())
        }
    }

    async fn get_network_interfaces(&self) -> Result<Vec<NetworkInterface>> {
        let mut interfaces = Vec::new();

        #[cfg(unix)]
        {
            let output = Command::new("ip")
                .args(&["addr", "show"])
                .output()
                .await
                .context("failed to get network interfaces")?;

            let output_str = String::from_utf8_lossy(&output.stdout);
            // Parse ip addr output (simplified)
            for line in output_str.lines() {
                if line.contains("mtu") && !line.contains("lo:") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        let name = parts[1].trim_end_matches(':').to_string();
                        interfaces.push(NetworkInterface {
                            name,
                            mac_address: "00:00:00:00:00:00".to_string(), // Simplified
                            ip_addresses: Vec::new(),
                            up: line.contains("UP"),
                            mtu: 1500, // Default
                        });
                    }
                }
            }
        }

        #[cfg(target_os = "windows")]
        {
            let output = Command::new("ipconfig")
                .args(&["/all"])
                .output()
                .await
                .context("failed to get network interfaces")?;

            // Parse ipconfig output (simplified)
            let output_str = String::from_utf8_lossy(&output.stdout);
            // Basic parsing - would need more sophisticated parsing in real implementation
            interfaces.push(NetworkInterface {
                name: "Ethernet".to_string(),
                mac_address: "00:00:00:00:00:00".to_string(),
                ip_addresses: Vec::new(),
                up: true,
                mtu: 1500,
            });
        }

        Ok(interfaces)
    }

    async fn get_default_routes(&self) -> Result<Vec<String>> {
        #[cfg(target_os = "linux")]
        {
            let output = Command::new("ip")
                .args(&["route", "show", "default"])
                .output()
                .await
                .context("failed to get default routes")?;

            let routes: Vec<String> = String::from_utf8_lossy(&output.stdout)
                .lines()
                .map(|line| line.to_string())
                .collect();

            Ok(routes)
        }

        #[cfg(target_os = "macos")]
        {
            let output = Command::new("route")
                .args(&["get", "default"])
                .output()
                .await
                .context("failed to get default routes")?;

            let routes: Vec<String> = String::from_utf8_lossy(&output.stdout)
                .lines()
                .map(|line| line.to_string())
                .collect();

            Ok(routes)
        }

        #[cfg(target_os = "windows")]
        {
            let output = Command::new("route")
                .args(&["print", "0.0.0.0"])
                .output()
                .await
                .context("failed to get default routes")?;

            let routes: Vec<String> = String::from_utf8_lossy(&output.stdout)
                .lines()
                .map(|line| line.to_string())
                .collect();

            Ok(routes)
        }

        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            Ok(Vec::new())
        }
    }

    async fn get_dns_servers(&self) -> Result<Vec<String>> {
        #[cfg(target_os = "linux")]
        {
            match tokio::fs::read_to_string("/etc/resolv.conf").await {
                Ok(content) => {
                    let servers: Vec<String> = content
                        .lines()
                        .filter(|line| line.starts_with("nameserver"))
                        .filter_map(|line| line.split_whitespace().nth(1))
                        .map(|s| s.to_string())
                        .collect();
                    Ok(servers)
                }
                Err(_) => Ok(Vec::new()),
            }
        }

        #[cfg(target_os = "macos")]
        {
            let output = Command::new("scutil")
                .args(&["--dns"])
                .output()
                .await
                .context("failed to get DNS servers")?;

            let servers: Vec<String> = String::from_utf8_lossy(&output.stdout)
                .lines()
                .filter(|line| line.contains("nameserver"))
                .filter_map(|line| line.split_whitespace().last())
                .map(|s| s.to_string())
                .collect();

            Ok(servers)
        }

        #[cfg(target_os = "windows")]
        {
            let output = Command::new("nslookup")
                .args(&["localhost"])
                .output()
                .await
                .context("failed to get DNS servers")?;

            // Parse nslookup output for DNS servers
            Ok(Vec::new()) // Simplified
        }

        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            Ok(Vec::new())
        }
    }

    #[cfg(target_os = "linux")]
    async fn install_systemd_service(&self, service_info: &ServiceInfo) -> Result<()> {
        let service_content = format!(
            r#"[Unit]
Description={}
After=network.target

[Service]
Type=simple
User={}
ExecStart={} {}
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
"#,
            service_info.description,
            service_info.user.as_deref().unwrap_or("root"),
            service_info.executable_path.display(),
            service_info.args.join(" ")
        );

        let service_path = format!("/etc/systemd/system/{}.service", service_info.name);
        tokio::fs::write(&service_path, service_content)
            .await
            .context("failed to write systemd service file")?;

        // Reload systemd and enable service
        Command::new("systemctl")
            .args(&["daemon-reload"])
            .output()
            .await
            .context("failed to reload systemd")?;

        if service_info.auto_start {
            Command::new("systemctl")
                .args(&["enable", &service_info.name])
                .output()
                .await
                .context("failed to enable systemd service")?;
        }

        Ok(())
    }

    #[cfg(target_os = "linux")]
    async fn uninstall_systemd_service(&self, service_name: &str) -> Result<()> {
        // Stop and disable service
        let _ = Command::new("systemctl")
            .args(&["stop", service_name])
            .output()
            .await;

        let _ = Command::new("systemctl")
            .args(&["disable", service_name])
            .output()
            .await;

        // Remove service file
        let service_path = format!("/etc/systemd/system/{}.service", service_name);
        let _ = tokio::fs::remove_file(&service_path).await;

        // Reload systemd
        Command::new("systemctl")
            .args(&["daemon-reload"])
            .output()
            .await
            .context("failed to reload systemd")?;

        Ok(())
    }

    #[cfg(target_os = "macos")]
    async fn install_launchd_service(&self, service_info: &ServiceInfo) -> Result<()> {
        let plist_content = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{}</string>
        {}
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
"#,
            service_info.name,
            service_info.executable_path.display(),
            service_info.args.iter()
                .map(|arg| format!("        <string>{}</string>", arg))
                .collect::<Vec<_>>()
                .join("\n")
        );

        let plist_path = format!("/Library/LaunchDaemons/{}.plist", service_info.name);
        tokio::fs::write(&plist_path, plist_content)
            .await
            .context("failed to write launchd plist file")?;

        if service_info.auto_start {
            Command::new("launchctl")
                .args(&["load", &plist_path])
                .output()
                .await
                .context("failed to load launchd service")?;
        }

        Ok(())
    }

    #[cfg(target_os = "macos")]
    async fn uninstall_launchd_service(&self, service_name: &str) -> Result<()> {
        let plist_path = format!("/Library/LaunchDaemons/{}.plist", service_name);

        // Unload service
        let _ = Command::new("launchctl")
            .args(&["unload", &plist_path])
            .output()
            .await;

        // Remove plist file
        let _ = tokio::fs::remove_file(&plist_path).await;

        Ok(())
    }

    #[cfg(target_os = "windows")]
    async fn install_windows_service(&self, service_info: &ServiceInfo) -> Result<()> {
        let service_cmd = format!("{} {}",
            service_info.executable_path.display(),
            service_info.args.join(" "));

        let output = Command::new("sc")
            .args(&[
                "create",
                &service_info.name,
                "binPath=",
                &service_cmd,
                "DisplayName=",
                &service_info.description,
            ])
            .output()
            .await
            .context("failed to create Windows service")?;

        if !output.status.success() {
            return Err(anyhow::anyhow!("Failed to create Windows service: {}",
                String::from_utf8_lossy(&output.stderr)));
        }

        if service_info.auto_start {
            Command::new("sc")
                .args(&["config", &service_info.name, "start=", "auto"])
                .output()
                .await
                .context("failed to configure Windows service auto-start")?;
        }

        Ok(())
    }

    #[cfg(target_os = "windows")]
    async fn uninstall_windows_service(&self, service_name: &str) -> Result<()> {
        // Stop service
        let _ = Command::new("sc")
            .args(&["stop", service_name])
            .output()
            .await;

        // Delete service
        let output = Command::new("sc")
            .args(&["delete", service_name])
            .output()
            .await
            .context("failed to delete Windows service")?;

        if !output.status.success() {
            return Err(anyhow::anyhow!("Failed to delete Windows service: {}",
                String::from_utf8_lossy(&output.stderr)));
        }

        Ok(())
    }

    async fn is_elevated(&self) -> Result<bool> {
        #[cfg(unix)]
        {
            Ok(nix::unistd::getuid().is_root())
        }

        #[cfg(windows)]
        {
            // Check if running as administrator on Windows
            let output = Command::new("net")
                .args(&["session"])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .await
                .context("failed to check elevation")?;

            Ok(output.success())
        }
    }

    async fn check_tun_permissions(&self) -> Result<bool> {
        #[cfg(target_os = "linux")]
        {
            // Check if /dev/net/tun exists and is accessible
            match tokio::fs::metadata("/dev/net/tun").await {
                Ok(_) => Ok(true),
                Err(_) => Ok(false),
            }
        }

        #[cfg(target_os = "macos")]
        {
            // On macOS, utun interfaces are available to root
            Ok(nix::unistd::getuid().is_root())
        }

        #[cfg(target_os = "windows")]
        {
            // Check for WinTun driver or TAP adapter
            Ok(true) // Simplified check
        }

        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            Ok(false)
        }
    }

    async fn check_network_permissions(&self) -> Result<bool> {
        // Check if we can modify network routes and interfaces
        self.is_elevated().await
    }
}