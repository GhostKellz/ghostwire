use anyhow::{Context, Result};
use ipnet::IpNet;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use crate::config::{TransportConfig, TunnelConfig};

#[derive(Debug, Clone)]
pub struct TunnelInterface {
    pub name: String,
    pub ip_addresses: Vec<IpNet>,
    pub mtu: u16,
    pub routes: Vec<IpNet>,
    pub dns_servers: Vec<IpAddr>,
    pub up: bool,
    pub stats: InterfaceStats,
}

#[derive(Debug, Clone, Default)]
pub struct InterfaceStats {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub errors_sent: u64,
    pub errors_received: u64,
    pub last_updated: Option<SystemTime>,
}

#[derive(Debug, Clone)]
pub struct RouteEntry {
    pub destination: IpNet,
    pub gateway: Option<IpAddr>,
    pub interface: String,
    pub metric: u32,
    pub source: RouteSource,
}

#[derive(Debug, Clone)]
pub enum RouteSource {
    System,
    GhostWire,
    Manual,
}

#[derive(Debug, Clone)]
pub enum TunnelState {
    Down,
    Starting,
    Up {
        interface: TunnelInterface,
        connected_since: SystemTime,
    },
    Stopping,
    Error {
        error: String,
        failed_at: SystemTime,
    },
}

pub struct TunnelManager {
    config: TunnelConfig,
    state: Arc<RwLock<TunnelState>>,
    interfaces: Arc<RwLock<HashMap<String, TunnelInterface>>>,
    routes: Arc<RwLock<Vec<RouteEntry>>>,
}

impl TunnelManager {
    pub fn new(config: TunnelConfig) -> Self {
        Self {
            config,
            state: Arc::new(RwLock::new(TunnelState::Down)),
            interfaces: Arc::new(RwLock::new(HashMap::new())),
            routes: Arc::new(RwLock::new(Vec::new())),
        }
    }

    pub async fn get_state(&self) -> TunnelState {
        self.state.read().await.clone()
    }

    pub async fn start_tunnel(&self, ip_addresses: Vec<IpNet>) -> Result<()> {
        info!("Starting tunnel with IPs: {:?}", ip_addresses);

        {
            let mut state = self.state.write().await;
            *state = TunnelState::Starting;
        }

        match self.create_tunnel_interface(&ip_addresses).await {
            Ok(interface) => {
                let mut state = self.state.write().await;
                *state = TunnelState::Up {
                    interface: interface.clone(),
                    connected_since: SystemTime::now(),
                };

                let mut interfaces = self.interfaces.write().await;
                interfaces.insert(interface.name.clone(), interface);

                info!("Tunnel started successfully");
                Ok(())
            }
            Err(e) => {
                error!("Failed to start tunnel: {}", e);
                let mut state = self.state.write().await;
                *state = TunnelState::Error {
                    error: e.to_string(),
                    failed_at: SystemTime::now(),
                };
                Err(e)
            }
        }
    }

    pub async fn stop_tunnel(&self) -> Result<()> {
        info!("Stopping tunnel");

        {
            let mut state = self.state.write().await;
            *state = TunnelState::Stopping;
        }

        // Remove routes
        self.remove_all_routes().await?;

        // Remove interface
        match self.destroy_tunnel_interface().await {
            Ok(_) => {
                let mut state = self.state.write().await;
                *state = TunnelState::Down;

                let mut interfaces = self.interfaces.write().await;
                interfaces.clear();

                info!("Tunnel stopped successfully");
                Ok(())
            }
            Err(e) => {
                error!("Failed to stop tunnel cleanly: {}", e);
                let mut state = self.state.write().await;
                *state = TunnelState::Error {
                    error: e.to_string(),
                    failed_at: SystemTime::now(),
                };
                Err(e)
            }
        }
    }

    pub async fn add_routes(&self, routes: Vec<IpNet>) -> Result<()> {
        info!("Adding routes: {:?}", routes);

        let interface_name = match self.get_tunnel_interface_name().await {
            Some(name) => name,
            None => return Err(anyhow::anyhow!("No tunnel interface available")),
        };

        for route in routes {
            self.add_route(route, &interface_name).await?;
        }

        Ok(())
    }

    pub async fn remove_routes(&self, routes: Vec<IpNet>) -> Result<()> {
        info!("Removing routes: {:?}", routes);

        for route in routes {
            self.remove_route(route).await?;
        }

        Ok(())
    }

    pub async fn update_dns(&self, dns_servers: Vec<IpAddr>) -> Result<()> {
        info!("Updating DNS servers: {:?}", dns_servers);

        if let Some(interface_name) = self.get_tunnel_interface_name().await {
            self.set_interface_dns(&interface_name, &dns_servers).await?;

            // Update interface state
            let mut interfaces = self.interfaces.write().await;
            if let Some(interface) = interfaces.get_mut(&interface_name) {
                interface.dns_servers = dns_servers;
            }
        }

        Ok(())
    }

    pub async fn get_interface_stats(&self, interface_name: &str) -> Option<InterfaceStats> {
        let interfaces = self.interfaces.read().await;
        interfaces.get(interface_name).map(|iface| iface.stats.clone())
    }

    pub async fn update_interface_stats(&self) -> Result<()> {
        let interface_names: Vec<String> = {
            let interfaces = self.interfaces.read().await;
            interfaces.keys().cloned().collect()
        };

        for interface_name in interface_names {
            if let Ok(stats) = self.read_interface_stats(&interface_name).await {
                let mut interfaces = self.interfaces.write().await;
                if let Some(interface) = interfaces.get_mut(&interface_name) {
                    interface.stats = stats;
                }
            }
        }

        Ok(())
    }

    async fn create_tunnel_interface(&self, ip_addresses: &[IpNet]) -> Result<TunnelInterface> {
        let interface_name = self.config.interface_name.clone();

        // Platform-specific interface creation
        #[cfg(target_os = "linux")]
        {
            self.create_linux_interface(&interface_name, ip_addresses).await
        }

        #[cfg(target_os = "macos")]
        {
            self.create_macos_interface(&interface_name, ip_addresses).await
        }

        #[cfg(target_os = "windows")]
        {
            self.create_windows_interface(&interface_name, ip_addresses).await
        }

        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            Err(anyhow::anyhow!("Unsupported platform"))
        }
    }

    async fn destroy_tunnel_interface(&self) -> Result<()> {
        let interface_name = &self.config.interface_name;

        #[cfg(target_os = "linux")]
        {
            self.destroy_linux_interface(interface_name).await
        }

        #[cfg(target_os = "macos")]
        {
            self.destroy_macos_interface(interface_name).await
        }

        #[cfg(target_os = "windows")]
        {
            self.destroy_windows_interface(interface_name).await
        }

        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            Err(anyhow::anyhow!("Unsupported platform"))
        }
    }

    #[cfg(target_os = "linux")]
    async fn create_linux_interface(&self, name: &str, ip_addresses: &[IpNet]) -> Result<TunnelInterface> {
        use tokio::process::Command;

        // Create TUN interface
        let output = Command::new("ip")
            .args(&["tuntap", "add", "dev", name, "mode", "tun"])
            .output()
            .await
            .context("failed to create TUN interface")?;

        if !output.status.success() {
            return Err(anyhow::anyhow!("Failed to create TUN interface: {}",
                String::from_utf8_lossy(&output.stderr)));
        }

        // Set MTU
        Command::new("ip")
            .args(&["link", "set", "dev", name, "mtu", &self.config.mtu.to_string()])
            .output()
            .await
            .context("failed to set interface MTU")?;

        // Add IP addresses
        for ip_addr in ip_addresses {
            let output = Command::new("ip")
                .args(&["addr", "add", &ip_addr.to_string(), "dev", name])
                .output()
                .await
                .context("failed to add IP address")?;

            if !output.status.success() {
                warn!("Failed to add IP address {}: {}", ip_addr,
                    String::from_utf8_lossy(&output.stderr));
            }
        }

        // Bring interface up
        Command::new("ip")
            .args(&["link", "set", "dev", name, "up"])
            .output()
            .await
            .context("failed to bring interface up")?;

        Ok(TunnelInterface {
            name: name.to_string(),
            ip_addresses: ip_addresses.to_vec(),
            mtu: self.config.mtu,
            routes: Vec::new(),
            dns_servers: Vec::new(),
            up: true,
            stats: InterfaceStats::default(),
        })
    }

    #[cfg(target_os = "linux")]
    async fn destroy_linux_interface(&self, name: &str) -> Result<()> {
        use tokio::process::Command;

        let output = Command::new("ip")
            .args(&["link", "delete", name])
            .output()
            .await
            .context("failed to delete TUN interface")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if !stderr.contains("Cannot find device") {
                return Err(anyhow::anyhow!("Failed to delete TUN interface: {}", stderr));
            }
        }

        Ok(())
    }

    #[cfg(target_os = "macos")]
    async fn create_macos_interface(&self, name: &str, ip_addresses: &[IpNet]) -> Result<TunnelInterface> {
        use tokio::process::Command;

        // Find available utun interface
        let interface_name = if name.starts_with("utun") {
            name.to_string()
        } else {
            "utun10".to_string() // Default utun interface
        };

        // Configure interface with first IP
        if let Some(first_ip) = ip_addresses.first() {
            let output = Command::new("ifconfig")
                .args(&[&interface_name, &first_ip.addr().to_string(), &first_ip.addr().to_string(), "up"])
                .output()
                .await
                .context("failed to configure TUN interface")?;

            if !output.status.success() {
                return Err(anyhow::anyhow!("Failed to configure TUN interface: {}",
                    String::from_utf8_lossy(&output.stderr)));
            }
        }

        // Set MTU
        Command::new("ifconfig")
            .args(&[&interface_name, "mtu", &self.config.mtu.to_string()])
            .output()
            .await
            .context("failed to set interface MTU")?;

        Ok(TunnelInterface {
            name: interface_name,
            ip_addresses: ip_addresses.to_vec(),
            mtu: self.config.mtu,
            routes: Vec::new(),
            dns_servers: Vec::new(),
            up: true,
            stats: InterfaceStats::default(),
        })
    }

    #[cfg(target_os = "macos")]
    async fn destroy_macos_interface(&self, name: &str) -> Result<()> {
        use tokio::process::Command;

        Command::new("ifconfig")
            .args(&[name, "down"])
            .output()
            .await
            .context("failed to bring interface down")?;

        Ok(())
    }

    #[cfg(target_os = "windows")]
    async fn create_windows_interface(&self, name: &str, ip_addresses: &[IpNet]) -> Result<TunnelInterface> {
        // Windows implementation would use WinTun library
        // This is a placeholder for actual Windows TUN interface creation
        warn!("Windows TUN interface creation not fully implemented");

        Ok(TunnelInterface {
            name: name.to_string(),
            ip_addresses: ip_addresses.to_vec(),
            mtu: self.config.mtu,
            routes: Vec::new(),
            dns_servers: Vec::new(),
            up: true,
            stats: InterfaceStats::default(),
        })
    }

    #[cfg(target_os = "windows")]
    async fn destroy_windows_interface(&self, name: &str) -> Result<()> {
        warn!("Windows TUN interface destruction not fully implemented");
        Ok(())
    }

    async fn add_route(&self, destination: IpNet, interface: &str) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            use tokio::process::Command;

            let output = Command::new("ip")
                .args(&["route", "add", &destination.to_string(), "dev", interface])
                .output()
                .await
                .context("failed to add route")?;

            if !output.status.success() {
                return Err(anyhow::anyhow!("Failed to add route: {}",
                    String::from_utf8_lossy(&output.stderr)));
            }
        }

        #[cfg(target_os = "macos")]
        {
            use tokio::process::Command;

            let output = Command::new("route")
                .args(&["add", "-net", &destination.to_string(), "-interface", interface])
                .output()
                .await
                .context("failed to add route")?;

            if !output.status.success() {
                return Err(anyhow::anyhow!("Failed to add route: {}",
                    String::from_utf8_lossy(&output.stderr)));
            }
        }

        // Update route tracking
        let route_entry = RouteEntry {
            destination,
            gateway: None,
            interface: interface.to_string(),
            metric: 0,
            source: RouteSource::GhostWire,
        };

        let mut routes = self.routes.write().await;
        routes.push(route_entry);

        debug!("Added route: {} via {}", destination, interface);
        Ok(())
    }

    async fn remove_route(&self, destination: IpNet) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            use tokio::process::Command;

            let output = Command::new("ip")
                .args(&["route", "del", &destination.to_string()])
                .output()
                .await
                .context("failed to remove route")?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                if !stderr.contains("No such process") {
                    return Err(anyhow::anyhow!("Failed to remove route: {}", stderr));
                }
            }
        }

        #[cfg(target_os = "macos")]
        {
            use tokio::process::Command;

            let output = Command::new("route")
                .args(&["delete", "-net", &destination.to_string()])
                .output()
                .await
                .context("failed to remove route")?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                if !stderr.contains("not in table") {
                    return Err(anyhow::anyhow!("Failed to remove route: {}", stderr));
                }
            }
        }

        // Update route tracking
        let mut routes = self.routes.write().await;
        routes.retain(|route| route.destination != destination);

        debug!("Removed route: {}", destination);
        Ok(())
    }

    async fn remove_all_routes(&self) -> Result<()> {
        let routes_to_remove: Vec<IpNet> = {
            let routes = self.routes.read().await;
            routes.iter()
                .filter(|route| matches!(route.source, RouteSource::GhostWire))
                .map(|route| route.destination)
                .collect()
        };

        for route in routes_to_remove {
            if let Err(e) = self.remove_route(route).await {
                warn!("Failed to remove route {}: {}", route, e);
            }
        }

        Ok(())
    }

    async fn set_interface_dns(&self, interface: &str, dns_servers: &[IpAddr]) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            // On Linux, we typically use systemd-resolved or similar
            info!("DNS configuration on Linux requires systemd-resolved integration");
        }

        #[cfg(target_os = "macos")]
        {
            use tokio::process::Command;

            let dns_list: Vec<String> = dns_servers.iter().map(|ip| ip.to_string()).collect();
            let dns_arg = dns_list.join(" ");

            Command::new("networksetup")
                .args(&["-setdnsservers", interface, &dns_arg])
                .output()
                .await
                .context("failed to set DNS servers")?;
        }

        #[cfg(target_os = "windows")]
        {
            info!("DNS configuration on Windows requires netsh integration");
        }

        Ok(())
    }

    async fn read_interface_stats(&self, interface: &str) -> Result<InterfaceStats> {
        #[cfg(target_os = "linux")]
        {
            use tokio::fs;

            let rx_bytes = fs::read_to_string(format!("/sys/class/net/{}/statistics/rx_bytes", interface))
                .await
                .context("failed to read rx_bytes")?
                .trim()
                .parse::<u64>()
                .unwrap_or(0);

            let tx_bytes = fs::read_to_string(format!("/sys/class/net/{}/statistics/tx_bytes", interface))
                .await
                .context("failed to read tx_bytes")?
                .trim()
                .parse::<u64>()
                .unwrap_or(0);

            let rx_packets = fs::read_to_string(format!("/sys/class/net/{}/statistics/rx_packets", interface))
                .await
                .context("failed to read rx_packets")?
                .trim()
                .parse::<u64>()
                .unwrap_or(0);

            let tx_packets = fs::read_to_string(format!("/sys/class/net/{}/statistics/tx_packets", interface))
                .await
                .context("failed to read tx_packets")?
                .trim()
                .parse::<u64>()
                .unwrap_or(0);

            Ok(InterfaceStats {
                bytes_received: rx_bytes,
                bytes_sent: tx_bytes,
                packets_received: rx_packets,
                packets_sent: tx_packets,
                errors_received: 0,
                errors_sent: 0,
                last_updated: Some(SystemTime::now()),
            })
        }

        #[cfg(not(target_os = "linux"))]
        {
            // Placeholder for other platforms
            Ok(InterfaceStats {
                last_updated: Some(SystemTime::now()),
                ..Default::default()
            })
        }
    }

    async fn get_tunnel_interface_name(&self) -> Option<String> {
        let interfaces = self.interfaces.read().await;
        interfaces.keys().next().cloned()
    }

    pub async fn get_routes(&self) -> Vec<RouteEntry> {
        self.routes.read().await.clone()
    }

    pub async fn get_interfaces(&self) -> HashMap<String, TunnelInterface> {
        self.interfaces.read().await.clone()
    }
}