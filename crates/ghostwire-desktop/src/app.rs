/// Main application state and logic for GhostWire Desktop
///
/// Manages the overall application state, coordinates between UI and backend,
/// and handles application lifecycle.

use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{info, warn, error};

use crate::config::AppConfig;
use crate::client::GhostWireClient;
use crate::ui::{ConnectionPanel, MachinesPanel, SettingsPanel, AboutPanel};
use crate::types::*;

pub struct GhostWireApp {
    config: AppConfig,
    client: Arc<RwLock<GhostWireClient>>,

    // UI state
    current_page: AppPage,
    show_settings: bool,
    show_about: bool,

    // Connection state
    connection_status: ConnectionStatus,
    last_update: Instant,

    // Data
    machines: Vec<Machine>,
    routes: Vec<Route>,
    network_stats: NetworkStats,

    // UI panels
    connection_panel: ConnectionPanel,
    machines_panel: MachinesPanel,
    settings_panel: SettingsPanel,
    about_panel: AboutPanel,
}

#[derive(Debug, Clone, PartialEq)]
pub enum AppPage {
    Connection,
    Machines,
    Settings,
}

impl GhostWireApp {
    pub async fn new(config: AppConfig) -> Result<Self, Box<dyn std::error::Error>> {
        let client = Arc::new(RwLock::new(
            GhostWireClient::new(config.clone()).await?
        ));

        Ok(Self {
            config: config.clone(),
            client,
            current_page: AppPage::Connection,
            show_settings: false,
            show_about: false,
            connection_status: ConnectionStatus::Disconnected,
            last_update: Instant::now(),
            machines: Vec::new(),
            routes: Vec::new(),
            network_stats: NetworkStats::default(),
            connection_panel: ConnectionPanel::new(),
            machines_panel: MachinesPanel::new(),
            settings_panel: SettingsPanel::new(config),
            about_panel: AboutPanel::new(),
        })
    }

    pub fn update(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
        // Update data periodically
        if self.last_update.elapsed() > Duration::from_secs(5) {
            self.refresh_data();
            self.last_update = Instant::now();
        }

        // Top menu bar
        egui::TopBottomPanel::top("menu_bar").show(ctx, |ui| {
            self.draw_menu_bar(ui, frame);
        });

        // Status bar
        egui::TopBottomPanel::bottom("status_bar").show(ctx, |ui| {
            self.draw_status_bar(ui);
        });

        // Sidebar navigation
        egui::SidePanel::left("sidebar")
            .resizable(false)
            .exact_width(200.0)
            .show(ctx, |ui| {
                self.draw_sidebar(ui);
            });

        // Main content area
        egui::CentralPanel::default().show(ctx, |ui| {
            self.draw_main_content(ui);
        });

        // Modal dialogs
        if self.show_settings {
            self.draw_settings_modal(ctx);
        }

        if self.show_about {
            self.draw_about_modal(ctx);
        }
    }

    fn draw_menu_bar(&mut self, ui: &mut egui::Ui, frame: &mut eframe::Frame) {
        egui::menu::bar(ui, |ui| {
            // Application menu
            ui.menu_button("GhostWire", |ui| {
                if ui.button("About GhostWire").clicked() {
                    self.show_about = true;
                    ui.close_menu();
                }
                ui.separator();
                if ui.button("Preferences...").clicked() {
                    self.show_settings = true;
                    ui.close_menu();
                }
                ui.separator();
                if ui.button("Quit").clicked() {
                    frame.close();
                }
            });

            // Connection menu
            ui.menu_button("Connection", |ui| {
                match self.connection_status {
                    ConnectionStatus::Disconnected => {
                        if ui.button("Connect").clicked() {
                            self.connect();
                            ui.close_menu();
                        }
                    }
                    ConnectionStatus::Connected(_) => {
                        if ui.button("Disconnect").clicked() {
                            self.disconnect();
                            ui.close_menu();
                        }
                    }
                    _ => {
                        ui.add_enabled(false, egui::Button::new("Connecting..."));
                    }
                }

                ui.separator();
                if ui.button("Refresh").clicked() {
                    self.refresh_data();
                    ui.close_menu();
                }
            });

            // View menu
            ui.menu_button("View", |ui| {
                if ui.selectable_label(self.current_page == AppPage::Connection, "Connection").clicked() {
                    self.current_page = AppPage::Connection;
                    ui.close_menu();
                }
                if ui.selectable_label(self.current_page == AppPage::Machines, "Machines").clicked() {
                    self.current_page = AppPage::Machines;
                    ui.close_menu();
                }
            });

            // Window controls (right-aligned)
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                // Connection status indicator
                let (status_text, status_color) = match &self.connection_status {
                    ConnectionStatus::Connected(_) => ("Connected", egui::Color32::from_rgb(34, 197, 94)),
                    ConnectionStatus::Connecting => ("Connecting...", egui::Color32::from_rgb(251, 191, 36)),
                    ConnectionStatus::Disconnected => ("Disconnected", egui::Color32::from_rgb(239, 68, 68)),
                    ConnectionStatus::Error(_) => ("Error", egui::Color32::from_rgb(239, 68, 68)),
                };

                ui.colored_label(status_color, status_text);

                // Status dot
                let dot_rect = egui::Rect::from_center_size(
                    ui.next_widget_position() + egui::vec2(-15.0, 0.0),
                    egui::vec2(8.0, 8.0)
                );
                ui.painter().circle_filled(dot_rect.center(), 4.0, status_color);
            });
        });
    }

    fn draw_sidebar(&mut self, ui: &mut egui::Ui) {
        ui.with_layout(egui::Layout::top_down(egui::Align::LEFT), |ui| {
            ui.add_space(10.0);

            // Navigation buttons
            let button_size = egui::vec2(180.0, 40.0);

            if ui.add_sized(button_size, egui::SelectableLabel::new(
                self.current_page == AppPage::Connection,
                "🔗 Connection"
            )).clicked() {
                self.current_page = AppPage::Connection;
            }

            if ui.add_sized(button_size, egui::SelectableLabel::new(
                self.current_page == AppPage::Machines,
                "🖥️ Machines"
            )).clicked() {
                self.current_page = AppPage::Machines;
            }

            ui.add_space(20.0);
            ui.separator();
            ui.add_space(20.0);

            // Quick actions
            ui.label("Quick Actions");
            ui.add_space(5.0);

            if ui.add_sized(button_size, egui::Button::new("🔄 Refresh")).clicked() {
                self.refresh_data();
            }

            if ui.add_sized(button_size, egui::Button::new("⚙️ Settings")).clicked() {
                self.show_settings = true;
            }

            // Network stats summary
            ui.add_space(20.0);
            ui.separator();
            ui.add_space(20.0);

            ui.label("Network");
            ui.add_space(5.0);

            // Connection status
            ui.horizontal(|ui| {
                ui.label("Status:");
                let (text, color) = match &self.connection_status {
                    ConnectionStatus::Connected(_) => ("Online", egui::Color32::GREEN),
                    ConnectionStatus::Connecting => ("Connecting", egui::Color32::YELLOW),
                    _ => ("Offline", egui::Color32::RED),
                };
                ui.colored_label(color, text);
            });

            // Machine count
            ui.horizontal(|ui| {
                ui.label("Machines:");
                ui.label(self.machines.len().to_string());
            });

            // Bandwidth
            ui.horizontal(|ui| {
                ui.label("Upload:");
                ui.label(format_bytes(self.network_stats.bytes_sent));
            });

            ui.horizontal(|ui| {
                ui.label("Download:");
                ui.label(format_bytes(self.network_stats.bytes_received));
            });
        });
    }

    fn draw_main_content(&mut self, ui: &mut egui::Ui) {
        match self.current_page {
            AppPage::Connection => {
                self.connection_panel.draw(ui, &self.connection_status, &self.network_stats);
            }
            AppPage::Machines => {
                self.machines_panel.draw(ui, &self.machines, &self.routes);
            }
            AppPage::Settings => {
                self.settings_panel.draw(ui);
            }
        }
    }

    fn draw_status_bar(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label(format!("GhostWire Desktop v{}", env!("CARGO_PKG_VERSION")));

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                // Last update time
                ui.label(format!("Last updated: {}s ago", self.last_update.elapsed().as_secs()));

                ui.separator();

                // Server info
                if let ConnectionStatus::Connected(ref info) = self.connection_status {
                    ui.label(format!("Server: {}", info.server_url));
                }
            });
        });
    }

    fn draw_settings_modal(&mut self, ctx: &egui::Context) {
        egui::Window::new("Settings")
            .resizable(true)
            .default_size([600.0, 400.0])
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                self.settings_panel.draw(ui);

                ui.separator();
                ui.horizontal(|ui| {
                    if ui.button("Save").clicked() {
                        // Save settings
                        self.show_settings = false;
                    }
                    if ui.button("Cancel").clicked() {
                        self.show_settings = false;
                    }
                });
            });
    }

    fn draw_about_modal(&mut self, ctx: &egui::Context) {
        egui::Window::new("About GhostWire")
            .resizable(false)
            .default_size([400.0, 300.0])
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                self.about_panel.draw(ui);

                ui.separator();
                if ui.button("Close").clicked() {
                    self.show_about = false;
                }
            });
    }

    fn connect(&mut self) {
        self.connection_status = ConnectionStatus::Connecting;
        // In a real app, this would initiate async connection
        info!("Initiating connection to GhostWire network");
    }

    fn disconnect(&mut self) {
        self.connection_status = ConnectionStatus::Disconnected;
        info!("Disconnected from GhostWire network");
    }

    fn refresh_data(&mut self) {
        // In a real app, this would fetch data from the client
        info!("Refreshing network data");

        // Mock some data updates
        self.network_stats.bytes_sent += 1024 * 50; // 50KB
        self.network_stats.bytes_received += 1024 * 200; // 200KB
    }

    pub fn connection_status(&self) -> &ConnectionStatus {
        &self.connection_status
    }

    pub fn is_connected(&self) -> bool {
        matches!(self.connection_status, ConnectionStatus::Connected(_))
    }
}

fn format_bytes(bytes: u64) -> String {
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