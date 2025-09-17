/// Settings panel UI for GhostWire Desktop
///
/// Configuration interface for application preferences and connection settings.

use crate::config::AppConfig;
use crate::types::{Theme, UIPreferences, ConnectionPreferences, NotificationSettings};

pub struct SettingsPanel {
    config: AppConfig,
    ui_prefs: UIPreferences,
    connection_prefs: ConnectionPreferences,
    notification_settings: NotificationSettings,
    active_tab: SettingsTab,
}

#[derive(Debug, Clone, PartialEq)]
enum SettingsTab {
    General,
    Connection,
    Notifications,
    Advanced,
}

impl SettingsPanel {
    pub fn new(config: AppConfig) -> Self {
        Self {
            config,
            ui_prefs: UIPreferences::default(),
            connection_prefs: ConnectionPreferences::default(),
            notification_settings: NotificationSettings {
                enabled: true,
                connection_events: true,
                machine_events: false,
                error_events: true,
            },
            active_tab: SettingsTab::General,
        }
    }

    pub fn draw(&mut self, ui: &mut egui::Ui) {
        ui.heading("Settings");

        ui.add_space(10.0);

        // Tab navigation
        ui.horizontal(|ui| {
            ui.selectable_value(&mut self.active_tab, SettingsTab::General, "General");
            ui.selectable_value(&mut self.active_tab, SettingsTab::Connection, "Connection");
            ui.selectable_value(&mut self.active_tab, SettingsTab::Notifications, "Notifications");
            ui.selectable_value(&mut self.active_tab, SettingsTab::Advanced, "Advanced");
        });

        ui.add_space(15.0);
        ui.separator();
        ui.add_space(15.0);

        // Tab content
        match self.active_tab {
            SettingsTab::General => self.draw_general_tab(ui),
            SettingsTab::Connection => self.draw_connection_tab(ui),
            SettingsTab::Notifications => self.draw_notifications_tab(ui),
            SettingsTab::Advanced => self.draw_advanced_tab(ui),
        }
    }

    fn draw_general_tab(&mut self, ui: &mut egui::Ui) {
        ui.heading("General Settings");
        ui.add_space(10.0);

        // Theme selection
        ui.horizontal(|ui| {
            ui.label("Theme:");
            egui::ComboBox::from_id_source("theme")
                .selected_text(format!("{:?}", self.ui_prefs.theme))
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut self.ui_prefs.theme, Theme::Light, "Light");
                    ui.selectable_value(&mut self.ui_prefs.theme, Theme::Dark, "Dark");
                    ui.selectable_value(&mut self.ui_prefs.theme, Theme::System, "System");
                });
        });

        ui.add_space(10.0);

        // System tray options
        ui.checkbox(&mut self.ui_prefs.minimize_to_tray, "Minimize to system tray");
        ui.checkbox(&mut self.ui_prefs.start_minimized, "Start minimized");

        ui.add_space(10.0);

        // Updates
        ui.checkbox(&mut self.ui_prefs.auto_update_check, "Check for updates automatically");

        ui.add_space(10.0);

        // Advanced features
        ui.checkbox(&mut self.ui_prefs.show_advanced_features, "Show advanced features");

        ui.add_space(20.0);

        // Application info
        ui.group(|ui| {
            ui.strong("Application Information");
            ui.add_space(5.0);

            egui::Grid::new("app_info")
                .num_columns(2)
                .spacing([20.0, 5.0])
                .show(ui, |ui| {
                    ui.label("Version:");
                    ui.label(env!("CARGO_PKG_VERSION"));
                    ui.end_row();

                    ui.label("Build:");
                    ui.label("Debug"); // In real app, this would be build info
                    ui.end_row();

                    ui.label("Config Path:");
                    ui.small(self.config.config_path.to_string_lossy());
                    ui.end_row();
                });
        });
    }

    fn draw_connection_tab(&mut self, ui: &mut egui::Ui) {
        ui.heading("Connection Settings");
        ui.add_space(10.0);

        // Server configuration
        ui.group(|ui| {
            ui.strong("Server");
            ui.add_space(5.0);

            ui.horizontal(|ui| {
                ui.label("Server URL:");
                ui.text_edit_singleline(&mut self.config.server_url);
            });

            ui.horizontal(|ui| {
                ui.label("API Key:");
                ui.add(egui::TextEdit::singleline(&mut self.config.api_key).password(true));
            });
        });

        ui.add_space(15.0);

        // Connection preferences
        ui.group(|ui| {
            ui.strong("Connection Preferences");
            ui.add_space(5.0);

            ui.checkbox(&mut self.connection_prefs.auto_connect, "Auto-connect on startup");
            ui.checkbox(&mut self.connection_prefs.accept_routes, "Accept subnet routes");
            ui.checkbox(&mut self.connection_prefs.accept_dns, "Accept DNS configuration");

            ui.add_space(10.0);

            // Exit node selection
            ui.horizontal(|ui| {
                ui.label("Exit node:");
                egui::ComboBox::from_id_source("exit_node")
                    .selected_text(
                        self.connection_prefs.exit_node
                            .as_deref()
                            .unwrap_or("None")
                    )
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut self.connection_prefs.exit_node, None, "None");
                        // In real app, populate with available exit nodes
                        ui.selectable_value(
                            &mut self.connection_prefs.exit_node,
                            Some("us-east-1".to_string()),
                            "us-east-1"
                        );
                        ui.selectable_value(
                            &mut self.connection_prefs.exit_node,
                            Some("eu-west-1".to_string()),
                            "eu-west-1"
                        );
                    });
            });

            // DERP preferences
            ui.checkbox(&mut self.connection_prefs.use_derp_only, "Use DERP relays only (disable direct connections)");

            ui.horizontal(|ui| {
                ui.label("Preferred DERP region:");
                egui::ComboBox::from_id_source("derp_region")
                    .selected_text(
                        self.connection_prefs.preferred_derp_region
                            .as_deref()
                            .unwrap_or("Auto")
                    )
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut self.connection_prefs.preferred_derp_region, None, "Auto");
                        ui.selectable_value(
                            &mut self.connection_prefs.preferred_derp_region,
                            Some("us-east".to_string()),
                            "US East"
                        );
                        ui.selectable_value(
                            &mut self.connection_prefs.preferred_derp_region,
                            Some("eu-west".to_string()),
                            "EU West"
                        );
                        ui.selectable_value(
                            &mut self.connection_prefs.preferred_derp_region,
                            Some("asia-pacific".to_string()),
                            "Asia Pacific"
                        );
                    });
            });
        });

        ui.add_space(15.0);

        // Advanced network settings
        if self.ui_prefs.show_advanced_features {
            ui.group(|ui| {
                ui.strong("Advanced Network");
                ui.add_space(5.0);

                ui.horizontal(|ui| {
                    ui.label("Listen Port:");
                    ui.add(egui::DragValue::new(&mut 41641u16).range(1024..=65535));
                });

                ui.horizontal(|ui| {
                    ui.label("MTU:");
                    ui.add(egui::DragValue::new(&mut 1280u16).range(576..=1500));
                });

                ui.checkbox(&mut false, "Enable packet logging");
                ui.checkbox(&mut false, "Force TCP mode");
            });
        }

        ui.add_space(15.0);

        // Test connection
        ui.horizontal(|ui| {
            if ui.button("Test Connection").clicked() {
                // Test connection to server
            }

            if ui.button("Reset to Defaults").clicked() {
                self.connection_prefs = ConnectionPreferences::default();
            }
        });
    }

    fn draw_notifications_tab(&mut self, ui: &mut egui::Ui) {
        ui.heading("Notification Settings");
        ui.add_space(10.0);

        ui.checkbox(&mut self.notification_settings.enabled, "Enable notifications");

        if self.notification_settings.enabled {
            ui.add_space(10.0);

            ui.group(|ui| {
                ui.strong("Notification Types");
                ui.add_space(5.0);

                ui.checkbox(&mut self.notification_settings.connection_events, "Connection events");
                ui.small("Notify when connecting or disconnecting");

                ui.add_space(5.0);

                ui.checkbox(&mut self.notification_settings.machine_events, "Machine events");
                ui.small("Notify when machines come online or go offline");

                ui.add_space(5.0);

                ui.checkbox(&mut self.notification_settings.error_events, "Error events");
                ui.small("Notify about connection errors and warnings");
            });

            ui.add_space(15.0);

            // Test notification
            if ui.button("Test Notification").clicked() {
                // Show test notification
            }
        }

        ui.add_space(20.0);

        // System notification settings note
        ui.group(|ui| {
            ui.strong("System Notifications");
            ui.add_space(5.0);
            ui.small("To fully enable notifications, make sure GhostWire has permission to show notifications in your system settings.");

            if ui.button("Open System Settings").clicked() {
                // Open system notification settings
                #[cfg(target_os = "windows")]
                {
                    std::process::Command::new("ms-settings:notifications")
                        .spawn()
                        .ok();
                }

                #[cfg(target_os = "macos")]
                {
                    std::process::Command::new("open")
                        .args(&["-b", "com.apple.preference.notifications"])
                        .spawn()
                        .ok();
                }
            }
        });
    }

    fn draw_advanced_tab(&mut self, ui: &mut egui::Ui) {
        ui.heading("Advanced Settings");
        ui.add_space(10.0);

        ui.group(|ui| {
            ui.strong("Logging");
            ui.add_space(5.0);

            ui.horizontal(|ui| {
                ui.label("Log Level:");
                egui::ComboBox::from_id_source("log_level")
                    .selected_text("Info")
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut "trace", "trace", "Trace");
                        ui.selectable_value(&mut "debug", "debug", "Debug");
                        ui.selectable_value(&mut "info", "info", "Info");
                        ui.selectable_value(&mut "warn", "warn", "Warning");
                        ui.selectable_value(&mut "error", "error", "Error");
                    });
            });

            if ui.button("Open Log File").clicked() {
                // Open log file location
            }

            if ui.button("Export Logs").clicked() {
                // Export logs for support
            }
        });

        ui.add_space(15.0);

        ui.group(|ui| {
            ui.strong("Data");
            ui.add_space(5.0);

            if ui.button("Clear Cache").clicked() {
                // Clear application cache
            }

            if ui.button("Reset All Settings").clicked() {
                // Reset to defaults with confirmation
            }

            ui.add_space(10.0);

            ui.horizontal(|ui| {
                ui.label("Config directory:");
                ui.small(self.config.config_path.to_string_lossy());
                if ui.small_button("📁").on_hover_text("Open in file manager").clicked() {
                    // Open config directory
                    #[cfg(target_os = "windows")]
                    {
                        std::process::Command::new("explorer")
                            .arg(&self.config.config_path)
                            .spawn()
                            .ok();
                    }

                    #[cfg(target_os = "macos")]
                    {
                        std::process::Command::new("open")
                            .arg(&self.config.config_path)
                            .spawn()
                            .ok();
                    }

                    #[cfg(target_os = "linux")]
                    {
                        std::process::Command::new("xdg-open")
                            .arg(&self.config.config_path)
                            .spawn()
                            .ok();
                    }
                }
            });
        });

        ui.add_space(15.0);

        ui.group(|ui| {
            ui.strong("Development");
            ui.add_space(5.0);

            ui.checkbox(&mut false, "Enable debug mode");
            ui.checkbox(&mut false, "Mock data mode");

            if ui.button("Generate Debug Report").clicked() {
                // Generate debug report
            }
        });
    }
}