/// Machines panel UI for GhostWire Desktop
///
/// Displays and manages connected devices in the mesh network.

use egui_extras::{Column, TableBuilder};
use crate::types::{Machine, Route};

pub struct MachinesPanel {
    selected_machine: Option<String>,
    show_offline: bool,
    search_query: String,
}

impl MachinesPanel {
    pub fn new() -> Self {
        Self {
            selected_machine: None,
            show_offline: true,
            search_query: String::new(),
        }
    }

    pub fn draw(&mut self, ui: &mut egui::Ui, machines: &[Machine], routes: &[Route]) {
        ui.heading("Machines");

        // Filters and controls
        ui.add_space(10.0);
        self.draw_controls(ui, machines);

        ui.add_space(10.0);

        // Filter machines based on search and visibility settings
        let filtered_machines: Vec<&Machine> = machines
            .iter()
            .filter(|machine| {
                let matches_search = if self.search_query.is_empty() {
                    true
                } else {
                    let query = self.search_query.to_lowercase();
                    machine.name.to_lowercase().contains(&query) ||
                    machine.hostname.to_lowercase().contains(&query) ||
                    machine.user.to_lowercase().contains(&query) ||
                    machine.ip_addresses.iter().any(|ip| ip.to_string().contains(&query))
                };

                let is_visible = self.show_offline || machine.online;

                matches_search && is_visible
            })
            .collect();

        // Machines table
        if filtered_machines.is_empty() {
            self.draw_empty_state(ui);
        } else {
            self.draw_machines_table(ui, &filtered_machines);
        }

        // Machine details sidebar (if selected)
        if let Some(ref machine_id) = self.selected_machine.clone() {
            if let Some(machine) = machines.iter().find(|m| m.id == *machine_id) {
                ui.add_space(20.0);
                ui.separator();
                ui.add_space(10.0);
                self.draw_machine_details(ui, machine, routes);
            }
        }
    }

    fn draw_controls(&mut self, ui: &mut egui::Ui, machines: &[Machine]) {
        ui.horizontal(|ui| {
            // Search box
            ui.label("Search:");
            ui.text_edit_singleline(&mut self.search_query);

            ui.separator();

            // Show offline toggle
            ui.checkbox(&mut self.show_offline, "Show offline");

            ui.separator();

            // Machine counts
            let online_count = machines.iter().filter(|m| m.online).count();
            let total_count = machines.len();
            ui.label(format!("{} online, {} total", online_count, total_count));

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("🔄 Refresh").clicked() {
                    // Refresh machines list
                }
            });
        });
    }

    fn draw_machines_table(&mut self, ui: &mut egui::Ui, machines: &[&Machine]) {
        TableBuilder::new(ui)
            .striped(true)
            .resizable(true)
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
            .column(Column::auto()) // Status
            .column(Column::remainder().at_least(120.0)) // Name
            .column(Column::remainder().at_least(100.0)) // User
            .column(Column::remainder().at_least(120.0)) // IP Address
            .column(Column::remainder().at_least(80.0))  // Connection
            .column(Column::remainder().at_least(80.0))  // Last Seen
            .header(20.0, |mut header| {
                header.col(|ui| { ui.strong("Status"); });
                header.col(|ui| { ui.strong("Name"); });
                header.col(|ui| { ui.strong("User"); });
                header.col(|ui| { ui.strong("IP Address"); });
                header.col(|ui| { ui.strong("Connection"); });
                header.col(|ui| { ui.strong("Last Seen"); });
            })
            .body(|mut body| {
                for machine in machines {
                    body.row(24.0, |mut row| {
                        // Status indicator
                        row.col(|ui| {
                            let status_color = machine.status_color();
                            let rect = ui.allocate_exact_size(
                                egui::vec2(8.0, 8.0),
                                egui::Sense::hover()
                            ).0;
                            ui.painter().circle_filled(rect.center(), 4.0, status_color);
                        });

                        // Name (clickable)
                        row.col(|ui| {
                            let response = ui.selectable_label(
                                self.selected_machine.as_ref() == Some(&machine.id),
                                &machine.name
                            );

                            if response.clicked() {
                                self.selected_machine = if self.selected_machine.as_ref() == Some(&machine.id) {
                                    None
                                } else {
                                    Some(machine.id.clone())
                                };
                            }

                            // Show hostname as subtitle
                            if !machine.hostname.is_empty() && machine.hostname != machine.name {
                                ui.small(&machine.hostname);
                            }
                        });

                        // User
                        row.col(|ui| {
                            ui.label(&machine.user);
                        });

                        // IP Address
                        row.col(|ui| {
                            if let Some(primary_ip) = machine.primary_ip() {
                                ui.monospace(primary_ip.to_string());
                            } else {
                                ui.weak_label("No IP");
                            }
                        });

                        // Connection type
                        row.col(|ui| {
                            let (text, color) = if machine.online {
                                if machine.direct_connection {
                                    ("Direct", egui::Color32::from_rgb(34, 197, 94))
                                } else {
                                    ("Relay", egui::Color32::from_rgb(251, 191, 36))
                                }
                            } else {
                                ("Offline", egui::Color32::from_rgb(156, 163, 175))
                            };

                            ui.colored_label(color, text);

                            // Show latency if available
                            if let Some(latency) = machine.latency {
                                ui.small(format!("{}ms", latency));
                            }
                        });

                        // Last seen
                        row.col(|ui| {
                            ui.small(machine.format_last_seen());
                        });
                    });
                }
            });
    }

    fn draw_empty_state(&self, ui: &mut egui::Ui) {
        ui.vertical_centered(|ui| {
            ui.add_space(50.0);

            // Icon
            ui.label("🖥️");
            ui.add_space(10.0);

            if self.search_query.is_empty() {
                ui.heading("No Machines");
                ui.label("No devices are currently connected to your GhostWire network.");
            } else {
                ui.heading("No Results");
                ui.label(format!("No machines match '{}'", self.search_query));
                if ui.button("Clear Search").clicked() {
                    // This would be handled by the parent
                }
            }
        });
    }

    fn draw_machine_details(&mut self, ui: &mut egui::Ui, machine: &Machine, routes: &[Route]) {
        ui.heading(format!("Machine Details: {}", machine.name));

        ui.add_space(10.0);

        // Basic information
        egui::Grid::new("machine_details")
            .num_columns(2)
            .spacing([20.0, 8.0])
            .show(ui, |ui| {
                ui.label("Hostname:");
                ui.label(&machine.hostname);
                ui.end_row();

                ui.label("User:");
                ui.label(&machine.user);
                ui.end_row();

                ui.label("Operating System:");
                ui.label(machine.os.as_deref().unwrap_or("Unknown"));
                ui.end_row();

                ui.label("Status:");
                let status_text = if machine.online { "Online" } else { "Offline" };
                ui.colored_label(machine.status_color(), status_text);
                ui.end_row();

                ui.label("Connection Type:");
                ui.label(machine.connection_type());
                ui.end_row();

                if let Some(latency) = machine.latency {
                    ui.label("Latency:");
                    ui.label(format!("{}ms", latency));
                    ui.end_row();
                }

                ui.label("Last Seen:");
                ui.label(machine.format_last_seen());
                ui.end_row();
            });

        ui.add_space(15.0);

        // IP Addresses
        if !machine.ip_addresses.is_empty() {
            ui.strong("IP Addresses:");
            ui.add_space(5.0);

            for ip in &machine.ip_addresses {
                ui.horizontal(|ui| {
                    ui.monospace(ip.to_string());
                    if ui.small_button("📋").on_hover_text("Copy to clipboard").clicked() {
                        ui.output_mut(|o| o.copied_text = ip.to_string());
                    }
                });
            }

            ui.add_space(15.0);
        }

        // Tags
        if !machine.tags.is_empty() {
            ui.strong("Tags:");
            ui.add_space(5.0);

            ui.horizontal_wrapped(|ui| {
                for tag in &machine.tags {
                    ui.small_button(tag);
                }
            });

            ui.add_space(15.0);
        }

        // Routes advertised by this machine
        let machine_routes: Vec<&Route> = routes
            .iter()
            .filter(|route| route.advertiser == machine.id)
            .collect();

        if !machine_routes.is_empty() {
            ui.strong("Advertised Routes:");
            ui.add_space(5.0);

            for route in machine_routes {
                ui.horizontal(|ui| {
                    ui.monospace(&route.destination);
                    let color = route.status_color();
                    let status = if route.enabled { "Enabled" } else { "Disabled" };
                    ui.colored_label(color, status);
                    if route.primary {
                        ui.small("(Primary)");
                    }
                });
            }

            ui.add_space(15.0);
        }

        // Actions
        ui.horizontal(|ui| {
            if machine.online {
                if ui.button("Ping").clicked() {
                    // Ping this machine
                }

                if ui.button("SSH").clicked() {
                    // Open SSH connection
                }
            }

            if ui.button("View Logs").clicked() {
                // View logs for this machine
            }

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("Close").clicked() {
                    self.selected_machine = None;
                }
            });
        });
    }
}