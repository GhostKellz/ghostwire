/// Connection panel UI for GhostWire Desktop
///
/// Displays connection status, network information, and connection controls.

use egui_plot::{Line, Plot, Points, PlotPoints};
use std::collections::VecDeque;
use chrono::{DateTime, Utc};

use crate::types::{ConnectionStatus, NetworkStats};

pub struct ConnectionPanel {
    bandwidth_history: VecDeque<BandwidthPoint>,
    max_history_points: usize,
}

#[derive(Clone)]
struct BandwidthPoint {
    timestamp: DateTime<Utc>,
    upload: f64,
    download: f64,
}

impl ConnectionPanel {
    pub fn new() -> Self {
        Self {
            bandwidth_history: VecDeque::new(),
            max_history_points: 60, // 1 minute of data at 1 second intervals
        }
    }

    pub fn draw(&mut self, ui: &mut egui::Ui, status: &ConnectionStatus, stats: &NetworkStats) {
        ui.heading("Connection");

        // Connection status card
        ui.add_space(10.0);
        self.draw_status_card(ui, status);

        ui.add_space(20.0);

        // Network statistics
        if matches!(status, ConnectionStatus::Connected(_)) {
            self.draw_network_stats(ui, stats);
            ui.add_space(20.0);
            self.draw_bandwidth_chart(ui, stats);
        } else {
            self.draw_disconnected_view(ui);
        }
    }

    fn draw_status_card(&self, ui: &mut egui::Ui, status: &ConnectionStatus) {
        egui::Frame::none()
            .fill(ui.style().visuals.faint_bg_color)
            .rounding(egui::Rounding::same(8.0))
            .inner_margin(egui::style::Margin::same(16.0))
            .show(ui, |ui| {
                match status {
                    ConnectionStatus::Connected(info) => {
                        ui.horizontal(|ui| {
                            // Status indicator
                            let rect = ui.allocate_exact_size(
                                egui::vec2(12.0, 12.0),
                                egui::Sense::hover()
                            ).0;
                            ui.painter().circle_filled(
                                rect.center(),
                                6.0,
                                egui::Color32::from_rgb(34, 197, 94)
                            );

                            ui.vertical(|ui| {
                                ui.heading("Connected");
                                ui.label(format!("Server: {}", info.server_url));
                                ui.label(format!("Local IP: {}", info.local_ip));
                                if let Some(latency) = info.latency {
                                    ui.label(format!("Latency: {}ms", latency));
                                }
                                ui.label(format!("Connected since: {}",
                                    info.connected_at.format("%H:%M:%S")
                                ));
                            });

                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                if ui.button("Disconnect").clicked() {
                                    // Handle disconnect
                                }
                            });
                        });
                    }
                    ConnectionStatus::Connecting => {
                        ui.horizontal(|ui| {
                            ui.spinner();
                            ui.vertical(|ui| {
                                ui.heading("Connecting...");
                                ui.label("Establishing connection to GhostWire network");
                            });

                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                if ui.button("Cancel").clicked() {
                                    // Handle cancel
                                }
                            });
                        });
                    }
                    ConnectionStatus::Disconnected => {
                        ui.horizontal(|ui| {
                            let rect = ui.allocate_exact_size(
                                egui::vec2(12.0, 12.0),
                                egui::Sense::hover()
                            ).0;
                            ui.painter().circle_filled(
                                rect.center(),
                                6.0,
                                egui::Color32::from_rgb(156, 163, 175)
                            );

                            ui.vertical(|ui| {
                                ui.heading("Disconnected");
                                ui.label("Not connected to GhostWire network");
                            });

                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                if ui.button("Connect").clicked() {
                                    // Handle connect
                                }
                            });
                        });
                    }
                    ConnectionStatus::Error(err) => {
                        ui.horizontal(|ui| {
                            let rect = ui.allocate_exact_size(
                                egui::vec2(12.0, 12.0),
                                egui::Sense::hover()
                            ).0;
                            ui.painter().circle_filled(
                                rect.center(),
                                6.0,
                                egui::Color32::from_rgb(239, 68, 68)
                            );

                            ui.vertical(|ui| {
                                ui.heading("Connection Error");
                                ui.colored_label(egui::Color32::RED, err);
                            });

                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                if ui.button("Retry").clicked() {
                                    // Handle retry
                                }
                            });
                        });
                    }
                }
            });
    }

    fn draw_network_stats(&self, ui: &mut egui::Ui, stats: &NetworkStats) {
        ui.heading("Network Statistics");

        egui::Grid::new("network_stats")
            .num_columns(2)
            .spacing([20.0, 8.0])
            .show(ui, |ui| {
                // Upload stats
                ui.label("Upload:");
                ui.label(format_bytes(stats.bytes_sent));
                ui.end_row();

                ui.label("Download:");
                ui.label(format_bytes(stats.bytes_received));
                ui.end_row();

                ui.label("Packets Sent:");
                ui.label(stats.packets_sent.to_string());
                ui.end_row();

                ui.label("Packets Received:");
                ui.label(stats.packets_received.to_string());
                ui.end_row();

                ui.label("Active Connections:");
                ui.label(stats.connections_active.to_string());
                ui.end_row();

                if let Some(handshake) = stats.last_handshake {
                    ui.label("Last Handshake:");
                    ui.label(format_relative_time(handshake));
                    ui.end_row();
                }
            });
    }

    fn draw_bandwidth_chart(&mut self, ui: &mut egui::Ui, stats: &NetworkStats) {
        ui.heading("Bandwidth Usage");

        // Update bandwidth history
        self.update_bandwidth_history(stats);

        // Create plot
        let plot = Plot::new("bandwidth_plot")
            .height(200.0)
            .show_x(false)
            .show_y(true)
            .allow_zoom(false)
            .allow_drag(false)
            .allow_scroll(false);

        plot.show(ui, |plot_ui| {
            if !self.bandwidth_history.is_empty() {
                // Upload line
                let upload_points: PlotPoints = self.bandwidth_history
                    .iter()
                    .enumerate()
                    .map(|(i, point)| [i as f64, point.upload])
                    .collect();

                let upload_line = Line::new(upload_points)
                    .color(egui::Color32::from_rgb(59, 130, 246))
                    .name("Upload");

                // Download line
                let download_points: PlotPoints = self.bandwidth_history
                    .iter()
                    .enumerate()
                    .map(|(i, point)| [i as f64, point.download])
                    .collect();

                let download_line = Line::new(download_points)
                    .color(egui::Color32::from_rgb(34, 197, 94))
                    .name("Download");

                plot_ui.line(upload_line);
                plot_ui.line(download_line);
            }
        });

        // Legend
        ui.horizontal(|ui| {
            ui.colored_label(egui::Color32::from_rgb(59, 130, 246), "● Upload");
            ui.colored_label(egui::Color32::from_rgb(34, 197, 94), "● Download");
        });
    }

    fn draw_disconnected_view(&self, ui: &mut egui::Ui) {
        ui.vertical_centered(|ui| {
            ui.add_space(50.0);

            // Large icon or illustration
            ui.label("🔗");
            ui.add_space(10.0);

            ui.heading("Not Connected");
            ui.label("Connect to your GhostWire network to see statistics and manage devices.");

            ui.add_space(20.0);

            if ui.button("Connect Now").clicked() {
                // Handle connect
            }
        });
    }

    fn update_bandwidth_history(&mut self, stats: &NetworkStats) {
        // In a real implementation, this would calculate rate from previous stats
        let now = Utc::now();
        let upload_rate = stats.bytes_sent as f64 / 1024.0; // KB/s (simplified)
        let download_rate = stats.bytes_received as f64 / 1024.0; // KB/s (simplified)

        self.bandwidth_history.push_back(BandwidthPoint {
            timestamp: now,
            upload: upload_rate,
            download: download_rate,
        });

        // Keep only recent history
        while self.bandwidth_history.len() > self.max_history_points {
            self.bandwidth_history.pop_front();
        }
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

fn format_relative_time(time: DateTime<Utc>) -> String {
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