/// About panel UI for GhostWire Desktop
///
/// Displays application information, credits, and links.

pub struct AboutPanel;

impl AboutPanel {
    pub fn new() -> Self {
        Self
    }

    pub fn draw(&self, ui: &mut egui::Ui) {
        ui.vertical_centered(|ui| {
            // App icon/logo
            ui.add_space(20.0);
            ui.label("🔗"); // In a real app, this would be an actual logo
            ui.add_space(10.0);

            // App name and version
            ui.heading("GhostWire Desktop");
            ui.label(format!("Version {}", env!("CARGO_PKG_VERSION")));

            ui.add_space(20.0);

            // Description
            ui.label("Secure mesh VPN client for modern networks");
            ui.add_space(10.0);
            ui.small("Built with Rust, egui, and ❤️");

            ui.add_space(30.0);
        });

        // Information sections
        ui.group(|ui| {
            ui.strong("About GhostWire");
            ui.add_space(5.0);
            ui.label("GhostWire is a modern mesh VPN solution that creates secure, point-to-point connections between your devices. It combines the simplicity of modern VPN tools with the power of mesh networking.");
        });

        ui.add_space(15.0);

        ui.group(|ui| {
            ui.strong("Features");
            ui.add_space(5.0);

            let features = [
                "Zero-configuration mesh networking",
                "End-to-end encryption with WireGuard",
                "Automatic NAT traversal and hole punching",
                "DERP relay fallback for difficult networks",
                "Cross-platform support (Windows, macOS, Linux)",
                "Web-based administration interface",
                "Fine-grained access control policies",
            ];

            for feature in &features {
                ui.horizontal(|ui| {
                    ui.label("•");
                    ui.label(*feature);
                });
            }
        });

        ui.add_space(15.0);

        // Links and actions
        ui.group(|ui| {
            ui.strong("Links");
            ui.add_space(5.0);

            ui.horizontal(|ui| {
                if ui.link("Website").clicked() {
                    // Open website
                }
                ui.label("•");
                if ui.link("Documentation").clicked() {
                    // Open documentation
                }
                ui.label("•");
                if ui.link("GitHub").clicked() {
                    // Open GitHub repository
                }
                ui.label("•");
                if ui.link("Support").clicked() {
                    // Open support page
                }
            });
        });

        ui.add_space(15.0);

        // System information
        ui.group(|ui| {
            ui.strong("System Information");
            ui.add_space(5.0);

            egui::Grid::new("system_info")
                .num_columns(2)
                .spacing([20.0, 5.0])
                .show(ui, |ui| {
                    ui.label("Platform:");
                    ui.label(env!("TARGET_OS"));
                    ui.end_row();

                    ui.label("Architecture:");
                    ui.label(env!("TARGET_ARCH"));
                    ui.end_row();

                    ui.label("Rust Version:");
                    ui.label(env!("RUSTC_VERSION"));
                    ui.end_row();

                    #[cfg(debug_assertions)]
                    {
                        ui.label("Build Type:");
                        ui.label("Debug");
                        ui.end_row();
                    }

                    #[cfg(not(debug_assertions))]
                    {
                        ui.label("Build Type:");
                        ui.label("Release");
                        ui.end_row();
                    }
                });
        });

        ui.add_space(15.0);

        // Copyright and license
        ui.group(|ui| {
            ui.strong("License");
            ui.add_space(5.0);
            ui.small("Copyright © 2024 GhostWire Team");
            ui.small("Licensed under the MIT OR Apache-2.0 license");
            ui.add_space(5.0);

            if ui.link("View License").clicked() {
                // Show license text
            }
        });

        ui.add_space(15.0);

        // Credits
        ui.group(|ui| {
            ui.strong("Built With");
            ui.add_space(5.0);

            let credits = [
                ("Rust", "Systems programming language"),
                ("egui", "Immediate mode GUI framework"),
                ("tokio", "Asynchronous runtime"),
                ("WireGuard", "VPN protocol"),
                ("QUIC", "Transport protocol"),
                ("tray-icon", "System tray integration"),
            ];

            for (name, description) in &credits {
                ui.horizontal(|ui| {
                    ui.small("•");
                    ui.small(format!("{}: {}", name, description));
                });
            }
        });

        ui.add_space(20.0);

        // Action buttons
        ui.horizontal(|ui| {
            if ui.button("Check for Updates").clicked() {
                // Check for updates
            }

            if ui.button("Report Issue").clicked() {
                // Open issue tracker
            }

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("Copy System Info").clicked() {
                    let system_info = format!(
                        "GhostWire Desktop v{}\nPlatform: {}\nArchitecture: {}\nRust: {}",
                        env!("CARGO_PKG_VERSION"),
                        env!("TARGET_OS"),
                        env!("TARGET_ARCH"),
                        env!("RUSTC_VERSION")
                    );
                    ui.output_mut(|o| o.copied_text = system_info);
                }
            });
        });
    }
}