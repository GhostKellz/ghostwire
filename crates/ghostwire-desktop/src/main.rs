/// GhostWire Desktop Client
///
/// Native cross-platform desktop client with system tray integration.
/// Provides a beautiful GUI for managing GhostWire mesh VPN connections.

use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, error};

mod app;
mod config;
mod tray;
mod ui;
mod client;
mod utils;
mod types;

use app::GhostWireApp;
use config::AppConfig;
use tray::SystemTray;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    info!("Starting GhostWire Desktop Client v{}", env!("CARGO_PKG_VERSION"));

    // Load configuration
    let config = AppConfig::load().await?;
    info!("Loaded configuration from {}", config.config_path.display());

    // Initialize the app state
    let app_state = Arc::new(RwLock::new(GhostWireApp::new(config).await?));

    // Initialize system tray (before GUI for better UX)
    let tray = SystemTray::new(app_state.clone())?;

    // Check if we should start minimized to tray
    let should_show_window = !std::env::args().any(|arg| arg == "--minimized");

    if should_show_window {
        // Run the GUI
        let options = eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default()
                .with_inner_size([1200.0, 800.0])
                .with_min_inner_size([800.0, 600.0])
                .with_icon(load_icon())
                .with_title("GhostWire")
                .with_resizable(true),
            ..Default::default()
        };

        // Clone the app state for the GUI
        let gui_state = app_state.clone();

        eframe::run_native(
            "GhostWire",
            options,
            Box::new(move |cc| {
                setup_custom_fonts(&cc.egui_ctx);
                Ok(Box::new(AppWrapper::new(gui_state)))
            }),
        )?;
    } else {
        info!("Starting in tray-only mode");
        // Keep the application running in tray mode
        tokio::signal::ctrl_c().await?;
    }

    Ok(())
}

/// Wrapper to integrate async app state with egui
struct AppWrapper {
    app_state: Arc<RwLock<GhostWireApp>>,
    runtime: tokio::runtime::Handle,
}

impl AppWrapper {
    fn new(app_state: Arc<RwLock<GhostWireApp>>) -> Self {
        Self {
            app_state,
            runtime: tokio::runtime::Handle::current(),
        }
    }
}

impl eframe::App for AppWrapper {
    fn update(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
        // Handle window close to minimize to tray instead of exiting
        if frame.info().events.contains(&egui::Event::WindowClosed) {
            frame.close();
            return;
        }

        // Update the app with blocking call to async state
        if let Ok(mut app) = self.app_state.try_write() {
            app.update(ctx, frame);
        }

        // Request repaint for animations and real-time updates
        ctx.request_repaint_after(std::time::Duration::from_millis(100));
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        info!("GhostWire Desktop shutting down");
    }
}

/// Load application icon
fn load_icon() -> egui::IconData {
    // In a real app, this would load from resources
    // For now, create a simple colored icon
    let icon_size = 32;
    let mut rgba = Vec::with_capacity(icon_size * icon_size * 4);

    for y in 0..icon_size {
        for x in 0..icon_size {
            let r = ((x as f32 / icon_size as f32) * 255.0) as u8;
            let g = ((y as f32 / icon_size as f32) * 255.0) as u8;
            let b = 200u8;
            let a = if (x - icon_size/2).pow(2) + (y - icon_size/2).pow(2) < (icon_size/2).pow(2) { 255 } else { 0 };

            rgba.extend_from_slice(&[r, g, b, a]);
        }
    }

    egui::IconData {
        rgba,
        width: icon_size as u32,
        height: icon_size as u32,
    }
}

/// Setup custom fonts for better UI
fn setup_custom_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();

    // Add system fonts for better native look
    #[cfg(target_os = "windows")]
    {
        fonts.font_data.insert(
            "segoe_ui".to_owned(),
            egui::FontData::from_static(include_bytes!("../assets/fonts/SegoeUI.ttf")).unwrap_or_default(),
        );
        fonts.families.get_mut(&egui::FontFamily::Proportional).unwrap()
            .insert(0, "segoe_ui".to_owned());
    }

    #[cfg(target_os = "macos")]
    {
        fonts.font_data.insert(
            "sf_pro".to_owned(),
            egui::FontData::from_static(include_bytes!("../assets/fonts/SFPro.ttf")).unwrap_or_default(),
        );
        fonts.families.get_mut(&egui::FontFamily::Proportional).unwrap()
            .insert(0, "sf_pro".to_owned());
    }

    // Add mono font for IPs and keys
    fonts.font_data.insert(
        "fira_code".to_owned(),
        egui::FontData::from_static(include_bytes!("../assets/fonts/FiraCode.ttf")).unwrap_or_default(),
    );
    fonts.families.get_mut(&egui::FontFamily::Monospace).unwrap()
        .insert(0, "fira_code".to_owned());

    ctx.set_fonts(fonts);

    // Setup custom theme
    let mut style = (*ctx.style()).clone();

    // Modern rounded corners
    style.visuals.window_rounding = egui::Rounding::same(12.0);
    style.visuals.button_rounding = egui::Rounding::same(8.0);
    style.visuals.menu_rounding = egui::Rounding::same(8.0);

    // Better spacing
    style.spacing.item_spacing = egui::vec2(8.0, 6.0);
    style.spacing.button_padding = egui::vec2(12.0, 8.0);
    style.spacing.window_margin = egui::style::Margin::same(12.0);

    // Colors inspired by modern VPN clients
    style.visuals.extreme_bg_color = egui::Color32::from_rgb(248, 250, 252);
    style.visuals.faint_bg_color = egui::Color32::from_rgb(241, 245, 249);

    ctx.set_style(style);
}