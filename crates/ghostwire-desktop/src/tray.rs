/// System tray integration for GhostWire Desktop
///
/// Provides system tray icon, menu, and notifications for seamless background operation.

use std::sync::Arc;
use tokio::sync::RwLock;
use tray_icon::{TrayIcon, TrayIconBuilder, TrayIconEvent, menu::{Menu, MenuItem, PredefinedMenuItem}};
use tracing::{info, error};

use crate::app::GhostWireApp;
use crate::types::{TrayAction, ConnectionStatus};

pub struct SystemTray {
    _tray_icon: TrayIcon,
    app_state: Arc<RwLock<GhostWireApp>>,
}

impl SystemTray {
    pub fn new(app_state: Arc<RwLock<GhostWireApp>>) -> Result<Self, Box<dyn std::error::Error>> {
        // Create tray menu
        let menu = Self::create_menu()?;

        // Create tray icon
        let icon = Self::load_tray_icon();
        let tray_icon = TrayIconBuilder::new()
            .with_menu(Box::new(menu))
            .with_tooltip("GhostWire")
            .with_icon(icon)
            .build()?;

        // Handle tray events
        let app_clone = app_state.clone();
        TrayIconEvent::set_event_handler(Some(Box::new(move |event| {
            Self::handle_tray_event(event, app_clone.clone());
        })));

        info!("System tray initialized successfully");

        Ok(Self {
            _tray_icon: tray_icon,
            app_state,
        })
    }

    fn create_menu() -> Result<Menu, Box<dyn std::error::Error>> {
        let menu = Menu::new();

        // Connection status (will be updated dynamically)
        let status_item = MenuItem::new("Status: Disconnected", false, None);
        menu.append(&status_item)?;

        menu.append(&PredefinedMenuItem::separator())?;

        // Main actions
        let show_item = MenuItem::new("Show GhostWire", true, None);
        let connect_item = MenuItem::new("Connect", true, None);
        let disconnect_item = MenuItem::new("Disconnect", false, None);

        menu.append(&show_item)?;
        menu.append(&connect_item)?;
        menu.append(&disconnect_item)?;

        menu.append(&PredefinedMenuItem::separator())?;

        // Settings and help
        let settings_item = MenuItem::new("Settings...", true, None);
        let about_item = MenuItem::new("About GhostWire", true, None);

        menu.append(&settings_item)?;
        menu.append(&about_item)?;

        menu.append(&PredefinedMenuItem::separator())?;

        // Quit
        let quit_item = MenuItem::new("Quit", true, None);
        menu.append(&quit_item)?;

        Ok(menu)
    }

    fn load_tray_icon() -> tray_icon::Icon {
        // Create a simple icon programmatically
        // In a real app, this would load from embedded resources
        let icon_size = 16;
        let mut rgba = Vec::with_capacity(icon_size * icon_size * 4);

        for y in 0..icon_size {
            for x in 0..icon_size {
                // Create a simple circular icon with gradient
                let center_x = icon_size as f32 / 2.0;
                let center_y = icon_size as f32 / 2.0;
                let distance = ((x as f32 - center_x).powi(2) + (y as f32 - center_y).powi(2)).sqrt();
                let radius = icon_size as f32 / 2.0 - 1.0;

                if distance <= radius {
                    // Inside circle - create gradient
                    let intensity = (1.0 - distance / radius * 0.5) * 255.0;
                    rgba.extend_from_slice(&[
                        50,  // R - blue-ish
                        100, // G
                        (intensity as u8).min(255), // B
                        255, // A
                    ]);
                } else {
                    // Outside circle - transparent
                    rgba.extend_from_slice(&[0, 0, 0, 0]);
                }
            }
        }

        tray_icon::Icon::from_rgba(rgba, icon_size as u32, icon_size as u32)
            .unwrap_or_else(|_| {
                // Fallback to a simple colored square
                let fallback_rgba = vec![50, 100, 200, 255; icon_size * icon_size];
                tray_icon::Icon::from_rgba(fallback_rgba, icon_size as u32, icon_size as u32)
                    .expect("Failed to create fallback icon")
            })
    }

    fn handle_tray_event(event: TrayIconEvent, app_state: Arc<RwLock<GhostWireApp>>) {
        match event {
            TrayIconEvent::Click { button, button_state, .. } => {
                if button == tray_icon::mouse::MouseButton::Left
                    && button_state == tray_icon::mouse::MouseButtonState::Up {
                    // Left click - show/hide window
                    Self::execute_action(TrayAction::ShowWindow, app_state);
                }
            }
            TrayIconEvent::DoubleClick { button, .. } => {
                if button == tray_icon::mouse::MouseButton::Left {
                    // Double click - show window
                    Self::execute_action(TrayAction::ShowWindow, app_state);
                }
            }
            TrayIconEvent::MenuEvent { id } => {
                // Handle menu item clicks
                Self::handle_menu_event(id, app_state);
            }
            _ => {}
        }
    }

    fn handle_menu_event(menu_id: tray_icon::menu::MenuId, app_state: Arc<RwLock<GhostWireApp>>) {
        // In a real implementation, we'd match against known menu item IDs
        // For now, we'll use string comparison (not ideal but works for demo)
        info!("Tray menu item clicked: {:?}", menu_id);

        // This is a simplified approach - in practice you'd store menu item IDs
        // and match against them properly
        Self::execute_action(TrayAction::ShowWindow, app_state);
    }

    fn execute_action(action: TrayAction, app_state: Arc<RwLock<GhostWireApp>>) {
        match action {
            TrayAction::ShowWindow => {
                info!("Showing main window from tray");
                // In a real implementation, this would show the hidden window
            }
            TrayAction::HideWindow => {
                info!("Hiding main window to tray");
            }
            TrayAction::Connect => {
                info!("Connecting from tray");
                // Trigger connection
            }
            TrayAction::Disconnect => {
                info!("Disconnecting from tray");
                // Trigger disconnection
            }
            TrayAction::Quit => {
                info!("Quitting application from tray");
                std::process::exit(0);
            }
            TrayAction::ToggleNotifications => {
                info!("Toggling notifications from tray");
            }
        }
    }

    pub fn update_status(&self, status: &ConnectionStatus) {
        // Update tray icon and menu based on connection status
        let (tooltip, _icon_variant) = match status {
            ConnectionStatus::Connected(_) => ("GhostWire - Connected", "connected"),
            ConnectionStatus::Connecting => ("GhostWire - Connecting...", "connecting"),
            ConnectionStatus::Disconnected => ("GhostWire - Disconnected", "disconnected"),
            ConnectionStatus::Error(_) => ("GhostWire - Error", "error"),
        };

        // Update tooltip
        if let Err(e) = self._tray_icon.set_tooltip(Some(tooltip)) {
            error!("Failed to update tray tooltip: {}", e);
        }

        // In a real implementation, we'd also update the icon and menu items
        info!("Tray status updated: {}", tooltip);
    }

    pub fn show_notification(&self, title: &str, message: &str) {
        // Show system notification
        #[cfg(feature = "notifications")]
        {
            use notify_rust::Notification;

            if let Err(e) = Notification::new()
                .summary(title)
                .body(message)
                .icon("ghostwire")
                .timeout(notify_rust::Timeout::Milliseconds(5000))
                .show()
            {
                error!("Failed to show notification: {}", e);
            }
        }

        #[cfg(not(feature = "notifications"))]
        {
            info!("Notification: {} - {}", title, message);
        }
    }
}

// Platform-specific implementations
#[cfg(target_os = "windows")]
mod windows {
    use winapi::um::winuser::{ShowWindow, FindWindowA, SW_SHOW, SW_HIDE};
    use std::ffi::CString;

    pub fn show_window() {
        unsafe {
            let window_title = CString::new("GhostWire").unwrap();
            let hwnd = FindWindowA(std::ptr::null(), window_title.as_ptr());
            if !hwnd.is_null() {
                ShowWindow(hwnd, SW_SHOW);
            }
        }
    }

    pub fn hide_window() {
        unsafe {
            let window_title = CString::new("GhostWire").unwrap();
            let hwnd = FindWindowA(std::ptr::null(), window_title.as_ptr());
            if !hwnd.is_null() {
                ShowWindow(hwnd, SW_HIDE);
            }
        }
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use cocoa::appkit::{NSApp, NSApplication, NSApplicationActivationPolicy};
    use objc::{msg_send, sel, sel_impl};

    pub fn show_window() {
        unsafe {
            let app: cocoa::base::id = NSApp();
            let _: () = msg_send![app, setActivationPolicy: NSApplicationActivationPolicy::NSApplicationActivationPolicyRegular];
            let _: () = msg_send![app, activateIgnoringOtherApps: true];
        }
    }

    pub fn hide_window() {
        unsafe {
            let app: cocoa::base::id = NSApp();
            let _: () = msg_send![app, setActivationPolicy: NSApplicationActivationPolicy::NSApplicationActivationPolicyAccessory];
        }
    }
}

#[cfg(target_os = "linux")]
mod linux {
    pub fn show_window() {
        // Linux window management would go here
        // This typically involves communicating with the window manager
    }

    pub fn hide_window() {
        // Linux window hiding would go here
    }
}