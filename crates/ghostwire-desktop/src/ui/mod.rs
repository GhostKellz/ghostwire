/// UI modules for GhostWire Desktop
///
/// Contains all UI panels and components for the desktop application.

pub mod connection;
pub mod machines;
pub mod settings;
pub mod about;

pub use connection::ConnectionPanel;
pub use machines::MachinesPanel;
pub use settings::SettingsPanel;
pub use about::AboutPanel;