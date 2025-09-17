/// GhostWire Web Admin Interface
///
/// Modern Leptos-based web UI for comprehensive mesh VPN management.
/// Inspired by headplane's excellent UX patterns, built with Rust and WebAssembly.

pub mod app;
pub mod components;
pub mod pages;
pub mod api;
pub mod auth;
pub mod types;
pub mod utils;

#[cfg(feature = "hydrate")]
use wasm_bindgen::prelude::wasm_bindgen;

#[cfg(feature = "hydrate")]
#[wasm_bindgen]
pub fn hydrate() {
    use crate::app::*;
    console_error_panic_hook::set_once();
    leptos::mount_to_body(App);
}