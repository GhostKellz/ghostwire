
  Web Admin (Coordination Server): Leptos + WASM ✅

  Why Leptos over Yew:
  - Better Axum integration - We're already using Axum, Leptos has first-class SSR support
  - Modern reactive system - Signals-based like SolidJS, better than Yew's component updates
  - SSR + Hydration - Fast initial loads, then full WASM interactivity
  - Shared types - Can share Rust types between server/client easily
  - Better performance - Fine-grained reactivity vs virtual DOM
  - Growing ecosystem - More momentum than Yew currently

  Client GUI: egui + eframe ✅

  Perfect choice because:
  - Native performance - No web overhead for system-level app
  - Cross-platform - Windows, Mac, Linux with single codebase
  - System tray integration - Perfect for VPN clients
  - Immediate mode - Easier state management than retained mode
  - Rust ecosystem - Great integration with our WireGuard engine

  🏗️ Architecture Plan

  ┌─────────────────────────────────────────┐
  │           GhostWire Ecosystem           │
  ├─────────────────────────────────────────┤
  │  Web Admin (Leptos + WASM)             │
  │  ├─ SSR dashboard pages                 │
  │  ├─ WASM interactive components         │
  │  ├─ Real-time node status               │
  │  └─ Policy editor with syntax highlight │
  ├─────────────────────────────────────────┤
  │  Server (Axum + zqlite)                │
  │  ├─ REST API for web admin              │
  │  ├─ gRPC for clients                    │
  │  ├─ WebSocket for real-time updates     │
  │  └─ Static file serving for web admin   │
  ├─────────────────────────────────────────┤
  │  Desktop Client (egui + eframe)        │
  │  ├─ System tray with status             │
  │  ├─ Connection management UI            │
  │  ├─ Route configuration                 │
  │  └─ Built-in log viewer                 │
  └─────────────────────────────────────────┘

  📦 Workspace Structure

  [workspace]
  members = [
      # ... existing crates
      "crates/ghostwire-web-admin",  # Leptos web admin
      "crates/ghostwire-gui",        # egui client GUI
  ]

  [workspace.dependencies]
  # Web admin dependencies
  leptos = "0.6"
  leptos_axum = "0.6"
  leptos_meta = "0.6"
  leptos_router = "0.6"

  # GUI client dependencies  
  egui = "0.28"
  eframe = "0.28"
  tray-icon = "0.14"
