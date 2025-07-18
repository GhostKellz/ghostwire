🏗️ Architecture Overview

Ghostwire is designed for composability and modularity. The architecture consists of layered components that allow you to build a programmable mesh and zero trust overlay, with ghostmesh as the overlay manager sitting above ghostwire as the secure transport protocol and Zig library.
Layered Architecture

    ghostmesh – Overlay/mesh manager
    Orchestrates topology, peer discovery, relays, ACLs, mesh health, DNS/proxy, SSO, and provides a programmable API for automation and control.
    Manages relay deployment (DERP/TURN-style) and handles mesh state, user access, and overlay services.

    ghostwire – Secure, next-gen wire protocol & Zig networking library
    Handles encrypted tunneling, P2P connections, NAT traversal, relays, and multiplexing.
    Direct replacement for WireGuard, but with modern protocols and more flexibility.

        ghostwire-core – Protocol logic, handshake, multiplexed tunnels, crypto primitives

        ghostwire-transport – QUIC, UDP/TCP, relay fallback, congestion control

        ghostwire-ice – STUN/ICE NAT traversal for P2P connectivity

        ghostwire-control – Secure control plane for tunnel management, mesh ops, identity, and peer-to-peer signaling

    Relay Service –  DERP/TURN relay fallback for maximum connectivity

    ghostctl – Zig CLI for configuring, managing, and debugging both ghostwire and ghostmesh

    ghostctl tui – Terminal UI for real-time mesh visualization, peer management, and logs

    zion integration – Available via zig fetch, zion fetch, and the Zion TUI

