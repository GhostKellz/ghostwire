# 👻 Ghostwire

[![Built with Zig](https://img.shields.io/badge/Zig-0.15.0-orange?logo=zig)](https://ziglang.org/)
[![QUIC Enabled](https://img.shields.io/badge/QUIC-Enabled-blue?logo=cloudflare\&logoColor=white)](https://datatracker.ietf.org/doc/html/rfc9000)
[![TLS 1.3](https://img.shields.io/badge/TLS-1.3-green?logo=letsencrypt\&logoColor=white)](https://datatracker.ietf.org/doc/html/rfc8446)
[![STUN/ICE](https://img.shields.io/badge/STUN%2FICE-Supported-lightgrey?logo=webrtc\&logoColor=black)](https://datatracker.ietf.org/doc/html/rfc8445)
[![UDP First](https://img.shields.io/badge/UDP-First-brightgreen?logo=udp\&logoColor=white)]()
[![Relay Fallback](https://img.shields.io/badge/Relay%20Fallback-Supported-purple)]()
[![Mesh Ready](https://img.shields.io/badge/Mesh-Ready-blueviolet?logo=cloud\&logoColor=white)]()
[![Zero Trust](https://img.shields.io/badge/Zero%20Trust-Enabled-critical?logo=security\&logoColor=white)]()
[![Zion Package](https://img.shields.io/badge/Available%20on-Zion%20%26%20Zig%20Fetch-brightgreen?logo=zig)]()

---

# Ghostwire: Next-Gen Mesh Networking Protocol

**Ghostwire** is a fully open, high-performance VPN and mesh networking protocol written in Zig (v0.15+). Designed as the next evolution after WireGuard, Ghostwire combines:

* The speed and flexibility of QUIC
* The modern security guarantees of TLS 1.3
* Native NAT traversal (STUN/ICE)
* Full mesh, relay, and overlay support
* CLI and TUI tools for management

Ghostwire is not just a tunnel: it’s an extensible platform for overlay networking, secure remote access, and next-gen cloud/homelab mesh automation.

## 🌟 Goals & Vision

* **Zig Native & Audit-Ready:** 100% Zig for maximum safety, performance, and auditability
* **Universal NAT Traversal:** P2P whenever possible; fallback relay or TURN as last resort
* **Programmable Mesh Networking:** Pluggable mesh/overlay architecture for dynamic networks
* **Multi-Platform & Easy to Build:** Linux, BSD, macOS (Windows & mobile soon)
* **Identity & Zero Trust:** Integrate with OIDC, GhostID, and other identity providers
* **CLI and TUI Management:** Full-featured `ghostctl` CLI and TUI for config, status, mesh ops
* **Developer-Friendly:** Available via `zig fetch`, `zion fetch`, or the Zion TUI for instant integration and rapid prototyping
* **Self-Hosting & Cloud Ready:** Run anywhere—bare metal, VM, LXC, Docker, or public cloud
* **App Layer Friendly:** Multiplexed streams (like SSH + VPN + Proxy + File Transfer in one protocol)
* **Strong Community & Docs:** Open development, full docs, and modern DevOps pipeline

## 🌐 Core Features

* **QUIC Transport:** UDP-based, fully multiplexed, connection migration & fast recovery
* **TLS 1.3 Encryption:** End-to-end for all data and control channels
* **STUN/ICE NAT Traversal:** Direct peer-to-peer when possible
* **Relay/TURN Fallback:** Always-connected, even behind hard NAT/firewalls
* **Mesh Overlay:** Decentralized, peer-discovered, and programmable networking
* **Zero Trust Design:** Encrypted control plane, identity, and access controls at core
* **Plug & Play Integration:** Easy to embed in Zig, Rust, or other mesh stacks

## 🚀 Protocols Used

* [QUIC (RFC 9000)](https://datatracker.ietf.org/doc/html/rfc9000)
* [TLS 1.3 (RFC 8446)](https://datatracker.ietf.org/doc/html/rfc8446)
* [STUN (RFC 5389)](https://datatracker.ietf.org/doc/html/rfc5389)
* [ICE (RFC 8445)](https://datatracker.ietf.org/doc/html/rfc8445)
* [UDP/TCP (Transport)](https://en.wikipedia.org/wiki/User_Datagram_Protocol)

## 🏗️ Architecture Overview

Ghostwire is designed for composability and modularity. The architecture consists of layered components that allow you to build a programmable mesh and zero trust overlay, with ghostmesh as the overlay manager sitting above ghostwire as the secure transport protocol and Zig library.

### **Layered Architecture**

* **ghostmesh** – Overlay/mesh manager

  * Orchestrates topology, peer discovery, relays, ACLs, mesh health, DNS/proxy, SSO, and provides a programmable API for automation and control.
  * Manages relay deployment (DERP/TURN-style) and handles mesh state, user access, and overlay services.

* **ghostwire** – Secure, next-gen wire protocol & Zig networking library

  * Handles encrypted tunneling, P2P connections, NAT traversal, relays, and multiplexing.

  * Direct replacement for WireGuard, but with modern protocols and more flexibility.

  * **ghostwire-core** – Protocol logic, handshake, multiplexed tunnels, crypto primitives

  * **ghostwire-transport** – QUIC, UDP/TCP, relay fallback, congestion control

  * **ghostwire-ice** – STUN/ICE NAT traversal for P2P connectivity

  * **ghostwire-control** – Secure control plane for tunnel management, mesh ops, identity, and peer-to-peer signaling

* **Relay Service** – Built-in DERP/TURN relay fallback for maximum connectivity

* **ghostctl** – Zig CLI for configuring, managing, and debugging both ghostwire and ghostmesh

* **ghostctl tui** – Terminal UI for real-time mesh visualization, peer management, and logs

* **zion integration** – Available via `zig fetch`, `zion fetch`, and the Zion TUI

---

Ghostwire is available via:

* `zig fetch --saved https://github.com/ghostkellz/ghostwire` (Zig package manager)
* `zion fetch ghostwire` (Zion ecosystem)
* Zion TUI app store

> *Build, run, and connect guides coming soon!*

## ✨ Status

**Alpha** – Actively developed. Early adopters & contributors wanted!

## 🛠️ Requirements

* **Zig v0.15.0+**
* Linux, BSD, macOS, Windows

## 💬 Contributing & Community

* Open roadmap, feature requests, and transparent development
* Planned Discord and Matrix channels for contributors
* Issues and PRs welcome on GitHub and Zion registry

## 📝 License

MIT or Apache 2.0 (TBD)

---

**Ghostwire is the programmable, next-gen mesh/VPN/overlay protocol for homelabbers, hackers, and cloud-native architects.**

---

