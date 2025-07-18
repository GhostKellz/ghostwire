# 🚦 Ghostwire Relay Architecture

A reference and roadmap for building modern relays for the Ghostwire mesh protocol, with a focus on **QUIC-native multiplexed relays** and future-proofing with **MASQUE/HTTP/3 tunneling**.

---

## Goals

* Universal fallback when direct P2P fails (NAT/firewall traversal)
* Multiplex multiple tunnels and app streams per relay connection
* Fast, secure, and zero trust by default
* Support several relay strategies:

  * QUIC-native (preferred)
  * MASQUE/HTTP/3 tunneling (optional/next-gen)
  * TURN/DERP (compatibility/fallback)
  * WebSocket/HTTP(S) (stealth/last resort)
* Programmable and dynamically orchestrated by ghostmesh overlay

---

## Relay Types & Plan

### 1. QUIC-Native Multiplexed Relay

* Relay server runs a QUIC endpoint
* Clients connect with authenticated QUIC sessions
* Supports:

  * Multiple concurrent encrypted tunnels (multiplexed streams)
  * Forwarding UDP, TCP, and mesh/app channels
  * Per-peer access control, logging, metrics
* **Protocol:** QUIC transport, Ghostwire message framing, mesh state propagation

### 2. MASQUE/HTTP/3 Tunnel Relay (Optional, Cutting Edge)

* Implements [MASQUE](https://datatracker.ietf.org/doc/html/draft-ietf-masque-protocol) standard for tunneling IP/UDP over HTTP/3
* Enables relays to double as HTTP/3 proxies for stealth, split tunneling, or app-layer relay
* Integrates with existing HTTP/3 infra (Cloudflare, NGINX, Envoy)
* **Protocol:** HTTP/3/QUIC, MASQUE Connect-UDP/Connect-IP

### 3. TURN/DERP-Style UDP Relay (Fallback)

* Standard UDP packet relay for compatibility with legacy NAT traversal
* Simple, battle-tested, and required for some networks
* **Protocol:** STUN/TURN/DERP

### 4. WebSocket/HTTP(S) Proxy (Ultimate Stealth/Fallback)

* Tunnels Ghostwire data over WebSocket or HTTP(S)
* For restrictive or enterprise/captive networks
* Higher overhead, but reliable for “works everywhere” connectivity
* **Protocol:** WebSocket framing, HTTP/HTTPS, possibly via third-party proxies

---

## Modular Implementation Plan

* All relays will live in `ghostwire-relay` as a library and/or service
* ghostmesh will discover, deploy, and orchestrate relays (auto-fallback, geo-distributed, ephemeral)
* Each relay mode will be modular and selectable at runtime
* CLI: `ghostctl relay` to run or manage relay nodes
* TUI: relay status, live connections, relay health metrics

---

## Example QUIC Relay Flow

1. Client connects to relay over QUIC (optionally, HTTP/3/MASQUE)
2. Auth handshake (identity, mesh token, Zero Trust checks)
3. Multiplexed streams for each peer or tunnel
4. Relay forwards packets, manages session, applies policies
5. Mesh/overlay can orchestrate, load-balance, or promote/demote relays

---

## Stretch/Future Goals

* MASQUE/HTTP/3 as primary relay for stealth, split-tunnel, app-aware routing
* Distributed relay mesh (mesh nodes can promote themselves to relays)
* Native support for SSO, metrics, dynamic config
* WASM/browser support for web-native relays

---

**Want code scaffolds, pseudo-protocols, or implementation checklists? Ping for breakdowns or Zig module outlines.**
