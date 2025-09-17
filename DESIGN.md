
---
title: Design 
```plaintext
                  ┌───────────────┐
                  │   OIDC IdP    │
                  │ (Azure/Google)│
                  └───────┬───────┘
                          │
                  ┌───────▼────────┐
                  │  ghostwcd      │
                  │ Control Plane  │
                  │  (ACL, Netmap) │
                  └───────┬────────┘
                          │ QUIC/TLS
                  ┌───────▼────────┐
                  │ Region Registry│
                  └───────┬────────┘
                          │
              ┌───────────▼───────────┐
              │      ghostderpd       │
              │ QUIC Relay + STUN     │
              └───────────┬───────────┘
                          │ QUIC (streams+datagrams)
      ┌───────────────────▼───────────────────┐
      │          ghostwired (client)          │
      │ ┌───────────────┐  ┌────────────────┐ │
      │ │ Kernel WG     │  │ ghostwire-wg   │ │
      │ │ (10+ Gbps)    │  │ (SIMD 1–2 Gbps)│ │
      │ └───────────────┘  └────────────────┘ │
      │             └─────boringtun fallback │
      └──────────────────────────────────────┘

