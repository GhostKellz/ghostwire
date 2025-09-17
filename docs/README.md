# GhostWire Documentation

Welcome to the comprehensive documentation for GhostWire, a modern mesh VPN system built in Rust.

## 📚 Documentation Overview

- [**Quick Start Guide**](./quick-start.md) - Get up and running with GhostWire in minutes
- [**Architecture Overview**](./architecture.md) - Deep dive into GhostWire's system design
- [**Installation Guide**](./installation.md) - Complete installation instructions for all platforms
- [**Configuration Reference**](./configuration.md) - Detailed configuration options
- [**API Documentation**](./api/README.md) - REST and gRPC API reference
- [**CLI Reference**](./cli.md) - Complete command-line interface documentation
- [**Web Admin Guide**](./web-admin.md) - Using the web-based administration interface
- [**Desktop Client Guide**](./desktop-client.md) - Native desktop application documentation
- [**Deployment Guide**](./deployment.md) - Production deployment best practices
- [**Monitoring & Observability**](./observability.md) - Metrics, logging, and monitoring setup
- [**Security Guide**](./security.md) - Security considerations and best practices
- [**Troubleshooting**](./troubleshooting.md) - Common issues and solutions
- [**Contributing**](./contributing.md) - How to contribute to GhostWire
- [**FAQ**](./faq.md) - Frequently asked questions

## 🚀 What is GhostWire?

GhostWire is a next-generation mesh VPN system that creates secure, zero-configuration networks. Built with modern technologies and inspired by the best practices from Tailscale, WireGuard, and other mesh networking solutions.

### Key Features

- **Zero-Configuration Mesh Networking** - Automatic peer discovery and connection
- **Hybrid Transport Architecture** - WireGuard + QUIC with intelligent failover
- **DERP Relay Network** - NAT traversal and relay infrastructure
- **Web-Based Administration** - Modern React-inspired web interface
- **Native Desktop Clients** - Cross-platform GUI applications
- **Comprehensive CLI Tools** - Full command-line interface
- **Enterprise Security** - ACL policies, OIDC integration, audit logging
- **Production Monitoring** - Prometheus metrics, health checks, alerting

### Architecture Highlights

- **Rust-First Implementation** - Memory-safe, high-performance networking
- **Modular Crate Design** - Composable components for flexible deployment
- **Real-Time Coordination** - gRPC and REST APIs for all operations
- **Database-Backed State** - SQLite/libSQL for reliable data persistence
- **Cloud-Native Ready** - Container support with Kubernetes manifests

## 🎯 Use Cases

### Personal Networks
- Connect personal devices across locations
- Secure remote access to home services
- Share resources between family members

### Small Teams
- Secure team collaboration tools
- Development environment access
- File sharing and backup solutions

### Enterprise Deployment
- Site-to-site connectivity
- Remote workforce access
- Micro-segmentation and zero-trust networking

### Edge Computing
- IoT device connectivity
- Edge-to-cloud communication
- Distributed application networking

## 📖 Getting Started

1. **[Quick Start](./quick-start.md)** - Get GhostWire running in 5 minutes
2. **[Installation](./installation.md)** - Detailed setup for your platform
3. **[First Network](./tutorials/first-network.md)** - Create your first mesh network
4. **[Advanced Configuration](./configuration.md)** - Customize for your needs

## 🏗️ System Requirements

### Minimum Requirements
- **CPU**: 1 core (2+ recommended)
- **Memory**: 512 MB RAM (1GB+ recommended)
- **Storage**: 100 MB free space
- **Network**: Internet connectivity

### Supported Platforms
- **Linux**: Ubuntu 20.04+, RHEL 8+, Debian 11+
- **macOS**: 11.0+ (Big Sur and later)
- **Windows**: Windows 10/11, Windows Server 2019+
- **Container**: Docker, Kubernetes, Podman

### Network Requirements
- **Outbound**: HTTPS (443), UDP (41641)
- **Optional**: Custom DERP ports, STUN servers
- **Firewall**: Automatic hole-punching, manual port forwarding supported

## 🔧 Component Overview

| Component | Description | Language | Status |
|-----------|-------------|----------|--------|
| **ghostwire-server** | Coordination server and control plane | Rust | ✅ Complete |
| **ghostwire-client** | Client daemon and transport layer | Rust | ✅ Complete |
| **ghostwire-cli** | Command-line interface (`gwctl`) | Rust | ✅ Complete |
| **ghostwire-web** | Web administration interface | Rust/Leptos | ✅ Complete |
| **ghostwire-desktop** | Native desktop GUI client | Rust/egui | ✅ Complete |
| **ghostwire-derp** | DERP relay server implementation | Rust | ✅ Complete |
| **ghostwire-dns** | MagicDNS and DNS management | Rust | ✅ Complete |
| **ghostwire-observability** | Metrics, logging, and monitoring | Rust | ✅ Complete |

## 📊 Performance Characteristics

### Throughput
- **Direct WireGuard**: Up to line speed (10+ Gbps tested)
- **QUIC Transport**: 1-5 Gbps depending on CPU
- **DERP Relay**: 100-500 Mbps per relay

### Latency
- **Direct Connection**: <1ms additional overhead
- **DERP Relay**: 10-50ms additional latency
- **Connection Establishment**: 100-500ms

### Resource Usage
- **Memory**: 10-50 MB per client
- **CPU**: <1% at idle, 5-15% under load
- **Storage**: <100 MB including logs

## 🔐 Security Features

- **End-to-End Encryption** - WireGuard and QUIC cryptography
- **Perfect Forward Secrecy** - Regular key rotation
- **Zero-Knowledge Architecture** - Coordination server never sees traffic
- **ACL Policy Engine** - Fine-grained access control
- **Audit Logging** - Complete activity tracking
- **OIDC Integration** - Enterprise identity providers

## 🌐 Network Topology

GhostWire creates a full-mesh network where every device can communicate directly with every other device, falling back to relay servers when direct connections aren't possible.

```
┌─────────────┐    ┌─────────────┐
│   Device A  │◄──►│   Device B  │
└─────────────┘    └─────────────┘
      │                   │
      ▼                   ▼
┌─────────────┐    ┌─────────────┐
│   Device C  │◄──►│   Device D  │
└─────────────┘    └─────────────┘
      │                   │
      └─────────┬─────────┘
                ▼
        ┌─────────────┐
        │ DERP Relay  │
        └─────────────┘
```

## 📈 Monitoring & Observability

GhostWire includes comprehensive monitoring capabilities:

- **Prometheus Metrics** - 50+ metrics covering all components
- **Structured Logging** - JSON logs with correlation IDs
- **Health Checks** - Automated monitoring of all services
- **Alerting** - Configurable alerts via webhook/email
- **Dashboards** - Built-in web dashboards for visualization

## 🚢 Deployment Options

### Standalone
- Single binary deployment
- Embedded SQLite database
- Built-in web interface

### Container
- Docker images for all components
- Kubernetes manifests included
- Helm charts available

### Cloud
- AWS/GCP/Azure deployment guides
- Terraform modules
- Auto-scaling configurations

## 📝 License

GhostWire is dual-licensed under MIT OR Apache-2.0. See [LICENSE-MIT](../LICENSE-MIT) and [LICENSE-APACHE](../LICENSE-APACHE) for details.

## 🤝 Community

- **GitHub**: [ghostkellz/ghostwire](https://github.com/ghostkellz/ghostwire)
- **Issues**: [Report bugs and request features](https://github.com/ghostkellz/ghostwire/issues)
- **Discussions**: [Community discussions](https://github.com/ghostkellz/ghostwire/discussions)
- **Security**: [Security policy and contact](../SECURITY.md)

## 📚 Further Reading

- [Architecture Deep Dive](./architecture.md)
- [Protocol Specifications](./protocols/)
- [API Reference](./api/)
- [Deployment Examples](./examples/)
- [Performance Tuning](./performance.md)
- [Security Best Practices](./security.md)