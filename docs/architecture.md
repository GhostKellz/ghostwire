# GhostWire Architecture

This document provides a comprehensive overview of GhostWire's system architecture, design principles, and implementation details.

## 🏗️ High-Level Architecture

GhostWire follows a distributed mesh architecture with centralized coordination. The system consists of several key components working together to provide seamless mesh networking.

```
┌─────────────────────────────────────────────────────────────────┐
│                    GhostWire Mesh Network                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐        │
│  │   Client A  │◄──►│   Client B  │◄──►│   Client C  │        │
│  │             │    │             │    │             │        │
│  │ 100.64.0.1  │    │ 100.64.0.2  │    │ 100.64.0.3  │        │
│  └─────────────┘    └─────────────┘    └─────────────┘        │
│         │                   │                   │              │
│         └─────────┬─────────┴─────────┬─────────┘              │
│                   │                   │                        │
│                   ▼                   ▼                        │
│           ┌─────────────┐    ┌─────────────┐                   │
│           │ DERP Relay  │    │ DERP Relay  │                   │
│           │ us-east-1   │    │ eu-west-1   │                   │
│           └─────────────┘    └─────────────┘                   │
│                   │                   │                        │
│                   └─────────┬─────────┘                        │
│                             │                                  │
│                             ▼                                  │
│                    ┌─────────────┐                             │
│                    │Coordination │                             │
│                    │   Server    │                             │
│                    └─────────────┘                             │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## 🔧 Core Components

### 1. Coordination Server (`ghostwire-server`)

The coordination server acts as the control plane for the entire mesh network.

**Responsibilities:**
- **Node Registration**: Manages device enrollment and authentication
- **Network State**: Maintains the authoritative view of network topology
- **Key Distribution**: Facilitates secure key exchange between peers
- **ACL Enforcement**: Evaluates and enforces access control policies
- **DERP Coordination**: Manages relay server assignments and load balancing

**Technologies:**
- **HTTP/gRPC APIs**: RESTful and streaming interfaces
- **SQLite/libSQL**: Embedded database for state persistence
- **Tokio**: Async runtime for high-performance I/O
- **OIDC Integration**: Enterprise authentication support

```rust
// Core server architecture
pub struct CoordinationServer {
    pub api_server: ApiServer,        // HTTP/gRPC endpoints
    pub node_manager: NodeManager,    // Device management
    pub acl_engine: AclEngine,        // Policy enforcement
    pub key_manager: KeyManager,      // Cryptographic operations
    pub derp_manager: DerpManager,    // Relay coordination
}
```

### 2. Client Daemon (`ghostwire-client`)

The client daemon runs on each device and handles network transport.

**Responsibilities:**
- **Transport Layer**: WireGuard and QUIC protocol implementation
- **NAT Traversal**: STUN/ICE for direct connection establishment
- **DERP Fallback**: Relay communication when direct fails
- **Network Interface**: TUN/TAP interface management
- **Route Management**: Dynamic routing table updates

**Architecture:**

```rust
pub struct GhostWireClient {
    pub transport: TransportManager,  // WireGuard + QUIC
    pub connection: ConnectionManager, // Peer connections
    pub network: NetworkManager,      // Interface management
    pub auth: AuthManager,           // Authentication
}
```

### 3. Command Line Interface (`gwctl`)

Unified CLI tool for all GhostWire operations.

**Features:**
- **Server Management**: Start, stop, configure coordination server
- **Client Operations**: Connect, disconnect, status monitoring
- **Network Administration**: Manage devices, routes, policies
- **Diagnostics**: Debug tools and network analysis

### 4. Web Administration Interface

Modern web-based management interface built with Leptos (Rust WebAssembly).

**Capabilities:**
- **Dashboard**: Real-time network status and metrics
- **Device Management**: Add, remove, configure devices
- **Policy Editor**: Visual ACL policy configuration
- **Monitoring**: Network topology visualization and analytics

### 5. Desktop GUI Client

Native cross-platform desktop application using egui.

**Features:**
- **System Tray Integration**: Background operation with quick access
- **Connection Management**: One-click connect/disconnect
- **Network Monitoring**: Real-time statistics and health information
- **Settings Management**: GUI-based configuration

## 🔀 Network Transport Architecture

GhostWire uses a hybrid transport approach combining multiple protocols for optimal performance and reliability.

### Transport Hierarchy

1. **Direct WireGuard** (Preferred)
   - Fastest performance (line speed)
   - Lowest latency (<1ms overhead)
   - Uses when direct connectivity possible

2. **QUIC Direct** (Fallback)
   - Better NAT traversal than WireGuard
   - TLS 1.3 encryption
   - 0-RTT connection resumption

3. **DERP Relay** (Last Resort)
   - Guaranteed connectivity
   - Higher latency (relay overhead)
   - Fallback when direct connection fails

### Connection Establishment Flow

```mermaid
sequenceDiagram
    participant A as Client A
    participant S as Coordination Server
    participant R as DERP Relay
    participant B as Client B

    A->>S: Register and authenticate
    B->>S: Register and authenticate

    A->>S: Request peer info for B
    S->>A: Return B's endpoints and keys

    A->>B: Attempt direct WireGuard
    alt Direct connection successful
        A<-->B: Direct WireGuard tunnel
    else Direct connection fails
        A->>B: Attempt QUIC direct
        alt QUIC successful
            A<-->B: Direct QUIC tunnel
        else QUIC fails
            A->>R: Connect via DERP relay
            B->>R: Connect via DERP relay
            A<-->R<-->B: Relayed connection
        end
    end
```

## 🔐 Security Architecture

GhostWire implements defense-in-depth security with multiple layers of protection.

### Cryptographic Foundation

- **WireGuard Protocol**: Noise protocol framework with ChaCha20Poly1305
- **QUIC TLS 1.3**: Modern TLS with perfect forward secrecy
- **Key Rotation**: Automatic key refresh every 2 minutes
- **Zero-Knowledge Design**: Coordination server never sees traffic

### Authentication & Authorization

```
┌─────────────────────────────────────────────────────────────┐
│                Authentication Flow                          │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────┐    ┌──────────┐    ┌─────────────┐            │
│  │ Client  │───►│   OIDC   │───►│Coordination │            │
│  │         │    │Provider  │    │   Server    │            │
│  └─────────┘    └──────────┘    └─────────────┘            │
│       │                                │                   │
│       │          ┌─────────────┐       │                   │
│       └─────────►│ ACL Engine  │◄──────┘                   │
│                  └─────────────┘                           │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Access Control Lists (ACLs)

HuJSON-based policy language for fine-grained access control:

```hjson
{
  // Define user groups
  "groups": {
    "group:admin": ["alice@company.com", "bob@company.com"],
    "group:developers": ["*.dev@company.com"],
    "group:interns": ["*.intern@company.com"]
  },

  // Tag ownership
  "tagOwners": {
    "tag:server": ["group:admin"],
    "tag:database": ["group:admin"],
    "tag:development": ["group:developers", "group:admin"]
  },

  // Access rules
  "acls": [
    // Admins can access everything
    {
      "action": "accept",
      "src": ["group:admin"],
      "dst": ["*:*"]
    },

    // Developers can access development resources
    {
      "action": "accept",
      "src": ["group:developers"],
      "dst": ["tag:development:*"]
    },

    // Everyone can access web services
    {
      "action": "accept",
      "src": ["*"],
      "dst": ["*:80", "*:443"]
    }
  ]
}
```

## 📊 Data Flow Architecture

### Control Plane (Coordination)

```
Client ──gRPC/HTTP──► Coordination Server
   │                        │
   │                        ▼
   │                  ┌─────────────┐
   │                  │   SQLite    │
   │                  │  Database   │
   │                  └─────────────┘
   │                        │
   │                        ▼
   │                 ┌─────────────┐
   │                 │ ACL Engine  │
   │                 └─────────────┘
   │                        │
   └────────◄───────────────┘
      Network Map Updates
```

### Data Plane (Traffic)

```
Client A ──WireGuard──► Client B
    │                      │
    │       Failed?        │
    ▼                      ▼
┌─────────┐            ┌─────────┐
│  QUIC   │◄──────────►│  QUIC   │
│ Direct  │            │ Direct  │
└─────────┘            └─────────┘
    │                      │
    │       Failed?        │
    ▼                      ▼
┌─────────┐            ┌─────────┐
│  DERP   │◄──Relay───►│  DERP   │
│ Client  │            │ Client  │
└─────────┘            └─────────┘
```

## 🌐 Network Architecture

### IP Address Allocation

GhostWire uses the CGNAT range `100.64.0.0/10` for mesh networking:

- **Coordinator**: `100.64.0.1/32`
- **Clients**: `100.64.0.2/32` - `100.64.255.254/32`
- **Subnets**: `100.65.0.0/16` - `100.127.255.0/16`

### Routing Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Routing Layers                           │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────────┐  ┌─────────────────┐                  │
│  │  Direct Routes  │  │  Subnet Routes  │                  │
│  │   100.64.x.x    │  │   192.168.x.x   │                  │
│  └─────────────────┘  └─────────────────┘                  │
│           │                     │                          │
│           ▼                     ▼                          │
│  ┌─────────────────────────────────────────┐               │
│  │           Route Manager                 │               │
│  └─────────────────────────────────────────┘               │
│                       │                                    │
│                       ▼                                    │
│  ┌─────────────────────────────────────────┐               │
│  │         TUN/TAP Interface               │               │
│  └─────────────────────────────────────────┘               │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### DNS Resolution (MagicDNS)

- **Device Names**: `laptop-alice.mesh.local` → `100.64.0.2`
- **Service Discovery**: `_http._tcp.web-server.mesh.local`
- **Split DNS**: Local mesh queries vs external DNS
- **Custom Records**: User-defined DNS entries

## 🔄 State Management

### Database Schema

```sql
-- Core entities
CREATE TABLE nodes (
    id TEXT PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    public_key TEXT UNIQUE NOT NULL,
    ip_address TEXT UNIQUE NOT NULL,
    user_id TEXT NOT NULL,
    machine_key TEXT NOT NULL,
    node_key TEXT NOT NULL,
    last_seen DATETIME,
    online BOOLEAN DEFAULT FALSE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE users (
    id TEXT PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    provider TEXT NOT NULL,
    provider_id TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE routes (
    id TEXT PRIMARY KEY,
    destination TEXT NOT NULL,
    advertiser_id TEXT NOT NULL,
    enabled BOOLEAN DEFAULT TRUE,
    primary_route BOOLEAN DEFAULT FALSE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (advertiser_id) REFERENCES nodes(id)
);

-- ACL and policies
CREATE TABLE acl_policies (
    id TEXT PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    content TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

### State Synchronization

1. **Event-Driven Updates**: Real-time state changes via gRPC streams
2. **Periodic Refresh**: Regular full state synchronization
3. **Conflict Resolution**: Last-write-wins with vector clocks
4. **Offline Tolerance**: Local state caching and eventual consistency

## 📈 Performance Architecture

### Scalability Characteristics

| Component | Connections | Throughput | Latency |
|-----------|-------------|------------|---------|
| **Coordination Server** | 10,000+ clients | 1000 req/sec | <10ms |
| **DERP Relay** | 1,000 clients | 1 Gbps | +20ms |
| **Client Daemon** | 100 peers | Line speed | <1ms |

### Resource Usage

- **Memory**: 10-50 MB per client, 100-500 MB per server
- **CPU**: <1% idle, 5-15% under load
- **Storage**: 1-10 MB state, 100 MB logs
- **Network**: Minimal overhead (<5% for most workloads)

## 🔧 Deployment Architecture

### Single-Server Deployment

```
┌─────────────────────────────────────────────────────────────┐
│                    Single Server                            │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │Coordination │  │    DERP     │  │ Web Admin   │         │
│  │   Server    │  │    Relay    │  │ Interface   │         │
│  │   :8080     │  │   :3478     │  │   :8080     │         │
│  └─────────────┘  └─────────────┘  └─────────────┘         │
│         │                │                │                │
│         └────────────────┼────────────────┘                │
│                          │                                 │
│                          ▼                                 │
│                 ┌─────────────┐                            │
│                 │   SQLite    │                            │
│                 │  Database   │                            │
│                 └─────────────┘                            │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Multi-Region Deployment

```
┌─────────────────────────────────────────────────────────────┐
│                  Multi-Region Setup                         │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Region: us-east-1     Region: eu-west-1     Region: ap-1  │
│  ┌─────────────┐       ┌─────────────┐       ┌───────────┐ │
│  │    DERP     │       │    DERP     │       │   DERP    │ │
│  │   Relay     │       │   Relay     │       │  Relay    │ │
│  └─────────────┘       └─────────────┘       └───────────┘ │
│         │                       │                   │      │
│         └───────────────────────┼───────────────────┘      │
│                                 │                          │
│                                 ▼                          │
│                        ┌─────────────┐                     │
│                        │Coordination │                     │
│                        │   Server    │                     │
│                        │  (Primary)  │                     │
│                        └─────────────┘                     │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## 🔍 Monitoring Architecture

GhostWire includes comprehensive observability:

### Metrics Collection

- **Prometheus Metrics**: 50+ metrics covering all components
- **Custom Metrics**: Application-specific performance indicators
- **System Metrics**: CPU, memory, disk, network utilization
- **Business Metrics**: Connection success rates, user activity

### Logging Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                   Logging Pipeline                          │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐     │
│  │  Component  │───►│   Tracing   │───►│    Logs     │     │
│  │    Logs     │    │ Subscriber  │    │ Appender    │     │
│  └─────────────┘    └─────────────┘    └─────────────┘     │
│                            │                    │          │
│                            ▼                    ▼          │
│                   ┌─────────────┐    ┌─────────────┐       │
│                   │   Jaeger    │    │   File /    │       │
│                   │  Tracing    │    │   Syslog    │       │
│                   └─────────────┘    └─────────────┘       │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## 🚀 Design Principles

### 1. **Zero-Configuration by Default**
- Automatic peer discovery and connection
- Sensible defaults for all settings
- Minimal required configuration

### 2. **Security by Design**
- Zero-trust architecture
- End-to-end encryption always
- Principle of least privilege

### 3. **Performance First**
- Direct connections when possible
- Intelligent transport selection
- Minimal protocol overhead

### 4. **Operational Excellence**
- Comprehensive monitoring and logging
- Self-healing and recovery
- Clear error messages and diagnostics

### 5. **Platform Agnostic**
- Cross-platform compatibility
- Container and cloud-native ready
- Multiple deployment options

This architecture enables GhostWire to provide a scalable, secure, and high-performance mesh VPN solution suitable for both personal and enterprise use cases.