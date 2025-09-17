# GhostWire Coordination Server Core

The coordination server core is the heart of the GhostWire mesh VPN system, responsible for managing node lifecycles, network topology, and secure communication between peers.

## Architecture Overview

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Coordinator   │◄───┤  NodeManager    │◄───┤  IpAllocator    │
└─────────┬───────┘    └─────────────────┘    └─────────────────┘
          │
          ├─────────────────────────────────────────────────────────┐
          │                                                         │
┌─────────▼───────┐    ┌─────────────────┐    ┌─────────────────┐   │
│ SessionManager  │    │  NetworkMapper  │    │HeartbeatMonitor │   │
└─────────────────┘    └─────────────────┘    └─────────────────┘   │
                                                                    │
          ┌─────────────────────────────────────────────────────────┘
          │
┌─────────▼───────┐    ┌─────────────────┐
│KeyExchangeManager│   │  Database Layer │
└─────────────────┘    └─────────────────┘
```

## Core Components

### 1. Coordinator (`coordinator/mod.rs`)

The main orchestrator that coordinates all subsystems and provides the primary API for node management.

**Key Responsibilities:**
- Node registration and validation
- Session creation and management
- Network map distribution
- Heartbeat processing
- Graceful service startup/shutdown

**Main APIs:**
```rust
// Register a new node
pub async fn register_node(
    &self,
    user_id: UserId,
    request: NodeRegistrationRequest,
) -> Result<NodeRegistrationResponse>

// Process node heartbeat
pub async fn process_heartbeat(
    &self,
    node_id: NodeId,
    heartbeat: NodeHeartbeat,
) -> Result<HeartbeatResponse>

// Unregister a node
pub async fn unregister_node(&self, node_id: &NodeId) -> Result<()>
```

### 2. NodeManager (`coordinator/node_manager.rs`)

Manages the complete lifecycle of nodes in the network, including IP allocation and endpoint tracking.

**Key Features:**
- **Automatic IP Allocation**: Manages IPv4/IPv6 address pools with collision avoidance
- **Public Key Validation**: Ensures unique and valid WireGuard keys
- **Endpoint Tracking**: Monitors node connectivity information
- **Status Management**: Tracks online/offline states

**IP Allocation Algorithm:**
```rust
struct IpAllocator {
    ipv4_range: cidr::Ipv4Cidr,          // e.g., 10.1.0.0/16
    ipv6_range: Option<cidr::Ipv6Cidr>,  // e.g., fd7a:115c:a1e0::/48
    allocated: Vec<IpAddr>,              // Currently assigned IPs
    next_ipv4: u32,                      // Next available IPv4
    next_ipv6: u128,                     // Next available IPv6
}
```

**Usage Example:**
```rust
// Register a new node
let node = node_manager.register_node(user_id, request).await?;
// IP addresses are automatically allocated from the pool

// Update endpoints when NAT traversal discovers new paths
node_manager.update_endpoints(&node_id, new_endpoints).await?;
```

### 3. SessionManager (`coordinator/session_manager.rs`)

Provides secure, token-based authentication for nodes with automatic cleanup.

**Security Features:**
- **Blake3-based Tokens**: Cryptographically secure session tokens
- **Configurable Expiration**: Session timeouts prevent token reuse
- **Automatic Cleanup**: Background task removes expired sessions
- **Per-Node Sessions**: One active session per node

**Token Generation:**
```rust
fn generate_session_token(&self, node: &Node) -> Result<String> {
    let mut hasher = Hasher::new();
    hasher.update(node.id.as_bytes());
    hasher.update(node.public_key.0.as_slice());
    hasher.update(&current_time_bytes);
    hasher.update(&random_bytes);

    let hash = hasher.finalize();
    Ok(base64::encode_config(hash.as_bytes(), base64::URL_SAFE_NO_PAD))
}
```

### 4. NetworkMapper (`coordinator/network_map.rs`)

Generates customized network maps for each node based on ACL policies and real-time topology.

**Key Features:**
- **ACL-Based Filtering**: Only authorized peers are included in maps
- **Intelligent Caching**: Version-based cache invalidation
- **Real-time Updates**: Automatic map regeneration on topology changes
- **Background Processing**: Async map generation doesn't block client requests

**Network Map Structure:**
```rust
pub struct NetworkMap {
    pub node_key: PublicKey,           // Node's own public key
    pub peers: Vec<Node>,              // Authorized peer nodes
    pub dns: DnsConfig,                // MagicDNS configuration
    pub derp_map: DerpMap,             // DERP relay servers
    pub packet_filter: Vec<PacketFilter>, // ACL-derived firewall rules
    pub user_profiles: HashMap<UserId, UserProfile>,
    pub domain: String,                // Network domain (e.g., "mycompany.ghost")
}
```

**ACL Evaluation Example:**
```rust
// Check if source node can communicate with destination node
async fn is_peer_authorized(
    &self,
    source: &Node,
    dest: &Node,
    acl_rules: &[AclRule],
) -> Result<bool> {
    for rule in acl_rules {
        if self.matches_acl_spec(source, &rule.source_spec).await? &&
           self.matches_acl_spec(dest, &rule.dest_spec).await? {
            return Ok(matches!(rule.action, AclAction::Accept));
        }
    }
    Ok(false) // Default deny
}
```

### 5. HeartbeatMonitor (`coordinator/heartbeat.rs`)

Monitors node health and connectivity with configurable grace periods.

**Monitoring Algorithm:**
1. **Heartbeat Recording**: Nodes send periodic heartbeats (default: 30s)
2. **Miss Detection**: Missing 2+ consecutive heartbeats triggers warning
3. **Grace Period**: 60-second grace period before marking offline
4. **Offline Handling**: Automatic cleanup and peer notification

**Health Status:**
```rust
pub struct NodeHealth {
    pub node_id: NodeId,
    pub is_online: bool,
    pub last_seen: SystemTime,
    pub time_since_last_heartbeat: Duration,
    pub consecutive_misses: u32,
    pub in_grace_period: bool,
}
```

### 6. KeyExchangeManager (`coordinator/key_exchange.rs`)

Handles cryptographic operations for WireGuard key management and DERP encryption.

**Key Validation:**
- Ensures 32-byte X25519 public keys
- Rejects zero keys and identity elements
- Validates keypair correspondence

**Security Functions:**
```rust
// Validate WireGuard public key
pub fn validate_public_key(key: &[u8]) -> Result<PublicKey>

// Generate secure keypair
pub fn generate_keypair() -> Result<(PublicKey, PrivateKey)>

// Compute shared secret for DERP encryption
pub fn compute_shared_secret(
    private_key: &PrivateKey,
    public_key: &PublicKey,
) -> Result<[u8; 32]>

// Constant-time key comparison
pub fn constant_time_compare(a: &[u8], b: &[u8]) -> bool
```

## Configuration

The coordination core is configured through the main server configuration:

```yaml
# Server configuration
server:
  listen_addr: "0.0.0.0:8080"

# Network configuration
network:
  ipv4_range: "10.1.0.0/16"         # IPv4 allocation pool
  ipv6_range: "fd7a:115c:a1e0::/48" # IPv6 allocation pool (optional)
  keepalive_interval: "30s"         # Heartbeat interval

# Authentication
auth:
  session_timeout: "24h"            # Session token lifetime

# Database
database:
  path: "/var/lib/ghostwire/db.sqlite"
  cache_size: "256MB"
  parallel_writes: true
```

## Performance Characteristics

### Scalability
- **50,000+ concurrent nodes**: Designed for large enterprise deployments
- **Sub-millisecond latency**: Optimized database queries and caching
- **Memory efficient**: Smart caching with automatic cleanup

### Database Optimization
- **Connection Pooling**: Up to 64 concurrent connections
- **Prepared Statements**: Cached for repeated queries
- **Spatial Indexes**: R-tree indexing for CIDR operations
- **Time-series Data**: Optimized metrics storage

### Caching Strategy
```rust
struct CachedNetworkMap {
    map: NetworkMap,
    generated_at: SystemTime,
    version: u64,           // Global version for cache invalidation
}
```

## Error Handling

The coordination core uses comprehensive error handling with specific error types:

```rust
pub enum GhostWireError {
    Database(String),       // Database operation failures
    Validation(String),     // Input validation errors
    Authentication(String), // Auth/session failures
    NotFound(String),       // Resource not found
    ResourceExhausted(String), // IP pool exhaustion, etc.
    Internal(String),       // Internal server errors
}
```

## Metrics and Observability

### Key Metrics Collected
- **Node Registration Rate**: New nodes per minute
- **Heartbeat Success Rate**: Percentage of successful heartbeats
- **Network Map Generation Time**: Performance monitoring
- **Session Validation Rate**: Authentication performance
- **Database Query Performance**: Query execution times

### Logging Levels
- **INFO**: Service lifecycle, node registration/removal
- **DEBUG**: Detailed operational information
- **TRACE**: Low-level debugging information
- **WARN**: Non-critical issues (e.g., missed heartbeats)
- **ERROR**: Critical failures requiring attention

## Security Considerations

### Authentication
- Session tokens use Blake3 hash with random salt
- Tokens are URL-safe base64 encoded
- Configurable session timeouts

### Key Management
- WireGuard keys validated for cryptographic safety
- Constant-time comparison prevents timing attacks
- Key sanitization for safe logging

### Access Control
- ACL policies control peer visibility
- Default-deny security model
- Tag-based and user-based access control

## Future Enhancements

### Planned Features
1. **Key Rotation**: Automatic WireGuard key rotation
2. **Load Balancing**: Multiple coordination server instances
3. **Geo-Distribution**: Region-aware DERP relay selection
4. **Advanced ACLs**: Time-based and condition-based rules

### Performance Optimizations
1. **gRPC Streaming**: Real-time network map updates
2. **Delta Updates**: Incremental network map changes
3. **Compression**: Network map compression for large networks
4. **Caching Layers**: Redis integration for distributed caching

This coordination core provides a solid foundation for the GhostWire mesh VPN system, handling the complex orchestration required for secure, scalable peer-to-peer networking.