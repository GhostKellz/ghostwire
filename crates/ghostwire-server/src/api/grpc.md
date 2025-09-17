# gRPC API Documentation

The GhostWire gRPC API provides high-performance, strongly-typed communication between nodes and the coordination server. Built on top of tonic and Protocol Buffers, it offers sub-millisecond latency and supports streaming for real-time updates.

## Protocol Definition

### Service Interface

```protobuf
service CoordinationService {
  // Register a new node in the network
  rpc RegisterNode(RegisterNodeRequest) returns (RegisterNodeResponse);

  // Send heartbeat and receive network updates
  rpc Heartbeat(HeartbeatRequest) returns (HeartbeatResponse);

  // Unregister a node from the network
  rpc UnregisterNode(UnregisterNodeRequest) returns (UnregisterNodeResponse);

  // Get current network map
  rpc GetNetworkMap(NetworkMapRequest) returns (NetworkMapResponse);

  // Stream real-time network map updates
  rpc StreamNetworkUpdates(StreamRequest) returns (stream NetworkUpdateEvent);
}
```

## Core Methods

### 1. Node Registration

**Purpose**: Register a new node in the GhostWire network

**Request**:
```protobuf
message RegisterNodeRequest {
  string name = 1;                    // Node hostname/name
  bytes public_key = 2;               // WireGuard public key (32 bytes)
  repeated Endpoint endpoints = 3;     // Node endpoints
  NodeCapabilities capabilities = 4;   // Node capabilities
  optional string pre_auth_key = 5;   // Pre-authentication key
  repeated string tags = 6;           // Node tags for ACL matching
}
```

**Response**:
```protobuf
message RegisterNodeResponse {
  string node_id = 1;                 // Assigned node ID
  string ipv4 = 2;                   // Assigned IPv4 address
  optional string ipv6 = 3;          // Assigned IPv6 address (if supported)
  string session_token = 4;          // Authentication token
  NetworkMap network_map = 5;        // Initial network map
  DerpMap derp_map = 6;             // DERP relay map
}
```

**Example Usage**:
```rust
use ghostwire_proto::coordination::v1::*;

let request = RegisterNodeRequest {
    name: "server-01".to_string(),
    public_key: node_public_key.to_vec(),
    endpoints: vec![
        Endpoint {
            addr: "203.0.113.10:41641".to_string(),
            r#type: EndpointType::DirectIpv4 as i32,
            preference: Some(10),
        }
    ],
    capabilities: Some(NodeCapabilities {
        can_derp: false,
        can_exit_node: true,
        supports_ipv6: true,
        supports_pcp: false,
        supports_pmp: false,
        supports_upnp: false,
    }),
    pre_auth_key: Some("preauthkey_abc123".to_string()),
    tags: vec!["server".to_string(), "production".to_string()],
};

let mut client = CoordinationServiceClient::connect("http://[::1]:8080").await?;
let response = client.register_node(request).await?;

println!("Registered node: {}", response.into_inner().node_id);
```

### 2. Heartbeat Processing

**Purpose**: Maintain node health status and receive network updates

**Request**:
```protobuf
message HeartbeatRequest {
  string node_id = 1;                // Node ID
  string session_token = 2;          // Session authentication token
  repeated Endpoint endpoints = 3;    // Current endpoints (if changed)
  optional NodeStats stats = 4;      // Node statistics
}
```

**Response**:
```protobuf
message HeartbeatResponse {
  optional NetworkMap network_map = 1;  // Updated network map (if changed)
  uint64 next_heartbeat_seconds = 2;    // Next heartbeat interval
  repeated string messages = 3;         // Server messages for the node
}
```

**Example Usage**:
```rust
// Set up metadata for authentication
let mut request = tonic::Request::new(HeartbeatRequest {
    node_id: node_id.to_string(),
    session_token: session_token.clone(),
    endpoints: current_endpoints,
    stats: Some(NodeStats {
        rx_bytes: 1024000,
        tx_bytes: 2048000,
        active_connections: 5,
        latency_ms: Some(12.5),
        packet_loss: Some(0.1),
    }),
});

// Add session token to metadata
request.metadata_mut().insert(
    "authorization",
    format!("Bearer {}", session_token).parse().unwrap(),
);

let response = client.heartbeat(request).await?;
```

### 3. Network Map Retrieval

**Purpose**: Get current network topology and peer information

**Request**:
```protobuf
message NetworkMapRequest {
  string node_id = 1;                // Requesting node ID
  string session_token = 2;          // Session authentication token
  optional uint64 current_version = 3; // Current map version (for delta updates)
}
```

**Response**:
```protobuf
message NetworkMapResponse {
  NetworkMap network_map = 1;        // Full or delta network map
  bool is_delta = 2;                 // True if this is a delta update
}
```

### 4. Real-Time Streaming

**Purpose**: Receive real-time network topology changes

**Request**:
```protobuf
message StreamRequest {
  string node_id = 1;                // Node ID
  string session_token = 2;          // Session authentication token
}
```

**Response Stream**:
```protobuf
message NetworkUpdateEvent {
  enum EventType {
    PEER_ADDED = 0;
    PEER_REMOVED = 1;
    PEER_UPDATED = 2;
    ACL_UPDATED = 3;
    DNS_UPDATED = 4;
  }

  EventType event_type = 1;          // Type of update
  optional Node peer = 2;            // Affected peer (for peer events)
  optional NetworkMap full_map = 3;  // Full map (for ACL/DNS updates)
  uint64 version = 4;                // Update version
}
```

**Example Streaming Client**:
```rust
let mut stream = client.stream_network_updates(StreamRequest {
    node_id: node_id.to_string(),
    session_token: session_token.clone(),
}).await?.into_inner();

while let Some(update) = stream.message().await? {
    match update.event_type() {
        EventType::PeerAdded => {
            if let Some(peer) = update.peer {
                println!("New peer added: {}", peer.name);
                // Update local peer list
            }
        }
        EventType::PeerRemoved => {
            println!("Peer removed");
            // Remove from local peer list
        }
        EventType::AclUpdated => {
            if let Some(full_map) = update.full_map {
                println!("ACL policies updated, rebuilding network map");
                // Rebuild local network configuration
            }
        }
        _ => {}
    }
}
```

## Data Types

### Node Information

```protobuf
message Node {
  string id = 1;                     // Node ID (UUID)
  string user_id = 2;                // Owner user ID
  string name = 3;                   // Node name/hostname
  bytes public_key = 4;              // WireGuard public key
  string ipv4 = 5;                   // IPv4 address
  optional string ipv6 = 6;          // IPv6 address
  repeated Endpoint endpoints = 7;    // Network endpoints
  repeated string allowed_ips = 8;    // Allowed IP ranges (CIDR)
  repeated Route routes = 9;          // Advertised routes
  repeated string tags = 10;          // Node tags
  int64 created_at = 11;             // Creation timestamp (Unix)
  int64 last_seen = 12;              // Last seen timestamp (Unix)
  optional int64 expires_at = 13;    // Expiration timestamp (Unix)
  bool online = 14;                  // Online status
}
```

### Network Endpoints

```protobuf
message Endpoint {
  string addr = 1;                   // IP:Port address
  EndpointType type = 2;             // Endpoint type
  optional uint32 preference = 3;    // Preference (lower = higher priority)
}

enum EndpointType {
  UNKNOWN = 0;
  DIRECT_IPV4 = 1;        // Direct IPv4 endpoint
  DIRECT_IPV6 = 2;        // Direct IPv6 endpoint
  STUN = 3;               // STUN-discovered endpoint
  DERP = 4;               // DERP relay endpoint
}
```

### DERP Configuration

```protobuf
message DerpMap {
  map<uint32, DerpRegion> regions = 1; // Region ID -> Region info
}

message DerpRegion {
  uint32 region_id = 1;              // Unique region identifier
  string region_code = 2;            // Region code (e.g., "us-east")
  string region_name = 3;            // Human-readable name
  repeated DerpNode nodes = 4;       // DERP nodes in this region
}

message DerpNode {
  string name = 1;                   // Node name
  string hostname = 2;               // Hostname or IP
  uint32 port = 3;                   // DERP port
  bytes public_key = 4;              // Node public key
  bool stun_only = 5;                // STUN-only node
  optional uint32 stun_port = 6;     // STUN port (if different)
}
```

## Authentication

### Session Token Authentication

All authenticated gRPC calls require a session token in the request metadata:

```rust
// Method 1: Add to request metadata
let mut request = tonic::Request::new(your_request);
request.metadata_mut().insert(
    "authorization",
    format!("Bearer {}", session_token).parse().unwrap(),
);

// Method 2: Use interceptor for automatic authentication
use tonic::service::Interceptor;

#[derive(Clone)]
struct AuthInterceptor {
    token: String,
}

impl Interceptor for AuthInterceptor {
    fn call(&mut self, mut request: tonic::Request<()>) -> Result<tonic::Request<()>, tonic::Status> {
        request.metadata_mut().insert(
            "authorization",
            format!("Bearer {}", self.token).parse().unwrap(),
        );
        Ok(request)
    }
}

let client = CoordinationServiceClient::with_interceptor(
    channel,
    AuthInterceptor { token: session_token }
);
```

### Error Handling

```rust
match client.register_node(request).await {
    Ok(response) => {
        println!("Registration successful");
    }
    Err(status) => {
        match status.code() {
            tonic::Code::Unauthenticated => {
                eprintln!("Invalid session token");
            }
            tonic::Code::InvalidArgument => {
                eprintln!("Invalid request: {}", status.message());
            }
            tonic::Code::NotFound => {
                eprintln!("Node not found");
            }
            tonic::Code::ResourceExhausted => {
                eprintln!("Rate limit exceeded");
            }
            _ => {
                eprintln!("Unexpected error: {}", status);
            }
        }
    }
}
```

## Performance Optimization

### Connection Management

```rust
// Use connection pooling for high-throughput scenarios
use tonic::transport::{Channel, Endpoint};
use std::time::Duration;

let channel = Endpoint::from_static("http://[::1]:8080")
    .keep_alive_while_idle(true)
    .keep_alive_timeout(Duration::from_secs(30))
    .connect().await?;

let client = CoordinationServiceClient::new(channel);
```

### Batch Operations

```rust
// For bulk operations, prefer streaming or batch methods
async fn register_multiple_nodes(
    client: &mut CoordinationServiceClient<Channel>,
    nodes: Vec<RegisterNodeRequest>
) -> Result<Vec<RegisterNodeResponse>, Box<dyn std::error::Error>> {
    let mut responses = Vec::new();

    // Use futures::stream for concurrent requests
    use futures::stream::{FuturesUnordered, StreamExt};

    let mut futures = FuturesUnordered::new();
    for node in nodes.into_iter().take(10) { // Limit concurrency
        futures.push(client.register_node(node));
    }

    while let Some(result) = futures.next().await {
        responses.push(result?.into_inner());
    }

    Ok(responses)
}
```

### Request Compression

```rust
use tonic::transport::Channel;
use tonic::codec::CompressionEncoding;

let mut client = CoordinationServiceClient::new(channel)
    .send_compressed(CompressionEncoding::Gzip)
    .accept_compressed(CompressionEncoding::Gzip);
```

## Testing

### Unit Testing

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use tonic::transport::Server;

    #[tokio::test]
    async fn test_node_registration() {
        // Start test server
        let coordinator = Arc::new(MockCoordinator::new());
        let service = GrpcCoordinationService::new(coordinator);

        let addr = "127.0.0.1:0".parse().unwrap();
        let server_handle = tokio::spawn(async move {
            Server::builder()
                .add_service(CoordinationServiceServer::new(service))
                .serve(addr)
                .await
        });

        // Connect client
        let mut client = CoordinationServiceClient::connect("http://127.0.0.1:8080").await?;

        // Test registration
        let request = RegisterNodeRequest {
            name: "test-node".to_string(),
            public_key: vec![0u8; 32],
            endpoints: vec![],
            capabilities: None,
            pre_auth_key: Some("test-key".to_string()),
            tags: vec![],
        };

        let response = client.register_node(request).await?;
        assert!(!response.into_inner().node_id.is_empty());
    }
}
```

### Load Testing

```bash
# Install ghz for gRPC load testing
go install github.com/bojand/ghz/cmd/ghz@latest

# Basic load test
ghz --proto coordination.proto \
    --call ghostwire.coordination.v1.CoordinationService.Heartbeat \
    --data '{"node_id":"test","session_token":"token"}' \
    --metadata '{"authorization":"Bearer token"}' \
    --total 10000 \
    --concurrency 100 \
    --timeout 5s \
    localhost:8080

# Streaming test
ghz --proto coordination.proto \
    --call ghostwire.coordination.v1.CoordinationService.StreamNetworkUpdates \
    --data '{"node_id":"test","session_token":"token"}' \
    --stream-call-duration 30s \
    --concurrency 50 \
    localhost:8080
```

## Best Practices

### 1. Connection Lifecycle

- **Reuse connections**: Don't create new connections for every request
- **Handle reconnection**: Implement exponential backoff for failed connections
- **Graceful shutdown**: Properly close connections and streams

### 2. Error Handling

- **Retry logic**: Implement retries for transient failures
- **Circuit breaker**: Prevent cascade failures
- **Logging**: Log all errors with context

### 3. Security

- **TLS encryption**: Always use TLS in production
- **Token rotation**: Regularly rotate session tokens
- **Rate limiting**: Respect server rate limits

### 4. Performance

- **Streaming**: Use streaming for real-time data
- **Compression**: Enable compression for large payloads
- **Connection pooling**: Reuse connections when possible

## Troubleshooting

### Common Issues

**Connection refused**:
```bash
# Check if server is running
netstat -tlnp | grep 8080

# Check firewall rules
sudo iptables -L | grep 8080
```

**Authentication errors**:
```rust
// Verify token format
if !session_token.starts_with("sess_") {
    eprintln!("Invalid token format");
}

// Check token expiration
let claims = decode_token(&session_token)?;
if claims.exp < current_timestamp() {
    eprintln!("Token expired");
}
```

**Performance issues**:
```rust
// Add request tracing
use tracing::{info, error, Instrument};

let span = tracing::info_span!("grpc_request", method = "RegisterNode");
let response = client.register_node(request)
    .instrument(span)
    .await?;
```

This gRPC API provides the foundation for high-performance, real-time communication in GhostWire mesh networks.