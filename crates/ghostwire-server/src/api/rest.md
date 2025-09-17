# REST API Documentation

The GhostWire REST API provides HTTP/JSON endpoints for administrative operations, web dashboard integration, and CLI tool access. Built with Axum and designed for ease of use, it offers comprehensive network management capabilities.

## Base URL

```
Production: https://api.ghostwire.example.com
Development: http://localhost:8081
```

## Authentication

### API Key Authentication (Admin)

For administrative operations, use an API key in the header:

```bash
curl -H "X-API-Key: gw_admin_your_api_key_here" \
     https://api.ghostwire.example.com/api/v1/users
```

### Bearer Token Authentication (User)

For user operations, use JWT/OAuth tokens:

```bash
curl -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
     https://api.ghostwire.example.com/api/v1/nodes
```

### Session Token Authentication (Node)

For node-specific operations, use session tokens:

```bash
curl -H "X-Session-Token: sess_abc123def456ghi789" \
     https://api.ghostwire.example.com/api/v1/nodes/node-123/network-map
```

## Core Endpoints

### Health & Status

#### GET /health

Returns server health status.

**Response**:
```json
{
  "status": "healthy",
  "timestamp": "2024-01-15T10:30:00Z",
  "version": "0.1.0"
}
```

#### GET /stats

Returns network statistics (requires authentication).

**Response**:
```json
{
  "total_nodes": 1234,
  "online_nodes": 987,
  "total_users": 56,
  "total_routes": 2468,
  "version": 42
}
```

### Node Management

#### GET /api/v1/nodes

List all nodes with optional filtering and pagination.

**Query Parameters**:
- `page` (int): Page number (default: 1)
- `per_page` (int): Items per page (default: 50, max: 1000)
- `user_id` (string): Filter by user ID
- `online` (boolean): Filter by online status
- `tag` (string): Filter by tag
- `name_contains` (string): Filter by name substring

**Example Request**:
```bash
curl -H "Authorization: Bearer $TOKEN" \
     "https://api.ghostwire.example.com/api/v1/nodes?page=2&per_page=25&online=true&tag=server"
```

**Response**:
```json
{
  "success": true,
  "data": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "user_id": "550e8400-e29b-41d4-a716-446655440001",
      "name": "server-01",
      "public_key": "deadbeef01234567890abcdef01234567890abcdef01234567890abcdef0123",
      "ipv4": "10.1.0.100",
      "ipv6": "fd7a:115c:a1e0::100",
      "online": true,
      "created_at": 1705312200,
      "last_seen": 1705398600,
      "expires_at": null,
      "endpoints": [
        {
          "addr": "203.0.113.10:41641",
          "endpoint_type": "direct_ipv4",
          "preference": 10
        }
      ],
      "routes": [
        {
          "id": "route_001",
          "prefix": "192.168.1.0/24",
          "advertised": true,
          "enabled": true,
          "is_primary": true
        }
      ],
      "tags": ["server", "production"]
    }
  ],
  "pagination": {
    "page": 2,
    "per_page": 25,
    "total_pages": 5,
    "total_items": 123,
    "has_next": true,
    "has_prev": true
  }
}
```

#### GET /api/v1/nodes/:id

Get detailed information about a specific node.

**Path Parameters**:
- `id` (string): Node ID (UUID)

**Response**:
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "user_id": "550e8400-e29b-41d4-a716-446655440001",
  "name": "server-01",
  "public_key": "deadbeef01234567890abcdef01234567890abcdef01234567890abcdef0123",
  "ipv4": "10.1.0.100",
  "ipv6": "fd7a:115c:a1e0::100",
  "online": true,
  "created_at": 1705312200,
  "last_seen": 1705398600,
  "expires_at": null,
  "endpoints": [...],
  "routes": [...],
  "tags": ["server", "production"]
}
```

#### DELETE /api/v1/nodes/:id

Delete a node from the network (admin only).

**Response**:
```json
{
  "success": true,
  "data": null,
  "message": "Node deleted successfully"
}
```

#### GET /api/v1/nodes/:id/network-map

Get the network map for a specific node.

**Authentication**: Requires node session token

**Response**:
```json
{
  "node_key": "deadbeef01234567890abcdef01234567890abcdef01234567890abcdef0123",
  "peers": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440002",
      "name": "client-01",
      "public_key": "abcdef01234567890deadbeef01234567890abcdef01234567890abcdef01",
      "ipv4": "10.1.0.101",
      "endpoints": [...],
      "allowed_ips": ["10.1.0.101/32"],
      "online": true
    }
  ],
  "dns": {
    "resolvers": ["10.1.0.1", "1.1.1.1"],
    "domains": ["ghostwire.local"],
    "magic_dns": true,
    "routes": {
      "ghostwire.local": {
        "resolvers": ["10.1.0.1"]
      }
    }
  },
  "derp_map": {
    "regions": {
      "1": {
        "region_id": 1,
        "region_code": "us-east",
        "region_name": "US East",
        "nodes": [
          {
            "name": "derp-01",
            "hostname": "derp1.ghostwire.example.com",
            "port": 443,
            "public_key": "c0ffee01234567890deadbeef01234567890abcdef01234567890abcdef01",
            "stun_only": false,
            "stun_port": 3478
          }
        ]
      }
    }
  },
  "packet_filters": [
    {
      "src_ips": ["10.1.0.0/16"],
      "dst_ports": [
        {"first": 22, "last": 22},
        {"first": 80, "last": 80},
        {"first": 443, "last": 443}
      ]
    }
  ],
  "user_profiles": {
    "550e8400-e29b-41d4-a716-446655440001": {
      "id": "550e8400-e29b-41d4-a716-446655440001",
      "login_name": "alice",
      "display_name": "Alice Smith",
      "profile_pic_url": "https://avatars.example.com/alice.jpg"
    }
  },
  "domain": "ghostwire.local",
  "version": 42
}
```

### User Management

#### GET /api/v1/users

List all users (admin only).

**Query Parameters**:
- `page` (int): Page number
- `per_page` (int): Items per page
- `name_contains` (string): Filter by name
- `is_admin` (boolean): Filter by admin status
- `has_nodes` (boolean): Filter users with/without nodes

**Response**:
```json
{
  "success": true,
  "data": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440001",
      "name": "alice",
      "email": "alice@example.com",
      "is_admin": false,
      "created_at": "2024-01-15T10:30:00Z",
      "last_active": "2024-01-15T14:25:30Z",
      "node_count": 3
    }
  ]
}
```

#### POST /api/v1/users

Create a new user (admin only).

**Request Body**:
```json
{
  "name": "bob",
  "email": "bob@example.com",
  "is_admin": false
}
```

**Response**:
```json
{
  "success": true,
  "data": {
    "id": "550e8400-e29b-41d4-a716-446655440002",
    "name": "bob",
    "email": "bob@example.com",
    "is_admin": false,
    "created_at": "2024-01-15T15:00:00Z",
    "last_active": null,
    "node_count": 0
  },
  "message": "User created successfully"
}
```

#### GET /api/v1/users/:id

Get detailed user information.

**Response**:
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440001",
  "name": "alice",
  "email": "alice@example.com",
  "is_admin": false,
  "created_at": "2024-01-15T10:30:00Z",
  "last_active": "2024-01-15T14:25:30Z",
  "node_count": 3,
  "nodes": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "name": "server-01",
      "online": true
    }
  ]
}
```

#### DELETE /api/v1/users/:id

Delete a user and all associated nodes (admin only).

**Response**:
```json
{
  "success": true,
  "data": null,
  "message": "User and 3 associated nodes deleted successfully"
}
```

### Pre-Auth Keys

#### GET /api/v1/preauth-keys

List pre-authentication keys (admin only).

**Response**:
```json
{
  "success": true,
  "data": [
    {
      "id": "pak_01h2x3y4z5a6b7c8d9e0f1g2h3",
      "key": "preauthkey_abc123def456ghi789",
      "user_id": "550e8400-e29b-41d4-a716-446655440001",
      "uses_remaining": 5,
      "expires_at": "2024-02-15T10:30:00Z",
      "created_at": "2024-01-15T10:30:00Z",
      "tags": ["server", "production"],
      "ephemeral": false
    }
  ]
}
```

#### POST /api/v1/preauth-keys

Create a new pre-authentication key (admin only).

**Request Body**:
```json
{
  "uses": 10,
  "expires_in_seconds": 2592000,
  "tags": ["server", "production"],
  "ephemeral": false
}
```

**Response**:
```json
{
  "success": true,
  "data": {
    "id": "pak_01h2x3y4z5a6b7c8d9e0f1g2h4",
    "key": "preauthkey_xyz789abc123def456",
    "user_id": "550e8400-e29b-41d4-a716-446655440001",
    "uses_remaining": 10,
    "expires_at": "2024-02-15T10:30:00Z",
    "created_at": "2024-01-15T10:30:00Z",
    "tags": ["server", "production"],
    "ephemeral": false
  }
}
```

### ACL Management

#### GET /api/v1/acl/rules

List ACL rules (admin only).

**Response**:
```json
{
  "success": true,
  "data": [
    {
      "id": "acl_rule_001",
      "action": "accept",
      "source": "tag:server",
      "destination": "tag:client",
      "ports": ["22", "80", "443"],
      "protocol": "tcp",
      "created_at": "2024-01-15T10:30:00Z",
      "enabled": true
    }
  ]
}
```

#### POST /api/v1/acl/rules

Create a new ACL rule (admin only).

**Request Body**:
```json
{
  "action": "accept",
  "source": "tag:production",
  "destination": "10.1.0.0/16",
  "ports": ["22", "80", "443"],
  "protocol": "tcp",
  "enabled": true
}
```

### Metrics & Monitoring

#### GET /api/v1/metrics

Get system metrics (admin only).

**Query Parameters**:
- `metric` (string): Metric name
- `from_timestamp` (string): Start time (ISO 8601)
- `to_timestamp` (string): End time (ISO 8601)
- `resolution` (string): Data resolution (minute, hour, day)
- `node_id` (string): Filter by node
- `user_id` (string): Filter by user

**Response**:
```json
{
  "metric": "node_count",
  "data_points": [
    {
      "timestamp": "2024-01-15T10:00:00Z",
      "value": 1234.0,
      "labels": {
        "status": "online"
      }
    }
  ],
  "unit": "count",
  "description": "Number of registered nodes"
}
```

#### GET /api/v1/audit-logs

Get audit logs (admin only).

**Query Parameters**:
- `user_id` (string): Filter by user
- `node_id` (string): Filter by node
- `action` (string): Filter by action
- `resource` (string): Filter by resource
- `success` (boolean): Filter by success status
- `from_timestamp` (string): Start time
- `to_timestamp` (string): End time

**Response**:
```json
{
  "success": true,
  "data": [
    {
      "id": "audit_log_001",
      "timestamp": "2024-01-15T10:30:00Z",
      "user_id": "550e8400-e29b-41d4-a716-446655440001",
      "node_id": null,
      "action": "create_user",
      "resource": "user:bob",
      "details": {
        "email": "bob@example.com",
        "is_admin": false
      },
      "client_ip": "203.0.113.100",
      "user_agent": "curl/7.68.0",
      "success": true
    }
  ]
}
```

## Error Handling

### Error Response Format

```json
{
  "error": "error",
  "code": "VALIDATION_ERROR",
  "message": "Invalid public key format",
  "details": {
    "field": "public_key",
    "expected": "64-character hex string"
  },
  "request_id": "req_01h2x3y4z5a6b7c8d9e0f1g2h3"
}
```

### HTTP Status Codes

| Status | Code | Description |
|--------|------|-------------|
| 200 | OK | Request successful |
| 201 | Created | Resource created |
| 400 | Bad Request | Invalid request data |
| 401 | Unauthorized | Authentication required |
| 403 | Forbidden | Insufficient permissions |
| 404 | Not Found | Resource not found |
| 409 | Conflict | Resource already exists |
| 422 | Unprocessable Entity | Validation failed |
| 429 | Too Many Requests | Rate limit exceeded |
| 500 | Internal Server Error | Server error |

### Error Codes

| Code | Description |
|------|-------------|
| `AUTHENTICATION_ERROR` | Invalid credentials |
| `AUTHORIZATION_ERROR` | Insufficient permissions |
| `VALIDATION_ERROR` | Invalid request data |
| `NOT_FOUND` | Resource not found |
| `ALREADY_EXISTS` | Resource already exists |
| `RATE_LIMIT_EXCEEDED` | Too many requests |
| `INTERNAL_ERROR` | Server error |

## Rate Limiting

The API implements rate limiting to prevent abuse:

- **Default limits**: 100 requests per minute
- **Burst allowance**: 10 additional requests
- **Headers returned**:
  - `X-RateLimit-Limit`: Maximum requests per window
  - `X-RateLimit-Remaining`: Remaining requests in current window
  - `X-RateLimit-Reset`: Window reset time (Unix timestamp)

**Example response with rate limit headers**:
```http
HTTP/1.1 200 OK
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1705398720
Content-Type: application/json
```

## Pagination

### Request Parameters

- `page` (int): Page number (1-based, default: 1)
- `per_page` (int): Items per page (default: 50, max: 1000)
- `sort_by` (string): Sort field (default: varies by endpoint)
- `sort_order` (string): Sort order (`asc` or `desc`, default: `asc`)

### Response Format

```json
{
  "success": true,
  "data": [...],
  "pagination": {
    "page": 2,
    "per_page": 50,
    "total_pages": 10,
    "total_items": 500,
    "has_next": true,
    "has_prev": true
  }
}
```

## Client Libraries

### cURL Examples

**List nodes with filtering**:
```bash
curl -H "Authorization: Bearer $TOKEN" \
     -G \
     -d "page=1" \
     -d "per_page=25" \
     -d "online=true" \
     -d "tag=production" \
     "https://api.ghostwire.example.com/api/v1/nodes"
```

**Create a user**:
```bash
curl -X POST \
     -H "X-API-Key: $API_KEY" \
     -H "Content-Type: application/json" \
     -d '{"name":"charlie","email":"charlie@example.com","is_admin":false}' \
     "https://api.ghostwire.example.com/api/v1/users"
```

### JavaScript/TypeScript

```typescript
// Using fetch API
class GhostWireAPI {
  constructor(
    private baseURL: string,
    private token: string,
    private tokenType: 'Bearer' | 'API-Key' = 'Bearer'
  ) {}

  private async request<T>(
    endpoint: string,
    options: RequestInit = {}
  ): Promise<T> {
    const url = `${this.baseURL}${endpoint}`;
    const headers = {
      'Content-Type': 'application/json',
      ...(this.tokenType === 'Bearer'
        ? { Authorization: `Bearer ${this.token}` }
        : { 'X-API-Key': this.token }
      ),
      ...options.headers,
    };

    const response = await fetch(url, { ...options, headers });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(`API Error: ${error.message}`);
    }

    return response.json();
  }

  async getNodes(params?: {
    page?: number;
    per_page?: number;
    online?: boolean;
    tag?: string;
  }) {
    const searchParams = new URLSearchParams();
    if (params) {
      Object.entries(params).forEach(([key, value]) => {
        if (value !== undefined) {
          searchParams.append(key, String(value));
        }
      });
    }

    return this.request(`/api/v1/nodes?${searchParams}`);
  }

  async createUser(userData: {
    name: string;
    email?: string;
    is_admin?: boolean;
  }) {
    return this.request('/api/v1/users', {
      method: 'POST',
      body: JSON.stringify(userData),
    });
  }

  async getNetworkMap(nodeId: string, sessionToken: string) {
    return this.request(`/api/v1/nodes/${nodeId}/network-map`, {
      headers: {
        'X-Session-Token': sessionToken,
      },
    });
  }
}

// Usage
const api = new GhostWireAPI('https://api.ghostwire.example.com', 'your-token');

const nodes = await api.getNodes({ online: true, tag: 'production' });
console.log(`Found ${nodes.data.length} online production nodes`);
```

### Python

```python
import requests
from typing import Optional, Dict, Any

class GhostWireAPI:
    def __init__(self, base_url: str, token: str, token_type: str = 'Bearer'):
        self.base_url = base_url.rstrip('/')
        self.token = token
        self.token_type = token_type
        self.session = requests.Session()

        if token_type == 'Bearer':
            self.session.headers.update({'Authorization': f'Bearer {token}'})
        else:
            self.session.headers.update({'X-API-Key': token})

    def request(self, method: str, endpoint: str, **kwargs) -> Dict[str, Any]:
        url = f"{self.base_url}{endpoint}"
        response = self.session.request(method, url, **kwargs)
        response.raise_for_status()
        return response.json()

    def get_nodes(self, **params) -> Dict[str, Any]:
        return self.request('GET', '/api/v1/nodes', params=params)

    def create_user(self, name: str, email: Optional[str] = None,
                   is_admin: bool = False) -> Dict[str, Any]:
        data = {'name': name, 'is_admin': is_admin}
        if email:
            data['email'] = email
        return self.request('POST', '/api/v1/users', json=data)

    def get_network_map(self, node_id: str, session_token: str) -> Dict[str, Any]:
        headers = {'X-Session-Token': session_token}
        return self.request('GET', f'/api/v1/nodes/{node_id}/network-map',
                          headers=headers)

# Usage
api = GhostWireAPI('https://api.ghostwire.example.com', 'your-token')

nodes = api.get_nodes(online=True, tag='production')
print(f"Found {len(nodes['data'])} online production nodes")
```

## Testing

### Unit Testing

```bash
# Run REST API tests
cargo test --package ghostwire-server rest::

# Run specific test
cargo test --package ghostwire-server test_node_creation
```

### Integration Testing

```bash
# Start test server
cargo run --bin ghostwire-server -- --config test-config.yaml &

# Run integration tests
./scripts/test-api.sh

# Load testing
wrk -t12 -c400 -d30s \
    -H "Authorization: Bearer $TOKEN" \
    http://localhost:8081/api/v1/nodes
```

## Security Considerations

### Production Deployment

1. **Use HTTPS**: Always deploy with TLS encryption
2. **API Key Security**: Use strong, randomly generated API keys
3. **Token Expiration**: Set reasonable JWT expiration times
4. **Rate Limiting**: Configure appropriate limits for your use case
5. **CORS**: Configure CORS policies for web applications
6. **Input Validation**: Never trust client input
7. **Audit Logging**: Monitor all administrative actions

### Security Headers

The API automatically includes security headers:

```http
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Referrer-Policy: strict-origin-when-cross-origin
Cache-Control: no-cache, no-store, must-revalidate
```

This REST API provides a comprehensive, secure, and scalable interface for managing GhostWire mesh networks through standard HTTP/JSON protocols.