# Authentication & Authorization Documentation

GhostWire implements a multi-layered authentication system supporting different access levels and authentication methods. This document covers the complete authentication and authorization architecture.

## Authentication Levels

### 1. Anonymous Access
- **Scope**: Public endpoints only
- **Endpoints**: `/health`, `/stats` (basic)
- **Use Case**: Health monitoring, status checks

### 2. Node Authentication
- **Method**: Session tokens
- **Scope**: Node-specific operations
- **Endpoints**: Heartbeat, network map retrieval
- **Use Case**: Node-to-server communication

### 3. User Authentication
- **Method**: JWT/OAuth bearer tokens
- **Scope**: User-owned resources
- **Endpoints**: User's own nodes and data
- **Use Case**: CLI tools, mobile apps

### 4. Administrative Authentication
- **Method**: API keys
- **Scope**: Full system access
- **Endpoints**: All administrative operations
- **Use Case**: Web dashboard, system management

## Authentication Methods

### Session Tokens (Node Authentication)

**Purpose**: Secure, temporary authentication for node operations

**Generation**:
```rust
use blake3::Hasher;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

pub fn generate_session_token(node_public_key: &PublicKey, user_id: &str) -> Result<String> {
    let mut hasher = Hasher::new();

    // Add node public key
    hasher.update(&node_public_key.0);

    // Add user ID
    hasher.update(user_id.as_bytes());

    // Add current timestamp
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_secs();
    hasher.update(&timestamp.to_le_bytes());

    // Add random bytes
    let mut random_bytes = [0u8; 16];
    OsRng.fill_bytes(&mut random_bytes);
    hasher.update(&random_bytes);

    let hash = hasher.finalize();
    Ok(URL_SAFE_NO_PAD.encode(hash.as_bytes()))
}
```

**Usage**:
```bash
# gRPC metadata
authorization: Bearer sess_abc123def456ghi789

# REST header
X-Session-Token: sess_abc123def456ghi789
```

**Validation**:
```rust
pub async fn validate_session_token(
    coordinator: &Coordinator,
    node_id: &NodeId,
    token: &str,
) -> Result<bool> {
    // Check token format
    if !token.starts_with("sess_") {
        return Ok(false);
    }

    // Verify against stored session
    coordinator.validate_session(node_id, token).await
}
```

### JWT Bearer Tokens (User Authentication)

**Purpose**: Stateless authentication for user operations

**Token Structure**:
```json
{
  "header": {
    "alg": "HS256",
    "typ": "JWT"
  },
  "payload": {
    "sub": "user_550e8400-e29b-41d4-a716-446655440000",
    "iss": "ghostwire-server",
    "aud": "ghostwire-api",
    "exp": 1705398600,
    "iat": 1705312200,
    "jti": "jwt_abc123def456",
    "permissions": ["node:read", "node:write"],
    "user_id": "550e8400-e29b-41d4-a716-446655440000",
    "username": "alice",
    "is_admin": false
  }
}
```

**Generation**:
```rust
use jsonwebtoken::{encode, Header, EncodingKey};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    iss: String,
    aud: String,
    exp: usize,
    iat: usize,
    jti: String,
    permissions: Vec<String>,
    user_id: String,
    username: String,
    is_admin: bool,
}

pub fn generate_jwt_token(
    user: &User,
    secret: &[u8],
    expiration_hours: u64,
) -> Result<String> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let expiration = now + (expiration_hours * 3600);

    let claims = Claims {
        sub: format!("user_{}", user.id),
        iss: "ghostwire-server".to_string(),
        aud: "ghostwire-api".to_string(),
        exp: expiration as usize,
        iat: now as usize,
        jti: format!("jwt_{}", generate_random_id()),
        permissions: user.get_permissions(),
        user_id: user.id.to_string(),
        username: user.name.clone(),
        is_admin: user.is_admin,
    };

    encode(&Header::default(), &claims, &EncodingKey::from_secret(secret))
        .map_err(|e| GhostWireError::crypto(format!("JWT encoding failed: {}", e)))
}
```

**Validation**:
```rust
use jsonwebtoken::{decode, DecodingKey, Validation};

pub fn validate_jwt_token(token: &str, secret: &[u8]) -> Result<Claims> {
    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret),
        &Validation::default(),
    )?;

    Ok(token_data.claims)
}
```

**Usage**:
```bash
curl -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
     https://api.ghostwire.example.com/api/v1/nodes
```

### API Keys (Administrative Authentication)

**Purpose**: Long-lived authentication for administrative operations

**Format**: `gw_admin_<version>_<32_random_bytes_hex>`

**Generation**:
```rust
use rand::RngCore;

pub fn generate_api_key() -> String {
    let mut key_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut key_bytes);

    format!(
        "gw_admin_v1_{}",
        hex::encode(&key_bytes)
    )
}
```

**Storage**:
```sql
CREATE TABLE api_keys (
    id INTEGER PRIMARY KEY,
    key_hash BLOB NOT NULL UNIQUE,  -- Blake3 hash of the key
    name TEXT NOT NULL,              -- Human-readable name
    permissions TEXT NOT NULL,       -- JSON array of permissions
    created_by INTEGER REFERENCES users(id),
    created_at INTEGER NOT NULL,
    expires_at INTEGER,              -- NULL for no expiration
    last_used_at INTEGER,
    is_active BOOLEAN DEFAULT TRUE
);
```

**Validation**:
```rust
pub async fn validate_api_key(
    db: &DatabaseConnection,
    key: &str,
) -> Result<Option<ApiKeyInfo>> {
    // Check format
    if !key.starts_with("gw_admin_v1_") {
        return Ok(None);
    }

    // Extract and hash the key
    let key_hash = blake3::hash(key.as_bytes());

    // Look up in database
    let api_key = sqlx::query_as!(
        ApiKeyRecord,
        "SELECT * FROM api_keys WHERE key_hash = ? AND is_active = TRUE",
        key_hash.as_bytes()
    )
    .fetch_optional(&db.pool)
    .await?;

    match api_key {
        Some(key_record) => {
            // Check expiration
            if let Some(expires_at) = key_record.expires_at {
                if expires_at < current_timestamp() {
                    return Ok(None);
                }
            }

            // Update last used
            sqlx::query!(
                "UPDATE api_keys SET last_used_at = ? WHERE id = ?",
                current_timestamp(),
                key_record.id
            )
            .execute(&db.pool)
            .await?;

            Ok(Some(ApiKeyInfo {
                id: key_record.id,
                name: key_record.name,
                permissions: serde_json::from_str(&key_record.permissions)?,
                created_by: key_record.created_by,
            }))
        }
        None => Ok(None),
    }
}
```

**Usage**:
```bash
curl -H "X-API-Key: gw_admin_v1_deadbeef0123456789abcdef..." \
     https://api.ghostwire.example.com/api/v1/users
```

## Authorization System

### Permission Model

**Permission Format**: `resource:action`

**Core Permissions**:
```rust
pub enum Permission {
    // Node permissions
    NodeRead,      // "node:read"
    NodeWrite,     // "node:write"
    NodeDelete,    // "node:delete"

    // User permissions
    UserRead,      // "user:read"
    UserWrite,     // "user:write"
    UserDelete,    // "user:delete"

    // ACL permissions
    AclRead,       // "acl:read"
    AclWrite,      // "acl:write"

    // System permissions
    SystemRead,    // "system:read"
    SystemWrite,   // "system:write"

    // Administrative permissions
    Admin,         // "admin" - full access
}
```

### Access Control Rules

```rust
pub struct AccessControl;

impl AccessControl {
    pub fn check_permission(
        auth_context: &AuthContext,
        required_permission: &str,
        resource_owner: Option<&UserId>,
    ) -> Result<bool> {
        match auth_context {
            AuthContext::Admin { permissions, .. } => {
                // Admins with "admin" permission have full access
                Ok(permissions.contains(&"admin".to_string()) ||
                   permissions.contains(&required_permission.to_string()))
            }

            AuthContext::User { user_id, permissions, .. } => {
                // Users can access their own resources
                if let Some(owner) = resource_owner {
                    if user_id == owner {
                        return Ok(Self::user_has_permission(permissions, required_permission));
                    }
                }

                // Check explicit permissions
                Ok(Self::user_has_permission(permissions, required_permission))
            }

            AuthContext::Node { node_id, .. } => {
                // Nodes have limited permissions
                match required_permission {
                    "node:heartbeat" | "node:network-map" | "node:unregister" => Ok(true),
                    _ => Ok(false),
                }
            }

            AuthContext::Anonymous => {
                // Anonymous users have no permissions
                Ok(false)
            }
        }
    }

    fn user_has_permission(permissions: &[String], required: &str) -> bool {
        permissions.contains(&required.to_string()) ||
        permissions.contains(&"admin".to_string())
    }
}
```

### Middleware Implementation

```rust
use axum::{
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::Response,
};

pub async fn auth_middleware(
    headers: HeaderMap,
    State(app_state): State<AppState>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // Extract authentication context
    let auth_context = extract_auth_context(&headers, &app_state).await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    // Add auth context to request extensions
    request.extensions_mut().insert(auth_context);

    Ok(next.run(request).await)
}

pub async fn require_permission(
    permission: &'static str,
) -> impl Fn(AuthContext, Request, Next) -> impl Future<Output = Result<Response, StatusCode>> {
    move |auth_context: AuthContext, request: Request, next: Next| async move {
        // Check if user has required permission
        if !AccessControl::check_permission(&auth_context, permission, None)? {
            return Err(StatusCode::FORBIDDEN);
        }

        Ok(next.run(request).await)
    }
}
```

## OIDC Integration

### Configuration

```yaml
auth:
  oidc:
    enabled: true
    provider: "https://auth.example.com"
    client_id: "ghostwire-server"
    client_secret: "${OIDC_CLIENT_SECRET}"
    redirect_uri: "https://ghostwire.example.com/auth/callback"
    scopes: ["openid", "profile", "email"]

  jwt:
    secret: "${JWT_SECRET}"
    expiration_hours: 24

  session:
    timeout_hours: 24
    cleanup_interval_hours: 1
```

### OIDC Flow Implementation

```rust
use openidconnect::{
    core::{CoreClient, CoreProviderMetadata, CoreResponseType},
    reqwest::async_http_client,
    AuthenticationFlow, AuthorizationCode, ClientId, ClientSecret,
    CsrfToken, IssuerUrl, Nonce, RedirectUrl, Scope,
};

pub struct OidcProvider {
    client: CoreClient,
    config: OidcConfig,
}

impl OidcProvider {
    pub async fn new(config: OidcConfig) -> Result<Self> {
        let provider_metadata = CoreProviderMetadata::discover_async(
            IssuerUrl::new(config.provider_url.clone())?,
            async_http_client,
        ).await?;

        let client = CoreClient::from_provider_metadata(
            provider_metadata,
            ClientId::new(config.client_id.clone()),
            Some(ClientSecret::new(config.client_secret.clone())),
        )
        .set_redirect_uri(RedirectUrl::new(config.redirect_uri.clone())?);

        Ok(Self { client, config })
    }

    pub fn get_authorization_url(&self) -> (String, CsrfToken, Nonce) {
        let (auth_url, csrf_token, nonce) = self
            .client
            .authorize_url(
                AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            .add_scope(Scope::new("openid".to_string()))
            .add_scope(Scope::new("profile".to_string()))
            .add_scope(Scope::new("email".to_string()))
            .url();

        (auth_url.to_string(), csrf_token, nonce)
    }

    pub async fn exchange_code(
        &self,
        code: AuthorizationCode,
        nonce: Nonce,
    ) -> Result<UserInfo> {
        let token_response = self
            .client
            .exchange_code(code)
            .request_async(async_http_client)
            .await?;

        let id_token = token_response
            .id_token()
            .ok_or_else(|| GhostWireError::authentication("No ID token in response"))?;

        let claims = id_token.claims(&self.client.id_token_verifier(), &nonce)?;

        Ok(UserInfo {
            sub: claims.subject().to_string(),
            email: claims.email().map(|e| e.to_string()),
            name: claims.name()
                .and_then(|n| n.get(None))
                .map(|n| n.to_string()),
            picture: claims.picture()
                .and_then(|p| p.get(None))
                .map(|p| p.to_string()),
        })
    }
}
```

### Auth Endpoints

```rust
// Authorization initiation
pub async fn auth_login(
    State(auth_provider): State<OidcProvider>,
) -> Result<impl IntoResponse, StatusCode> {
    let (auth_url, csrf_token, nonce) = auth_provider.get_authorization_url();

    // Store CSRF token and nonce in session/database
    // In production, use secure session storage

    Ok(Redirect::to(&auth_url))
}

// Authorization callback
pub async fn auth_callback(
    Query(params): Query<AuthCallbackParams>,
    State(auth_provider): State<OidcProvider>,
    State(coordinator): State<Arc<Coordinator>>,
) -> Result<impl IntoResponse, StatusCode> {
    // Verify CSRF token
    if !verify_csrf_token(&params.state) {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Exchange code for user info
    let user_info = auth_provider
        .exchange_code(
            AuthorizationCode::new(params.code),
            get_stored_nonce(&params.state)?,
        )
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Create or update user
    let user = coordinator
        .upsert_user_from_oidc(&user_info)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Generate JWT token
    let jwt_token = generate_jwt_token(&user, &get_jwt_secret(), 24)?;

    // Return token (in production, set secure cookie)
    Ok(Json(serde_json::json!({
        "access_token": jwt_token,
        "token_type": "Bearer",
        "expires_in": 86400
    })))
}
```

## CLI Authentication

### Device Flow

For CLI tools, implement OAuth 2.0 Device Authorization Grant:

```rust
pub struct DeviceAuthFlow {
    client: reqwest::Client,
    config: OidcConfig,
}

impl DeviceAuthFlow {
    pub async fn initiate(&self) -> Result<DeviceAuthResponse> {
        let response = self.client
            .post(&format!("{}/device/code", self.config.provider_url))
            .form(&[
                ("client_id", &self.config.client_id),
                ("scope", "openid profile email"),
            ])
            .send()
            .await?;

        Ok(response.json().await?)
    }

    pub async fn poll_for_token(
        &self,
        device_code: &str,
        interval: u64,
    ) -> Result<TokenResponse> {
        loop {
            tokio::time::sleep(Duration::from_secs(interval)).await;

            let response = self.client
                .post(&format!("{}/token", self.config.provider_url))
                .form(&[
                    ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                    ("device_code", device_code),
                    ("client_id", &self.config.client_id),
                ])
                .send()
                .await?;

            match response.status() {
                StatusCode::OK => return Ok(response.json().await?),
                StatusCode::BAD_REQUEST => {
                    let error: DeviceAuthError = response.json().await?;
                    match error.error.as_str() {
                        "authorization_pending" => continue,
                        "slow_down" => {
                            tokio::time::sleep(Duration::from_secs(5)).await;
                            continue;
                        }
                        _ => return Err(GhostWireError::authentication(error.error)),
                    }
                }
                _ => return Err(GhostWireError::authentication("Token request failed")),
            }
        }
    }
}
```

### CLI Usage

```bash
# Initiate device flow
$ ghostwire auth login
Please visit: https://auth.example.com/device
Enter code: ABCD-EFGH
Waiting for authorization...

# Store token securely
$ ghostwire auth status
Authenticated as: alice@example.com
Token expires: 2024-01-16T10:30:00Z

# Use stored token
$ ghostwire nodes list
# Uses stored token automatically
```

## Security Best Practices

### Token Management

1. **Secure Storage**:
   ```rust
   // Use OS keyring for token storage
   use keyring::Entry;

   pub fn store_token(token: &str) -> Result<()> {
       let entry = Entry::new("ghostwire", "access_token")?;
       entry.set_password(token)?;
       Ok(())
   }

   pub fn get_stored_token() -> Result<String> {
       let entry = Entry::new("ghostwire", "access_token")?;
       Ok(entry.get_password()?)
   }
   ```

2. **Token Rotation**:
   ```rust
   pub async fn refresh_token_if_needed(
       current_token: &str,
       refresh_token: &str,
   ) -> Result<Option<String>> {
       let claims = decode_jwt_claims(current_token)?;

       // Refresh if token expires within 10 minutes
       if claims.exp < (current_timestamp() + 600) {
           return Ok(Some(refresh_jwt_token(refresh_token).await?));
       }

       Ok(None)
   }
   ```

3. **Secure Transmission**:
   - Always use HTTPS in production
   - Use secure HTTP headers
   - Implement proper CORS policies

### Rate Limiting

```rust
pub struct RateLimiter {
    buckets: Arc<RwLock<HashMap<IpAddr, TokenBucket>>>,
    config: RateLimitConfig,
}

impl RateLimiter {
    pub async fn check_rate_limit(&self, client_ip: IpAddr) -> Result<()> {
        let mut buckets = self.buckets.write().await;
        let bucket = buckets
            .entry(client_ip)
            .or_insert_with(|| TokenBucket::new(&self.config));

        if !bucket.consume(1) {
            return Err(GhostWireError::ResourceExhausted(
                "Rate limit exceeded".to_string()
            ));
        }

        Ok(())
    }
}
```

### Audit Logging

```rust
pub async fn log_auth_event(
    event_type: AuthEventType,
    user_id: Option<&UserId>,
    client_ip: IpAddr,
    success: bool,
    details: Option<serde_json::Value>,
) {
    let event = AuthEvent {
        timestamp: SystemTime::now(),
        event_type,
        user_id: user_id.map(|u| u.to_string()),
        client_ip: client_ip.to_string(),
        success,
        details,
    };

    // Log to structured logging
    if success {
        info!(
            event_type = ?event.event_type,
            user_id = event.user_id,
            client_ip = %event.client_ip,
            "Authentication event"
        );
    } else {
        warn!(
            event_type = ?event.event_type,
            user_id = event.user_id,
            client_ip = %event.client_ip,
            "Authentication failure"
        );
    }

    // Store in audit log
    store_audit_event(event).await;
}
```

This authentication system provides robust, scalable, and secure access control for GhostWire mesh networks with support for multiple authentication methods and comprehensive authorization policies.