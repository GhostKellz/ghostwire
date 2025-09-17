# Google Workspace SSO Setup Guide

This guide covers setting up GhostWire with Google Workspace (formerly G Suite) for Single Sign-On authentication using OpenID Connect.

## Prerequisites

- Google Workspace admin account
- GhostWire server with SSL/TLS enabled
- Domain verified in Google Workspace
- Google Cloud Console access

## Google Cloud Console Setup

### 1. Create Project

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select existing one:
   - **Project Name**: `GhostWire VPN`
   - **Organization**: Your Google Workspace organization

### 2. Enable APIs

1. Navigate to **APIs & Services** → **Library**
2. Enable the following APIs:
   - **Google+ API** (for profile information)
   - **Admin SDK** (for group membership - optional)
   - **People API** (for user details)

### 3. Configure OAuth Consent Screen

1. Go to **APIs & Services** → **OAuth consent screen**
2. Choose **Internal** (for Workspace users only) or **External**
3. Fill in application information:
   - **App name**: `GhostWire Mesh VPN`
   - **User support email**: `admin@yourdomain.com`
   - **App domain**: `https://ghostwire.yourdomain.com`
   - **Authorized domains**: `yourdomain.com`
   - **Developer contact**: `admin@yourdomain.com`

4. Add scopes:
   - `openid`
   - `email`
   - `profile`
   - `https://www.googleapis.com/auth/admin.directory.group.readonly` (for groups)

### 4. Create OAuth 2.0 Credentials

1. Go to **APIs & Services** → **Credentials**
2. Click **Create Credentials** → **OAuth 2.0 Client IDs**
3. Configure the client:
   - **Application type**: `Web application`
   - **Name**: `GhostWire Server`
   - **Authorized JavaScript origins**: `https://ghostwire.yourdomain.com`
   - **Authorized redirect URIs**: `https://ghostwire.yourdomain.com/auth/callback`

4. **Download the JSON file** or copy the Client ID and Client Secret

## Google Workspace Admin Configuration

### 1. Configure SSO App

1. Go to [Google Admin Console](https://admin.google.com)
2. Navigate to **Apps** → **Web and mobile apps**
3. Click **Add app** → **Add custom SAML app** or use OAuth app
4. Configure app settings:
   - **App name**: `GhostWire VPN`
   - **Description**: `Secure mesh VPN access`

### 2. Set User Access

1. In the app configuration, go to **User access**
2. Configure organizational units:
   - **ON for everyone**: All users can access
   - **OFF for everyone, ON for some**: Specific groups/OUs only
3. Optionally restrict by groups:
   - Create Google Groups: `ghostwire-admins@yourdomain.com`, `ghostwire-users@yourdomain.com`

### 3. Configure Groups (Optional)

For group-based access control:

1. Go to **Directory** → **Groups**
2. Create groups:
   - `ghostwire-admins@yourdomain.com` - Admin access
   - `ghostwire-users@yourdomain.com` - Standard user access
   - `ghostwire-readonly@yourdomain.com` - Read-only access

## GhostWire Configuration

### Basic Configuration

```yaml
# server.yaml
auth:
  oidc:
    enabled: true
    provider_url: "https://accounts.google.com"
    client_id: "your-google-client-id.apps.googleusercontent.com"
    client_secret: "${OIDC_CLIENT_SECRET}"
    redirect_uri: "https://ghostwire.yourdomain.com/auth/callback"
    scopes:
      - "openid"
      - "email"
      - "profile"

  user_mapping:
    auto_create_users: true

    # Domain restriction
    allowed_domains:
      - "yourdomain.com"

    # Admin users
    admin_users:
      - "admin@yourdomain.com"
      - "sysadmin@yourdomain.com"

    # Default permissions for new users
    default_permissions:
      - "node:read"
      - "node:write"
      - "user:read"

  jwt:
    secret: "${JWT_SECRET}"
    expiration_hours: 24
    refresh_expiration_hours: 168
    issuer: "ghostwire-server"
    audience: "ghostwire-api"
```

### Advanced Configuration with Groups

```yaml
# server.yaml
auth:
  oidc:
    enabled: true
    provider_url: "https://accounts.google.com"
    client_id: "your-google-client-id.apps.googleusercontent.com"
    client_secret: "${OIDC_CLIENT_SECRET}"
    redirect_uri: "https://ghostwire.yourdomain.com/auth/callback"
    scopes:
      - "openid"
      - "email"
      - "profile"
      - "https://www.googleapis.com/auth/admin.directory.group.readonly"

    # Google-specific configuration
    google:
      # Enable group synchronization
      sync_groups: true

      # Domain restriction (Workspace domain)
      hosted_domain: "yourdomain.com"

      # Service account for group API access
      service_account_key: "${GOOGLE_SERVICE_ACCOUNT_KEY}"

  user_mapping:
    auto_create_users: true

    # Restrict to Workspace domain
    allowed_domains:
      - "yourdomain.com"

    # Group-based permissions
    group_mapping:
      "ghostwire-admins@yourdomain.com": ["admin"]
      "ghostwire-users@yourdomain.com": ["node:read", "node:write"]
      "ghostwire-readonly@yourdomain.com": ["node:read"]

    # Domain-based auto-admin (optional)
    admin_domains:
      - "admin.yourdomain.com"
```

### Environment Variables

```bash
# Required
OIDC_CLIENT_SECRET=your-google-client-secret
JWT_SECRET=your-secure-jwt-secret-minimum-256-bits

# Optional - for group sync
GOOGLE_SERVICE_ACCOUNT_KEY=base64-encoded-service-account-json
GOOGLE_WORKSPACE_DOMAIN=yourdomain.com

# Optional - for domain restriction
GOOGLE_HOSTED_DOMAIN=yourdomain.com
```

## Service Account Setup (For Group Sync)

### 1. Create Service Account

1. In Google Cloud Console, go to **IAM & Admin** → **Service Accounts**
2. Click **Create Service Account**:
   - **Name**: `ghostwire-group-sync`
   - **Description**: `Service account for GhostWire group synchronization`
3. Create and download the JSON key file

### 2. Enable Domain-Wide Delegation

1. Edit the service account
2. Check **Enable Google Workspace Domain-wide Delegation**
3. Note the **Client ID** of the service account

### 3. Configure Workspace Admin

1. Go to [Google Admin Console](https://admin.google.com)
2. Navigate to **Security** → **API Controls** → **Domain-wide Delegation**
3. Add the service account Client ID with these scopes:
   ```
   https://www.googleapis.com/auth/admin.directory.group.readonly
   https://www.googleapis.com/auth/admin.directory.user.readonly
   ```

### 4. Configure GhostWire

```bash
# Encode service account JSON
cat service-account.json | base64 -w 0 > service-account.b64

# Set environment variable
export GOOGLE_SERVICE_ACCOUNT_KEY=$(cat service-account.b64)
```

## Device Flow for CLI

### Configuration

```yaml
# server.yaml
auth:
  oidc:
    device_flow:
      enabled: true
      # Google device flow endpoints
      device_endpoint: "https://oauth2.googleapis.com/device/code"
      token_endpoint: "https://oauth2.googleapis.com/token"

      # Polling configuration
      polling_interval: 5
      max_polling_time: 300
```

### Usage

```bash
# CLI authentication
$ ghostwire auth login --provider google
Please visit: https://www.google.com/device
Enter code: ABCD-EFGH
Waiting for authorization...
✓ Authentication successful
```

## Advanced Features

### Domain Restriction

Restrict access to specific Google Workspace domain:

```yaml
auth:
  oidc:
    google:
      # Enforce hosted domain
      hosted_domain: "yourdomain.com"

      # Verify domain in token
      verify_hosted_domain: true
```

### Group Synchronization

Automatic group membership sync:

```yaml
auth:
  oidc:
    google:
      sync_groups: true

      # Group sync interval
      group_sync_interval_hours: 1

      # Group name format
      group_name_format: "email"  # or "name"

      # Only sync specific groups
      sync_group_filter:
        - "ghostwire-*"
        - "vpn-*"
```

### Custom Claims Mapping

```yaml
auth:
  user_mapping:
    # Map Google profile fields
    field_mapping:
      username: "email"  # Use email as username
      display_name: "name"
      avatar_url: "picture"

    # Custom attribute mapping
    custom_claims:
      department: "organizations.department"
      location: "organizations.location"
```

## Security Considerations

### 1. Client Secret Security

```bash
# Use Google Secret Manager (recommended)
gcloud secrets create ghostwire-oidc-secret --data-file=client_secret.txt

# Reference in deployment
export OIDC_CLIENT_SECRET=$(gcloud secrets versions access latest --secret="ghostwire-oidc-secret")
```

### 2. Token Validation

```yaml
auth:
  jwt:
    # Short-lived access tokens
    expiration_hours: 1

    # Validate Google-specific claims
    validate_issuer: true
    validate_audience: true

    # Additional validation
    validate_email_verified: true
```

### 3. Rate Limiting

```yaml
auth:
  rate_limiting:
    # Google OAuth rate limits
    requests_per_minute: 100
    requests_per_day: 10000

    # Per-user limits
    user_requests_per_minute: 10
```

## Troubleshooting

### Common Issues

#### 1. "Error 400: redirect_uri_mismatch"

**Solution**: Verify redirect URI configuration:
```bash
# Check configured URIs
curl -s "https://accounts.google.com/.well-known/openid_configuration"

# Verify in Google Cloud Console
echo "Configured: https://ghostwire.yourdomain.com/auth/callback"
```

#### 2. "Error 403: access_denied"

**Solution**: Check user access configuration:
1. Verify user is in correct Google Workspace OU
2. Check app access settings in Admin Console
3. Verify domain restrictions

#### 3. "Error: invalid_client"

**Solution**: Verify client credentials:
```bash
# Test client credentials
curl -X POST "https://oauth2.googleapis.com/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id={client_id}&client_secret={client_secret}&grant_type=client_credentials"
```

#### 4. Group sync not working

**Solution**: Check service account configuration:
```bash
# Test service account
ghostwire auth test-google-groups --user admin@yourdomain.com

# Verify delegation
curl -H "Authorization: Bearer $SERVICE_ACCOUNT_TOKEN" \
     "https://admin.googleapis.com/admin/directory/v1/groups"
```

### Debug Commands

```bash
# Test OIDC discovery
curl https://accounts.google.com/.well-known/openid_configuration

# Validate hosted domain
ghostwire auth validate-token $TOKEN --check-hosted-domain

# Test group membership
ghostwire auth list-user-groups user@yourdomain.com

# Check domain verification
dig TXT _googleapi.yourdomain.com
```

### Monitoring

Monitor Google Workspace authentication:

```yaml
# Prometheus metrics
ghostwire_auth_google_success_total
ghostwire_auth_google_failure_total{reason="domain_mismatch"}
ghostwire_auth_google_group_sync_duration_seconds
ghostwire_auth_google_api_requests_total{endpoint="groups"}
```

## Best Practices

### 1. Organization Structure

```yaml
# Organize by department/function
group_mapping:
  "it-team@yourdomain.com": ["admin", "node:manage"]
  "engineering@yourdomain.com": ["node:read", "node:write"]
  "support@yourdomain.com": ["node:read", "user:read"]
```

### 2. Automated User Provisioning

```yaml
auth:
  user_mapping:
    # Auto-provision based on Google profile
    auto_create_users: true

    # Set permissions based on Google Groups
    provision_rules:
      - condition: "groups contains 'admin@yourdomain.com'"
        permissions: ["admin"]
      - condition: "email endsWith '@yourdomain.com'"
        permissions: ["node:read", "node:write"]
```

### 3. Audit and Compliance

```yaml
auth:
  audit:
    # Log all authentication events
    log_authentication: true

    # Export to Google Cloud Logging
    export_to_google_cloud: true

    # Compliance requirements
    retain_logs_days: 90
```

## Migration Guide

### From Google OAuth to OpenID Connect

```bash
# Export existing user mappings
ghostwire auth export-users --format json > users.json

# Update configuration
vim server.yaml  # Change to OIDC endpoints

# Restart server
systemctl restart ghostwire-server

# Verify migration
ghostwire auth test-login --provider google
```

This comprehensive guide provides everything needed to integrate GhostWire with Google Workspace for enterprise SSO authentication.