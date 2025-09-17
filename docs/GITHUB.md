# GitHub SSO Setup Guide

This guide covers setting up GhostWire with GitHub for Single Sign-On authentication using OAuth 2.0. Supports both GitHub.com and GitHub Enterprise Server.

## Prerequisites

- GitHub organization or GitHub Enterprise account
- GhostWire server with SSL/TLS enabled
- Organization admin access for GitHub Apps

## GitHub OAuth App Setup

### 1. Create OAuth App

1. Go to your GitHub organization: `https://github.com/organizations/{org}/settings/applications`
2. Click **New OAuth App**
3. Configure the application:
   - **Application name**: `GhostWire Mesh VPN`
   - **Homepage URL**: `https://ghostwire.yourdomain.com`
   - **Application description**: `Secure mesh VPN access for {organization}`
   - **Authorization callback URL**: `https://ghostwire.yourdomain.com/auth/callback`

### 2. Note Credentials

After creating the app:
- **Client ID**: Copy this value
- **Generate a new client secret**: Copy the secret immediately

### 3. Configure App Settings

1. **Enable device flow** (for CLI authentication)
2. **Request user authorization on install**: Enabled
3. **Expire user authorization tokens**: Enabled (recommended)

## GitHub Enterprise Setup (Optional)

### For GitHub Enterprise Server

1. Follow the same steps in your GitHub Enterprise instance
2. Update endpoints in configuration:
   ```yaml
   auth:
     oidc:
       provider_url: "https://github.yourdomain.com"
       token_endpoint: "https://github.yourdomain.com/login/oauth/access_token"
       auth_endpoint: "https://github.yourdomain.com/login/oauth/authorize"
   ```

## GhostWire Configuration

### Basic Configuration

```yaml
# server.yaml
auth:
  oidc:
    enabled: true
    # GitHub uses OAuth 2.0, not OpenID Connect
    provider_type: "github"
    provider_url: "https://github.com"
    client_id: "your-github-client-id"
    client_secret: "${OIDC_CLIENT_SECRET}"
    redirect_uri: "https://ghostwire.yourdomain.com/auth/callback"

    # GitHub OAuth endpoints
    auth_endpoint: "https://github.com/login/oauth/authorize"
    token_endpoint: "https://github.com/login/oauth/access_token"
    user_endpoint: "https://api.github.com/user"

    # GitHub OAuth scopes
    scopes:
      - "user:email"
      - "read:user"
      - "read:org"  # For organization membership

  user_mapping:
    auto_create_users: true

    # Restrict to organization members
    github:
      required_organization: "your-github-org"

    # Admin users
    admin_users:
      - "admin-github-username"
      - "sysadmin-github-username"

    # Default permissions
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

### Advanced Configuration with Teams

```yaml
# server.yaml
auth:
  oidc:
    enabled: true
    provider_type: "github"
    provider_url: "https://github.com"
    client_id: "your-github-client-id"
    client_secret: "${OIDC_CLIENT_SECRET}"
    redirect_uri: "https://ghostwire.yourdomain.com/auth/callback"

    # GitHub-specific endpoints
    auth_endpoint: "https://github.com/login/oauth/authorize"
    token_endpoint: "https://github.com/login/oauth/access_token"
    user_endpoint: "https://api.github.com/user"

    # Extended scopes for team access
    scopes:
      - "user:email"
      - "read:user"
      - "read:org"
      - "read:team"  # For team membership

    # GitHub-specific configuration
    github:
      # Required organization
      required_organization: "your-github-org"

      # Team-based access control
      team_access:
        enabled: true

        # Map GitHub teams to permissions
        team_mapping:
          "admins": ["admin"]
          "developers": ["node:read", "node:write"]
          "devops": ["admin", "node:manage"]
          "readonly": ["node:read"]

      # Enterprise configuration (if using GitHub Enterprise)
      enterprise_url: "https://github.yourdomain.com"  # Optional

  user_mapping:
    auto_create_users: true

    # Organization/team-based permissions
    provision_rules:
      - condition: "teams contains 'admins'"
        permissions: ["admin"]
      - condition: "teams contains 'developers'"
        permissions: ["node:read", "node:write"]
      - condition: "organization == 'your-github-org'"
        permissions: ["node:read"]
```

### Environment Variables

```bash
# Required
OIDC_CLIENT_SECRET=your-github-client-secret
JWT_SECRET=your-secure-jwt-secret-minimum-256-bits

# Optional
GITHUB_ORG=your-github-org  # Organization name
GITHUB_ENTERPRISE_URL=https://github.yourdomain.com  # For GitHub Enterprise
```

## Team-Based Access Control

### 1. Organization Setup

Create teams in your GitHub organization:

1. Go to `https://github.com/orgs/{org}/teams`
2. Create teams:
   - `@your-org/ghostwire-admins` - Full administrative access
   - `@your-org/ghostwire-users` - Standard VPN access
   - `@your-org/ghostwire-readonly` - Read-only monitoring access

### 2. Team Permissions Mapping

```yaml
auth:
  user_mapping:
    github:
      team_mapping:
        # Use team slugs (lowercase, hyphenated)
        "ghostwire-admins": ["admin"]
        "ghostwire-users": ["node:read", "node:write", "user:read"]
        "ghostwire-readonly": ["node:read"]

        # Department-based teams
        "engineering": ["node:read", "node:write"]
        "devops": ["admin", "node:manage"]
        "security": ["admin", "audit:read"]
```

### 3. Nested Team Support

```yaml
auth:
  user_mapping:
    github:
      # Include child teams
      include_child_teams: true

      # Team hierarchy mapping
      team_hierarchy:
        "engineering":
          - "frontend-team"
          - "backend-team"
          - "mobile-team"
        "operations":
          - "devops-team"
          - "security-team"
```

## Device Flow for CLI

### Configuration

```yaml
auth:
  oidc:
    device_flow:
      enabled: true
      # GitHub device flow endpoints
      device_endpoint: "https://github.com/login/device/code"
      token_endpoint: "https://github.com/login/oauth/access_token"

      # GitHub-specific parameters
      github:
        # Include organization in device flow
        include_organization: true
```

### Usage

```bash
# CLI authentication
$ ghostwire auth login --provider github
Please visit: https://github.com/login/device
Enter code: ABCD-EFGH
Waiting for authorization...
✓ Authentication successful

# Organization-specific login
$ ghostwire auth login --provider github --org your-github-org
```

## Advanced Features

### 1. Fine-Grained Access Control

```yaml
auth:
  user_mapping:
    github:
      # Repository-based access (if using GitHub Apps)
      repository_access:
        "your-org/infrastructure": ["admin"]
        "your-org/vpn-config": ["node:write"]

      # Permission based on GitHub role
      organization_roles:
        "owner": ["admin"]
        "member": ["node:read", "node:write"]
        "billing_manager": ["node:read"]
```

### 2. Time-Based Access

```yaml
auth:
  user_mapping:
    github:
      # Temporary access for contractors
      contractor_access:
        enabled: true
        max_duration_days: 30
        requires_approval: true

      # Team-based expiration
      team_expiration:
        "contractors": 30  # days
        "interns": 90      # days
```

### 3. IP Restrictions

```yaml
auth:
  security:
    github:
      # Restrict based on GitHub's last known IP
      verify_ip_restrictions: true

      # Additional IP allowlists
      allowed_ip_ranges:
        - "192.168.1.0/24"    # Office network
        - "10.0.0.0/8"        # VPN network
```

## Security Considerations

### 1. Organization Security

```yaml
auth:
  security:
    github:
      # Require 2FA for organization members
      require_2fa: true

      # Verify organization membership is public
      require_public_membership: false

      # Check for verified email
      require_verified_email: true
```

### 2. Token Security

```yaml
auth:
  jwt:
    # Short-lived tokens for GitHub users
    expiration_hours: 2

    # GitHub-specific claims validation
    validate_github_claims: true

    # Include GitHub metadata in tokens
    include_github_metadata: true
```

### 3. Audit Logging

```yaml
auth:
  audit:
    github:
      # Log all GitHub API calls
      log_api_calls: true

      # Track team membership changes
      monitor_team_changes: true

      # Alert on suspicious activity
      security_alerts:
        - "new_organization_member"
        - "team_permission_change"
        - "failed_2fa_verification"
```

## Troubleshooting

### Common Issues

#### 1. "Bad verification code"

**Solution**: Check OAuth app configuration:
```bash
# Verify callback URL
echo "Configured: https://ghostwire.yourdomain.com/auth/callback"

# Test OAuth flow
curl -X POST "https://github.com/login/oauth/access_token" \
  -H "Accept: application/json" \
  -d "client_id={client_id}&client_secret={client_secret}&code={auth_code}"
```

#### 2. "Not a member of organization"

**Solution**: Verify organization membership:
```bash
# Check organization membership
curl -H "Authorization: token $GITHUB_TOKEN" \
     "https://api.github.com/orgs/{org}/members/{username}"

# Check user's organizations
curl -H "Authorization: token $GITHUB_TOKEN" \
     "https://api.github.com/user/orgs"
```

#### 3. "Insufficient permissions"

**Solution**: Check OAuth scopes:
```bash
# Verify token scopes
curl -H "Authorization: token $GITHUB_TOKEN" \
     "https://api.github.com/user" -I | grep X-OAuth-Scopes

# Required scopes: user:email, read:user, read:org
```

#### 4. Team access not working

**Solution**: Verify team membership API:
```bash
# Check team membership
curl -H "Authorization: token $GITHUB_TOKEN" \
     "https://api.github.com/orgs/{org}/teams/{team}/members/{username}"

# List user's teams
curl -H "Authorization: token $GITHUB_TOKEN" \
     "https://api.github.com/user/teams"
```

### Debug Commands

```bash
# Test GitHub OAuth flow
ghostwire auth test-github --org your-github-org

# Validate organization membership
ghostwire auth check-github-membership username --org your-github-org

# List user's teams
ghostwire auth list-github-teams username --org your-github-org

# Test device flow
ghostwire auth device-flow-test --provider github
```

### Monitoring

Monitor GitHub authentication:

```yaml
# Prometheus metrics
ghostwire_auth_github_success_total
ghostwire_auth_github_failure_total{reason="org_membership_required"}
ghostwire_auth_github_api_requests_total{endpoint="user"}
ghostwire_auth_github_team_sync_duration_seconds
```

## GitHub App Alternative (Advanced)

### Create GitHub App

For enhanced security and permissions:

1. Go to `https://github.com/organizations/{org}/settings/apps`
2. Click **New GitHub App**
3. Configure:
   - **App name**: `GhostWire VPN`
   - **Homepage URL**: `https://ghostwire.yourdomain.com`
   - **Callback URL**: `https://ghostwire.yourdomain.com/auth/github/callback`
   - **Webhook URL**: `https://ghostwire.yourdomain.com/webhooks/github`

### App Permissions

```yaml
# GitHub App permissions
permissions:
  # User data
  members: read
  emails: read

  # Organization data
  organization_plan: read
  organization_user_blocking: read

  # Team data (if using teams)
  organization_administration: read
```

### Configuration

```yaml
auth:
  github_app:
    enabled: true
    app_id: "123456"
    installation_id: "789012"
    private_key: "${GITHUB_APP_PRIVATE_KEY}"

    # Webhook verification
    webhook_secret: "${GITHUB_WEBHOOK_SECRET}"

    # Real-time updates
    webhook_events:
      - "member_added"
      - "member_removed"
      - "team_membership"
```

## Migration Guide

### From Basic Auth to GitHub OAuth

```bash
# Export existing users
ghostwire users export --format json > users.json

# Map emails to GitHub usernames
ghostwire auth map-github-users users.json > github-mapping.json

# Update configuration
vim server.yaml  # Add GitHub OAuth configuration

# Import with GitHub mapping
ghostwire auth import-users github-mapping.json --provider github
```

### From Other OAuth Providers

```bash
# Export user permissions
ghostwire auth export-permissions > permissions.json

# Update configuration for GitHub
vim server.yaml

# Restart server
systemctl restart ghostwire-server

# Import permissions with team mapping
ghostwire auth import-permissions permissions.json --map-to-github-teams
```

This comprehensive guide provides everything needed to integrate GhostWire with GitHub for enterprise SSO authentication using either OAuth Apps or GitHub Apps.