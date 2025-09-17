# Microsoft Azure/Entra ID SSO Setup Guide

This guide covers setting up GhostWire with Microsoft Azure Active Directory (now called Microsoft Entra ID) for Single Sign-On authentication.

## Prerequisites

- Azure Active Directory tenant with admin access
- GhostWire server with SSL/TLS enabled
- Domain name pointing to your GhostWire server

## Azure App Registration

### 1. Create App Registration

1. Navigate to the [Azure Portal](https://portal.azure.com)
2. Go to **Azure Active Directory** → **App registrations**
3. Click **New registration**
4. Configure the application:
   - **Name**: `GhostWire Mesh VPN`
   - **Supported account types**:
     - Single tenant: `Accounts in this organizational directory only`
     - Multi-tenant: `Accounts in any organizational directory`
   - **Redirect URI**: `Web` → `https://ghostwire.yourdomain.com/auth/callback`

### 2. Configure Authentication

1. Go to **Authentication** in your app registration
2. Add additional redirect URIs if needed:
   - Web: `https://ghostwire.yourdomain.com/auth/callback`
   - SPA: `https://ghostwire.yourdomain.com/auth/spa-callback` (for frontend)
3. Configure **Front-channel logout URL**: `https://ghostwire.yourdomain.com/auth/logout`
4. Under **Implicit grant and hybrid flows**:
   - ✅ Access tokens (used for implicit flows)
   - ✅ ID tokens (used for implicit and hybrid flows)

### 3. Create Client Secret

1. Go to **Certificates & secrets**
2. Click **New client secret**
3. Set description: `GhostWire Server Secret`
4. Set expiration: `24 months` (recommended)
5. **Copy the secret value immediately** - you won't be able to see it again

### 4. Configure API Permissions

1. Go to **API permissions**
2. Add the following permissions:
   - **Microsoft Graph**:
     - `openid` (Sign users in)
     - `profile` (View users' basic profile)
     - `email` (View users' email address)
     - `User.Read` (Sign in and read user profile)
     - `GroupMember.Read.All` (Read group memberships) - Optional for group-based access
3. Click **Grant admin consent** for your organization

### 5. Configure Token Configuration (Optional)

1. Go to **Token configuration**
2. Add optional claims for ID tokens:
   - `email`
   - `family_name`
   - `given_name`
   - `upn` (User Principal Name)
   - `groups` (if using group-based access control)

## GhostWire Configuration

### Single Tenant Setup

For single tenant (most common):

```yaml
# server.yaml
auth:
  oidc:
    enabled: true
    provider_url: "https://login.microsoftonline.com/{tenant-id}/v2.0"
    client_id: "your-application-client-id"
    client_secret: "${OIDC_CLIENT_SECRET}"
    redirect_uri: "https://ghostwire.yourdomain.com/auth/callback"
    scopes:
      - "openid"
      - "profile"
      - "email"
      - "User.Read"

  user_mapping:
    auto_create_users: true
    admin_users:
      - "admin@yourdomain.com"
      - "sysadmin@yourdomain.com"

    # Optional: Map Azure AD groups to GhostWire permissions
    group_mapping:
      "GhostWire Admins": ["admin"]
      "GhostWire Users": ["node:read", "node:write"]
      "GhostWire ReadOnly": ["node:read"]

  jwt:
    secret: "${JWT_SECRET}"
    expiration_hours: 24
    refresh_expiration_hours: 168
    issuer: "ghostwire-server"
    audience: "ghostwire-api"
```

### Multi-Tenant Setup

For multi-tenant organizations:

```yaml
# server.yaml
auth:
  oidc:
    enabled: true
    provider_url: "https://login.microsoftonline.com/common/v2.0"  # Note: 'common'
    client_id: "your-application-client-id"
    client_secret: "${OIDC_CLIENT_SECRET}"
    redirect_uri: "https://ghostwire.yourdomain.com/auth/callback"
    scopes:
      - "openid"
      - "profile"
      - "email"
      - "User.Read"

    # Multi-tenant specific configuration
    additional_params:
      # Restrict to specific tenants (optional)
      tenant_ids:
        - "tenant-id-1"
        - "tenant-id-2"

      # Prompt for tenant selection
      prompt: "select_account"
```

### Environment Variables

```bash
# Required secrets
OIDC_CLIENT_SECRET=your-azure-client-secret
JWT_SECRET=your-secure-jwt-secret-minimum-256-bits

# Optional Azure-specific settings
AZURE_TENANT_ID=your-tenant-id  # For single tenant
AZURE_TENANT_RESTRICTION=yourdomain.com  # Restrict to specific domain
```

## Advanced Configuration

### Group-Based Access Control

To use Azure AD groups for access control:

1. **Enable Group Claims**:
   ```yaml
   auth:
     oidc:
       scopes:
         - "openid"
         - "profile"
         - "email"
         - "User.Read"
         - "GroupMember.Read.All"
   ```

2. **Configure Group Mapping**:
   ```yaml
   auth:
     user_mapping:
       group_mapping:
         # Use Azure AD Group Object IDs
         "12345678-1234-1234-1234-123456789abc": ["admin"]
         "87654321-4321-4321-4321-cba987654321": ["node:read", "node:write"]

         # Or use Group Names (requires additional setup)
         "GhostWire Administrators": ["admin"]
         "VPN Users": ["node:read", "node:write"]
   ```

### Conditional Access Policies

Configure Azure Conditional Access for enhanced security:

1. **Create Conditional Access Policy**:
   - Target: Your GhostWire application
   - Conditions: Device compliance, location, risk level
   - Access controls: Require MFA, compliant device

2. **Example Policy**:
   ```json
   {
     "displayName": "GhostWire VPN Access",
     "state": "enabled",
     "conditions": {
       "applications": {
         "includeApplications": ["your-ghostwire-app-id"]
       },
       "users": {
         "includeGroups": ["ghostwire-users-group-id"]
       },
       "locations": {
         "excludeLocations": ["trusted-network-location-id"]
       }
     },
     "grantControls": {
       "operator": "AND",
       "builtInControls": ["mfa", "compliantDevice"]
     }
   }
   ```

### Device Flow for CLI

Configure device flow for CLI authentication:

```yaml
# server.yaml
auth:
  oidc:
    device_flow:
      enabled: true
      # Azure automatically supports device flow
      device_endpoint: "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/devicecode"
      token_endpoint: "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
```

## Tenant-Specific Considerations

### Single Tenant Deployment

```yaml
auth:
  oidc:
    provider_url: "https://login.microsoftonline.com/12345678-1234-1234-1234-123456789abc/v2.0"
    validation:
      # Validate tenant ID in tokens
      tenant_id: "12345678-1234-1234-1234-123456789abc"

      # Restrict to specific domains
      allowed_domains:
        - "yourdomain.com"
        - "subsidiary.yourdomain.com"
```

### Multi-Tenant Deployment

```yaml
auth:
  oidc:
    provider_url: "https://login.microsoftonline.com/common/v2.0"
    validation:
      # Allow specific tenants only
      allowed_tenants:
        - "12345678-1234-1234-1234-123456789abc"  # Main org
        - "87654321-4321-4321-4321-cba987654321"  # Partner org

      # Or allow all tenants but restrict domains
      allowed_domains:
        - "yourdomain.com"
        - "partner.com"
```

## Security Best Practices

### 1. Certificate Validation

```yaml
auth:
  oidc:
    # Validate certificates (default: true)
    validate_certificates: true

    # Pin specific certificate thumbprints (optional)
    pinned_certificates:
      - "certificate-thumbprint-1"
      - "certificate-thumbprint-2"
```

### 2. Token Validation

```yaml
auth:
  jwt:
    # Short access token lifetime
    expiration_hours: 1

    # Longer refresh token lifetime
    refresh_expiration_hours: 24

    # Validate issuer and audience
    strict_validation: true
```

### 3. Rate Limiting

```yaml
auth:
  rate_limiting:
    # Limit authentication attempts
    max_attempts_per_minute: 10
    max_attempts_per_hour: 100

    # Lockout duration
    lockout_duration_minutes: 15
```

## Troubleshooting

### Common Issues

#### 1. "AADSTS50011: The reply URL specified in the request does not match"

**Solution**: Check redirect URI configuration:
- Ensure exact match in Azure portal
- Include protocol (https://)
- No trailing slash differences

#### 2. "AADSTS65001: The user or administrator has not consented"

**Solution**: Grant admin consent:
```bash
# Test consent URL
curl "https://login.microsoftonline.com/{tenant}/adminconsent?client_id={client_id}&redirect_uri={redirect_uri}"
```

#### 3. "Invalid client secret"

**Solution**: Regenerate client secret:
1. Go to Azure portal → App registration → Certificates & secrets
2. Create new secret
3. Update environment variable

#### 4. Multi-tenant access issues

**Solution**: Verify multi-tenant configuration:
```bash
# Test token endpoint
curl -X POST "https://login.microsoftonline.com/common/oauth2/v2.0/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id={client_id}&client_secret={client_secret}&grant_type=client_credentials&scope=https://graph.microsoft.com/.default"
```

### Debug Commands

```bash
# Test OIDC discovery
curl https://login.microsoftonline.com/{tenant}/v2.0/.well-known/openid_configuration

# Validate token
ghostwire auth validate-token $TOKEN

# Test group membership
curl -H "Authorization: Bearer $TOKEN" \
     "https://graph.microsoft.com/v1.0/me/memberOf"

# Check Conditional Access policies
az ad user get-member-groups --id user@domain.com
```

### Monitoring

Monitor authentication metrics:

```yaml
# Prometheus metrics
ghostwire_auth_azure_success_total
ghostwire_auth_azure_failure_total{reason="consent_required"}
ghostwire_auth_azure_group_sync_duration_seconds
```

## Migration Guide

### From Legacy Azure AD

1. Update endpoint URLs:
   ```yaml
   # Old
   provider_url: "https://login.microsoftonline.com/{tenant}/oauth2/authorize"

   # New
   provider_url: "https://login.microsoftonline.com/{tenant}/v2.0"
   ```

2. Update scopes:
   ```yaml
   # Old
   scopes: ["https://graph.microsoft.com/User.Read"]

   # New
   scopes: ["openid", "profile", "email", "User.Read"]
   ```

### From Other Providers

```bash
# Export existing users
ghostwire auth export-users --format json > users.json

# Update configuration for Azure
vim server.yaml

# Import users with Azure mapping
ghostwire auth import-users users.json --provider azure --map-emails
```

This comprehensive guide provides everything needed to integrate GhostWire with Microsoft Azure/Entra ID for enterprise SSO authentication.