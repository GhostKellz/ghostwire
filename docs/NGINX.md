# NGINX Setup Guide for GhostWire with SSO

This guide covers setting up NGINX as a reverse proxy for GhostWire with SSL/TLS termination and SSO integration for securing the web GUI.

## Prerequisites

- NGINX 1.18+ with SSL module
- Valid SSL certificate (Let's Encrypt recommended)
- GhostWire server running on internal port
- Domain name pointing to your server

## Basic NGINX Configuration

### 1. SSL Certificate Setup

#### Using Let's Encrypt (Recommended)

```bash
# Install certbot
sudo apt update
sudo apt install certbot python3-certbot-nginx

# Obtain certificate
sudo certbot --nginx -d ghostwire.yourdomain.com

# Test auto-renewal
sudo certbot renew --dry-run
```

#### Using Custom Certificate

```bash
# Place your certificates
sudo mkdir -p /etc/nginx/ssl/ghostwire
sudo cp yourdomain.com.crt /etc/nginx/ssl/ghostwire/
sudo cp yourdomain.com.key /etc/nginx/ssl/ghostwire/
sudo chmod 600 /etc/nginx/ssl/ghostwire/yourdomain.com.key
```

### 2. Main NGINX Configuration

Create `/etc/nginx/sites-available/ghostwire`:

```nginx
# Rate limiting zones
limit_req_zone $binary_remote_addr zone=auth_limit:10m rate=10r/m;
limit_req_zone $binary_remote_addr zone=api_limit:10m rate=100r/m;
limit_req_zone $binary_remote_addr zone=general_limit:10m rate=1000r/m;

# Upstream backend
upstream ghostwire_backend {
    server 127.0.0.1:8080;

    # Health checking (NGINX Plus)
    # health_check interval=10s fails=3 passes=2;

    # Load balancing for multiple instances
    # server 127.0.0.1:8081;
    # server 127.0.0.1:8082;
}

# HTTP to HTTPS redirect
server {
    listen 80;
    listen [::]:80;
    server_name ghostwire.yourdomain.com;

    # Allow Let's Encrypt challenges
    location /.well-known/acme-challenge/ {
        root /var/www/html;
    }

    # Redirect everything else to HTTPS
    location / {
        return 301 https://$server_name$request_uri;
    }
}

# Main HTTPS server
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name ghostwire.yourdomain.com;

    # SSL Configuration
    ssl_certificate /etc/letsencrypt/live/ghostwire.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/ghostwire.yourdomain.com/privkey.pem;

    # Modern SSL configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;

    # SSL session optimization
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    ssl_session_tickets off;

    # OCSP stapling
    ssl_stapling on;
    ssl_stapling_verify on;
    ssl_trusted_certificate /etc/letsencrypt/live/ghostwire.yourdomain.com/chain.pem;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self' wss: https:;" always;

    # Logging
    access_log /var/log/nginx/ghostwire_access.log combined;
    error_log /var/log/nginx/ghostwire_error.log warn;

    # General rate limiting
    limit_req zone=general_limit burst=50 nodelay;

    # Root location for health checks
    location = /health {
        access_log off;
        return 200 "healthy\n";
        add_header Content-Type text/plain;
    }

    # API endpoints
    location /api/ {
        limit_req zone=api_limit burst=20 nodelay;

        proxy_pass http://ghostwire_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host $host;
        proxy_set_header X-Forwarded-Port $server_port;

        # API-specific timeouts
        proxy_connect_timeout 5s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;

        # Buffer settings
        proxy_buffering on;
        proxy_buffer_size 4k;
        proxy_buffers 8 4k;
    }

    # gRPC endpoints
    location /grpc/ {
        grpc_pass grpc://ghostwire_backend;
        grpc_set_header Host $host;
        grpc_set_header X-Real-IP $remote_addr;
        grpc_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        grpc_set_header X-Forwarded-Proto $scheme;

        # gRPC-specific timeouts
        grpc_connect_timeout 5s;
        grpc_send_timeout 60s;
        grpc_read_timeout 60s;
    }

    # Authentication endpoints (higher rate limiting)
    location /auth/ {
        limit_req zone=auth_limit burst=5 nodelay;

        proxy_pass http://ghostwire_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host $host;
        proxy_set_header X-Forwarded-Port $server_port;

        # Auth-specific timeouts
        proxy_connect_timeout 10s;
        proxy_send_timeout 30s;
        proxy_read_timeout 30s;
    }

    # WebSocket support for real-time updates
    location /ws/ {
        proxy_pass http://ghostwire_backend;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # WebSocket timeouts
        proxy_connect_timeout 7d;
        proxy_send_timeout 7d;
        proxy_read_timeout 7d;
    }

    # Static assets with caching
    location /static/ {
        proxy_pass http://ghostwire_backend;
        proxy_set_header Host $host;

        # Cache static assets
        expires 1y;
        add_header Cache-Control "public, immutable";

        # Compression
        gzip on;
        gzip_vary on;
        gzip_types text/css application/javascript application/json image/svg+xml;
    }

    # Web GUI (main application)
    location / {
        # Authentication required for web GUI
        auth_request /auth/verify;

        proxy_pass http://ghostwire_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host $host;
        proxy_set_header X-Forwarded-Port $server_port;

        # Pass authentication info
        proxy_set_header X-Auth-User $upstream_http_x_auth_user;
        proxy_set_header X-Auth-Groups $upstream_http_x_auth_groups;

        # Standard timeouts
        proxy_connect_timeout 5s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }

    # Internal authentication verification
    location = /auth/verify {
        internal;
        proxy_pass http://ghostwire_backend/auth/verify;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        proxy_set_header X-Original-URI $request_uri;
        proxy_set_header X-Original-Method $request_method;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Error pages
    error_page 401 /auth/login;
    error_page 403 /403.html;
    error_page 404 /404.html;
    error_page 500 502 503 504 /50x.html;
}
```

### 3. Enable the Site

```bash
# Enable the site
sudo ln -s /etc/nginx/sites-available/ghostwire /etc/nginx/sites-enabled/

# Test configuration
sudo nginx -t

# Reload NGINX
sudo systemctl reload nginx
```

## Advanced Security Configuration

### 1. Enhanced Security Headers

Create `/etc/nginx/conf.d/security.conf`:

```nginx
# Security headers map
map $sent_http_content_type $csp_policy {
    default "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self' wss: https:;";
    ~^text/html "default-src 'self'; script-src 'self' 'sha256-xyz123...'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self' wss: https:; frame-ancestors 'none';";
}

# Security configuration
server {
    # ... existing configuration ...

    # Enhanced security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Content-Security-Policy $csp_policy always;
    add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;

    # Remove server information
    server_tokens off;
    more_clear_headers Server;
    more_set_headers "Server: GhostWire";
}
```

### 2. IP Whitelisting for Admin

```nginx
# Admin access restriction
location /admin/ {
    # Allow specific IP ranges
    allow 192.168.1.0/24;    # Internal network
    allow 10.0.0.0/8;        # VPN network
    allow 203.0.113.0/24;    # Office IP range
    deny all;

    # Continue with normal proxy configuration
    proxy_pass http://ghostwire_backend;
    # ... other settings ...
}
```

### 3. GeoIP Blocking

```nginx
# Install GeoIP module first:
# sudo apt install nginx-module-geoip

# Load GeoIP module
load_module modules/ngx_http_geoip_module.so;

http {
    # GeoIP database
    geoip_country /usr/share/GeoIP/GeoIP.dat;

    # Block specific countries
    map $geoip_country_code $blocked_country {
        default 0;
        CN 1;  # China
        RU 1;  # Russia
        KP 1;  # North Korea
    }

    server {
        # Block based on country
        if ($blocked_country) {
            return 403 "Access denied from your location";
        }

        # ... rest of configuration ...
    }
}
```

## SSO Integration Configurations

### 1. Azure/Microsoft Entra ID

```nginx
server {
    # ... existing configuration ...

    # Azure AD specific auth verification
    location = /auth/verify {
        internal;
        proxy_pass http://ghostwire_backend/auth/verify;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        proxy_set_header X-Original-URI $request_uri;
        proxy_set_header X-Original-Method $request_method;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Azure AD specific headers
        proxy_set_header X-MS-CLIENT-PRINCIPAL-ID $http_x_ms_client_principal_id;
        proxy_set_header X-MS-CLIENT-PRINCIPAL-NAME $http_x_ms_client_principal_name;
    }

    # Azure AD callback
    location /auth/callback {
        limit_req zone=auth_limit burst=5 nodelay;

        proxy_pass http://ghostwire_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Increase timeout for OAuth flow
        proxy_connect_timeout 15s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }
}
```

### 2. Google Workspace Integration

```nginx
server {
    # ... existing configuration ...

    # Google-specific auth headers
    location = /auth/verify {
        internal;
        proxy_pass http://ghostwire_backend/auth/verify;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        proxy_set_header X-Original-URI $request_uri;
        proxy_set_header X-Forwarded-Host $host;

        # Google Workspace specific
        proxy_set_header X-Goog-Authenticated-User-Email $http_x_goog_authenticated_user_email;
        proxy_set_header X-Goog-Authenticated-User-ID $http_x_goog_authenticated_user_id;
    }
}
```

### 3. GitHub Integration

```nginx
server {
    # ... existing configuration ...

    # GitHub OAuth specific configuration
    location /auth/github/ {
        limit_req zone=auth_limit burst=3 nodelay;

        proxy_pass http://ghostwire_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # GitHub-specific timeouts
        proxy_connect_timeout 10s;
        proxy_send_timeout 30s;
        proxy_read_timeout 30s;
    }
}
```

## Performance Optimization

### 1. Caching Configuration

```nginx
# Cache zone definitions
proxy_cache_path /var/cache/nginx/ghostwire levels=1:2 keys_zone=ghostwire_cache:10m max_size=1g inactive=60m use_temp_path=off;

server {
    # ... existing configuration ...

    # Cache API responses
    location /api/v1/nodes {
        proxy_cache ghostwire_cache;
        proxy_cache_valid 200 302 5m;
        proxy_cache_valid 404 1m;
        proxy_cache_use_stale error timeout invalid_header updating http_500 http_502 http_503 http_504;
        proxy_cache_lock on;

        # Cache headers
        add_header X-Cache-Status $upstream_cache_status;

        proxy_pass http://ghostwire_backend;
        # ... other proxy settings ...
    }

    # Don't cache authentication endpoints
    location /auth/ {
        proxy_cache off;
        proxy_no_cache 1;
        proxy_cache_bypass 1;

        proxy_pass http://ghostwire_backend;
        # ... other proxy settings ...
    }
}
```

### 2. Compression

```nginx
server {
    # ... existing configuration ...

    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_min_length 1000;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types
        text/plain
        text/css
        text/xml
        text/javascript
        application/json
        application/javascript
        application/xml+rss
        application/atom+xml
        image/svg+xml;
}
```

### 3. Connection Optimization

```nginx
# Worker processes optimization
worker_processes auto;
worker_cpu_affinity auto;
worker_rlimit_nofile 65535;

events {
    worker_connections 4096;
    use epoll;
    multi_accept on;
}

http {
    # Connection optimization
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    keepalive_requests 1000;

    # Buffer optimization
    client_body_buffer_size 128k;
    client_max_body_size 10m;
    client_header_buffer_size 3m;
    large_client_header_buffers 4 256k;

    # Timeout optimization
    client_body_timeout 12;
    client_header_timeout 12;
    send_timeout 10;
}
```

## Monitoring and Logging

### 1. Enhanced Logging

```nginx
# Custom log format
log_format ghostwire_format '$remote_addr - $remote_user [$time_local] '
                           '"$request" $status $body_bytes_sent '
                           '"$http_referer" "$http_user_agent" '
                           '$request_time $upstream_response_time '
                           '"$http_x_forwarded_for" "$http_authorization"';

server {
    # ... existing configuration ...

    # Separate logs for different endpoints
    access_log /var/log/nginx/ghostwire_access.log ghostwire_format;
    access_log /var/log/nginx/ghostwire_api.log ghostwire_format if=$api_request;
    access_log /var/log/nginx/ghostwire_auth.log ghostwire_format if=$auth_request;

    # Log filtering
    map $request_uri $api_request {
        ~^/api/ 1;
        default 0;
    }

    map $request_uri $auth_request {
        ~^/auth/ 1;
        default 0;
    }
}
```

### 2. Metrics Export

```nginx
# NGINX Plus metrics (if available)
location /nginx_status {
    stub_status;
    allow 127.0.0.1;
    allow 192.168.1.0/24;
    deny all;
}

# Custom metrics endpoint
location /metrics {
    proxy_pass http://ghostwire_backend/metrics;
    allow 127.0.0.1;
    allow 192.168.1.0/24;  # Monitoring network
    deny all;
}
```

## Troubleshooting

### Common Issues

#### 1. SSL Certificate Problems

```bash
# Check certificate validity
sudo openssl x509 -in /etc/letsencrypt/live/ghostwire.yourdomain.com/fullchain.pem -text -noout

# Test SSL configuration
sudo nginx -t

# Check certificate chain
curl -I https://ghostwire.yourdomain.com
```

#### 2. Authentication Loop

```bash
# Check auth verification endpoint
curl -H "Authorization: Bearer $TOKEN" https://ghostwire.yourdomain.com/auth/verify

# Debug auth headers
tail -f /var/log/nginx/ghostwire_error.log | grep auth
```

#### 3. Performance Issues

```bash
# Check NGINX status
curl http://localhost/nginx_status

# Monitor connections
ss -tuln | grep :443

# Check upstream health
curl -I http://127.0.0.1:8080/health
```

### Debug Commands

```bash
# Test configuration
sudo nginx -t

# Reload configuration
sudo systemctl reload nginx

# Check error logs
sudo tail -f /var/log/nginx/error.log

# Test SSL
openssl s_client -connect ghostwire.yourdomain.com:443 -servername ghostwire.yourdomain.com

# Test HTTP/2
curl -I --http2 https://ghostwire.yourdomain.com

# Benchmark performance
ab -n 1000 -c 10 https://ghostwire.yourdomain.com/api/v1/health
```

## Security Checklist

- [ ] SSL/TLS properly configured with modern ciphers
- [ ] Security headers implemented (HSTS, CSP, etc.)
- [ ] Rate limiting configured for all endpoints
- [ ] Authentication required for web GUI
- [ ] IP whitelisting for admin access
- [ ] Proper logging and monitoring configured
- [ ] Regular security updates applied
- [ ] Certificate auto-renewal working
- [ ] Firewall rules configured
- [ ] Regular security audits performed

This comprehensive NGINX setup provides enterprise-grade security, performance, and SSO integration for your GhostWire deployment.