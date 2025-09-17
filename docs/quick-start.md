# GhostWire Quick Start Guide

Get GhostWire up and running in 5 minutes! This guide will help you create your first mesh VPN network.

## 📋 Prerequisites

- Linux, macOS, or Windows machine
- Internet connection
- Administrative/sudo privileges (for network configuration)

## 🚀 Option 1: Using Pre-built Binaries

### Download Latest Release

```bash
# Linux x86_64
curl -L https://github.com/ghostkellz/ghostwire/releases/latest/download/ghostwire-linux-x86_64.tar.gz | tar xz

# macOS
curl -L https://github.com/ghostkellz/ghostwire/releases/latest/download/ghostwire-macos-universal.tar.gz | tar xz

# Windows (PowerShell)
Invoke-WebRequest -Uri "https://github.com/ghostkellz/ghostwire/releases/latest/download/ghostwire-windows-x86_64.zip" -OutFile "ghostwire.zip"
Expand-Archive ghostwire.zip
```

### Install Binaries

```bash
# Linux/macOS
sudo mv ghostwire-* /usr/local/bin/
sudo chmod +x /usr/local/bin/ghostwire-*

# Verify installation
ghostwire-server --version
gwctl --version
```

## 🔧 Option 2: Build from Source

### Install Rust

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
```

### Clone and Build

```bash
git clone https://github.com/ghostkellz/ghostwire.git
cd ghostwire

# Build all components
cargo build --release

# Install binaries
sudo cp target/release/ghostwire-server /usr/local/bin/
sudo cp target/release/gwctl /usr/local/bin/
sudo cp target/release/ghostwire-client /usr/local/bin/
```

## 🏗️ Step 1: Start the Coordination Server

Create a configuration file:

```bash
mkdir -p ~/.config/ghostwire
cat > ~/.config/ghostwire/server.toml << EOF
[server]
listen_addr = "0.0.0.0:8080"
derp_addr = "0.0.0.0:3478"

[database]
url = "sqlite:///home/$USER/.config/ghostwire/ghostwire.db"

[auth]
method = "local"

[acl]
policy_path = "/home/$USER/.config/ghostwire/policy.hujson"
EOF
```

Create a basic ACL policy:

```bash
cat > ~/.config/ghostwire/policy.hujson << EOF
{
  // Allow all authenticated users to access all resources
  "acls": [
    {
      "action": "accept",
      "src": ["*"],
      "dst": ["*:*"]
    }
  ],

  // Define user groups
  "groups": {
    "group:admin": ["*"]
  },

  // Tag owners
  "tagOwners": {
    "tag:server": ["group:admin"],
    "tag:client": ["group:admin"]
  }
}
EOF
```

Start the server:

```bash
# Start in foreground
ghostwire-server --config ~/.config/ghostwire/server.toml

# Or start as daemon (Linux/macOS)
ghostwire-server --config ~/.config/ghostwire/server.toml --daemon
```

## 📱 Step 2: Connect Your First Client

### Initialize Client Configuration

```bash
mkdir -p ~/.config/ghostwire/client
gwctl config init --server http://localhost:8080
```

### Authenticate and Connect

```bash
# Authenticate with the server
gwctl auth login

# Start the client daemon
sudo ghostwire-client --config ~/.config/ghostwire/client/config.toml

# Check connection status
gwctl status
```

You should see output like:

```
✅ Connected to GhostWire network
📍 Server: http://localhost:8080
🔑 Machine: laptop-alice-001
📡 IP Address: 100.64.0.1
🌐 Status: Online
⚡ Uptime: 5 seconds
```

## 🔗 Step 3: Add More Devices

### On Each Additional Device

1. **Install GhostWire** (using steps above)

2. **Connect to the same server**:
   ```bash
   gwctl config init --server http://YOUR_SERVER_IP:8080
   gwctl auth login
   sudo ghostwire-client
   ```

3. **Verify connectivity**:
   ```bash
   gwctl peers
   ping 100.64.0.1  # IP of first device
   ```

## 🌐 Step 4: Access the Web Interface

GhostWire includes a modern web administration interface:

1. **Open your browser** to `http://localhost:8080`
2. **Log in** with your credentials
3. **Explore the dashboard**:
   - View connected devices
   - Monitor network traffic
   - Manage access policies
   - Configure routes and exit nodes

## 📊 Step 5: Monitor Your Network

### View Network Status

```bash
# List all connected devices
gwctl machines list

# Show network topology
gwctl network topology

# Display real-time statistics
gwctl stats --follow
```

### Access Built-in Monitoring

- **Metrics**: `http://localhost:8080/metrics` (Prometheus format)
- **Health**: `http://localhost:8080/health`
- **Dashboard**: `http://localhost:8080/dashboard`

## 🎯 Common Use Cases

### Share Files Between Devices

Once connected, devices can access each other directly:

```bash
# On device A (100.64.0.1)
python3 -m http.server 8000

# On device B (100.64.0.2)
curl http://100.64.0.1:8000
```

### Access Remote Services

```bash
# SSH to another device
ssh user@100.64.0.1

# Access web services
curl http://100.64.0.2:3000
```

### Route Traffic Through Exit Node

```bash
# Set device as exit node
gwctl machine configure --exit-node 100.64.0.1

# Route all traffic through exit node
gwctl client configure --use-exit-node 100.64.0.1
```

## 🔧 Next Steps

### Production Deployment

- [**Installation Guide**](./installation.md) - Production installation
- [**Configuration Reference**](./configuration.md) - Advanced configuration
- [**Security Guide**](./security.md) - Security hardening
- [**Deployment Guide**](./deployment.md) - Production deployment

### Advanced Features

- [**ACL Policies**](./acl.md) - Fine-grained access control
- [**OIDC Integration**](./auth.md) - Enterprise authentication
- [**MagicDNS**](./dns.md) - Automatic DNS resolution
- [**Subnet Routes**](./routing.md) - Network routing configuration

### Monitoring & Observability

- [**Metrics Setup**](./observability.md) - Prometheus monitoring
- [**Log Management**](./logging.md) - Centralized logging
- [**Alerting**](./alerting.md) - Automated alerts

## 🆘 Troubleshooting

### Connection Issues

```bash
# Check service status
gwctl status

# View logs
gwctl logs --follow

# Test connectivity
gwctl ping 100.64.0.1

# Reset configuration
gwctl config reset
```

### Common Problems

**Problem**: "Permission denied" errors
**Solution**: Run client with `sudo` or configure capabilities:
```bash
sudo setcap cap_net_admin+ep /usr/local/bin/ghostwire-client
```

**Problem**: Can't connect to server
**Solution**: Check firewall settings and server address:
```bash
# Test server connectivity
curl http://YOUR_SERVER:8080/health

# Check local firewall
sudo ufw status  # Ubuntu
sudo firewall-cmd --list-all  # RHEL/CentOS
```

**Problem**: Devices can't reach each other
**Solution**: Verify ACL policies and routing:
```bash
gwctl acl check --src 100.64.0.1 --dst 100.64.0.2:22
gwctl network debug
```

## 📚 Learn More

- [**Architecture Overview**](./architecture.md) - How GhostWire works
- [**CLI Reference**](./cli.md) - Complete command reference
- [**API Documentation**](./api/README.md) - REST and gRPC APIs
- [**Contributing**](./contributing.md) - How to contribute

## 🎉 Success!

You now have a working GhostWire mesh VPN network! Your devices can securely communicate with each other regardless of their physical location or network configuration.

For production deployments, continue with the [Installation Guide](./installation.md) and [Security Guide](./security.md).