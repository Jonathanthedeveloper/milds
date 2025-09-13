# MLIDS Getting Started Guide

## Quick Start

### Basic Monitoring Setup
```bash
# 1. Activate virtual environment
source .venv/bin/activate  # Linux/macOS
# or
.\.venv\Scripts\activate   # Windows

# 2. Start basic monitoring
python index.py start --dir "/var/log" --app-log "/var/log/auth.log"
```

### Network Monitoring Setup
```bash
# Enable network monitoring (requires admin privileges)
python index.py start --enable-net --interface "eth0"
```

### Web Dashboard Setup
```bash
# Start with WebSocket sink for real-time dashboard
python index.py start --ws-sink --ws-port 8765
```

## Core Concepts

### Monitoring Layers

MLIDS provides three levels of intrusion detection:

1. **Host Monitoring** - File system changes and integrity
2. **Network Monitoring** - Packet analysis and anomaly detection
3. **Application Monitoring** - Log analysis and pattern matching

### Event Types

The system detects various security events:

- **File Changes** - Unauthorized file modifications
- **Failed Logins** - Brute force attempts
- **SQL Injection** - Database attack attempts
- **XSS Attempts** - Cross-site scripting attacks
- **Port Scans** - Network reconnaissance
- **Anomalous Traffic** - Unusual network patterns

## Basic Usage Examples

### 1. Monitor Home Directory
```bash
python index.py start --dir "$HOME"
```

### 2. Monitor System Logs
```bash
# Linux
python index.py start --app-log "/var/log/auth.log"

# Windows
python index.py start --app-log "C:\Windows\System32\LogFiles\Security\security.evtx"
```

### 3. Network Monitoring
```bash
# Auto-detect interface
python index.py start --enable-net

# Specific interface
python index.py start --enable-net --interface "wlan0"
```

### 4. Combined Monitoring
```bash
python index.py start \
  --dir "/var/log" \
  --app-log "/var/log/auth.log" \
  --enable-net \
  --interface "eth0"
```

## Real-time Alerts

### TCP Sink for External Tools
```bash
python index.py start --tcp-sink --tcp-port 8765
```

### WebSocket for Web Dashboard
```bash
python index.py start --ws-sink --ws-port 8765
```

## Log Analysis

### View Recent Events
```bash
python index.py analyze
```

### Search for Specific Events
```bash
# Search for failed logins
python index.py analyze --search "Failed Login"

# Search for SQL injection attempts
python index.py analyze --search "SQL Injection"
```

### Generate Reports
```bash
# Compliance report
python index.py analyze --report compliance

# Visual summary
python index.py analyze --plot
```

## Configuration Examples

### Basic Configuration File
Create `config.yaml`:
```yaml
# Note: supply the main logfile to the logger at runtime or via the CLI.
logs_dir: "logs"
monitor_dir: "/var/log"
app_log_file: "/var/log/auth.log"

# Monitoring settings
enable_network: false
port_scan_threshold: 10
brute_force_threshold: 5

# Output settings
console_color: true
tcp_sink_enabled: false
websocket_sink_enabled: false
```

### Advanced Configuration
```yaml
# Custom detection rules
app_rules:
  "Custom Attack": "malicious_pattern.*"
  "Suspicious Activity": "suspicious.*"

# Intel feed for known threats
intel_ips:
  - "192.168.1.100"
  - "10.0.0.50"

# Action configuration
actions:
  "Failed Login":
    - type: "block_ip"
      threshold: 5
  "SQL Injection":
    - type: "webhook"
  url: "https://security.example.local/alert"
```

## Common Workflows

### 1. Development Environment Monitoring
```bash
# Monitor project directory and logs
python index.py start \
  --dir "/home/user/projects" \
  --app-log "/var/log/syslog"
```

### 2. Server Monitoring
```bash
# Monitor critical system paths
python index.py start \
  --dir "/etc" \
  --dir "/var/www" \
  --app-log "/var/log/apache2/access.log" \
  --enable-net
```

### 3. Incident Response
```bash
# Quick analysis of recent activity
python index.py analyze --search "192.168.1.100"

# Generate incident report
python index.py analyze --report compliance
```

## Integration Examples

### Logstash/Elasticsearch
```bash
# Send alerts to Logstash
python index.py start --tcp-sink --tcp-host "logstash.example.local" --tcp-port 5044
```

### SIEM Integration
```bash
# Send to SIEM system
python index.py start --tcp-sink --tcp-host "siem.example.local" --tcp-port 514
```

### Custom Alert Handler
```python
# Python script to handle alerts
import socket
import json

def handle_alerts():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('localhost', 8765))
        s.listen()
        conn, addr = s.accept()
        with conn:
            while True:
                data = conn.recv(1024)
                if not data:
                    break
                alert = json.loads(data.decode())
                print(f"Alert: {alert}")
                # Custom handling logic here

handle_alerts()
```

## Troubleshooting

### Common Issues

#### No Events Detected
```bash
# Check if monitoring is running
ps aux | grep mlids

# Check log directory and rotated files
ls -la logs/

# Verify configuration
python index.py analyze
```

#### Network Monitoring Fails
```bash
# Check interface name
python -c "import scapy.all as scapy; print(scapy.get_working_ifaces())"

# Verify permissions (may need sudo)
sudo python index.py start --enable-net
```

#### High Resource Usage
```bash
# Adjust monitoring parameters
python index.py config --key sleep_idle --value 0.5
python index.py config --key log_window --value 500
```

## Next Steps

1. Review the [Configuration Guide](configuration.md) for advanced options
2. Check the [Examples](examples.md) for specific use cases
3. Set up automated monitoring with systemd/cron
4. Configure alerting and notification systems
5. Review the [API Documentation](api.md) for custom integrations