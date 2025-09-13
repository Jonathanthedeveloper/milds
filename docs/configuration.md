# MLIDS Configuration Guide

## Configuration Overview

MLIDS supports multiple configuration methods:

1. **YAML Configuration File** (recommended)
2. **Command Line Arguments**
3. **Environment Variables**
4. **Runtime Configuration**

## Configuration File Format

### Basic Configuration
Create `config.yaml` in the project root:

```yaml
# Logging Configuration
logs_dir: "logs"
console_color: true

# Monitoring Targets
monitor_dir: "/var/log"
app_log_file: "/var/log/auth.log"

# Network Monitoring
enable_network: false
network_interface: "eth0"

# Detection Thresholds
port_scan_threshold: 10
brute_force_threshold: 5
packet_rate_threshold: 100
anomaly_window: 60

# Output Sinks
tcp_sink_enabled: false
tcp_sink_host: "127.0.0.1"
tcp_sink_port: 8765

websocket_sink_enabled: false
websocket_sink_host: "127.0.0.1"
websocket_sink_port: 8765

# Performance Tuning
sleep_idle: 0.1
log_window: 1000
```

### Advanced Configuration
```yaml
# Custom Detection Rules
app_rules:
  "Custom Attack Pattern": "malicious.*pattern"
  "Suspicious User Agent": "bot|crawler|scanner"
  "Data Exfiltration": "large.*upload|download"

# Threat Intelligence
intel_ips:
  - "192.168.1.100"
  - "10.0.0.50"
  - "192.168.1.200"

# Automated Actions
actions:
  "Failed Login":
    - type: "block_ip"
      threshold: 5
      duration: 3600
    - type: "webhook"
  url: "https://security.example.local/alert"
      method: "POST"

  "SQL Injection":
    - type: "webhook"
  url: "https://hooks.slack.example.local/webhook"
      payload: '{"text": "SQL Injection detected: {{details}}"}'

  "Brute Force":
    - type: "run"
      cmd: "iptables -A INPUT -s {{ip}} -j DROP"
      allow_commands: true

# MFA Configuration
mfa_totp_enabled: false
mfa_totp_secret: ""  # Do NOT store secrets in plaintext; use environment variables or secret manager

# External Rules File
rules_file: "custom_rules.yaml"
rule_meta:
  version: "1.0"
  author: "Security Team"
  last_updated: "2025-01-13"
```

## Configuration Sections

### Logging Configuration

MLIDS writes structured JSON-line logs to a single file in the configured
logs directory. By default logs are written to `logs/mlids.json` and are
rotated daily (midnight) by the application. The configuration no longer
includes a `log_file` key — use `logs_dir` to change where logs are stored.

Example configuration:

```yaml
logs_dir: "logs"                 # Directory where MLIDS writes rotated logs
console_color: true
log_level: "INFO"               # Logging level (DEBUG, INFO, WARNING, ERROR)
log_format: "json"              # Log format (json, text)
log_rotation: "daily"           # Informational only; rotation is managed by the app
backup_count: 30                  # Number of rotated files to keep
```

To obtain a logger in code use `get_logger()` and optionally pass `logs_dir`:

```python
from milds.logger import get_logger
logger = get_logger('mlids', logs_dir='logs')
```

To start MLIDS from the CLI (it will use the configured `logs_dir`):

```bash
python index.py start
```

### Monitoring Configuration

```yaml
# File system monitoring
monitor_dir: "/var/log"           # Directory to monitor for changes
exclude_patterns:                 # Patterns to exclude from monitoring
  - "*.tmp"
  - "*.log"
  - "cache/*"
include_patterns:                 # Patterns to include (if specified)
  - "*.conf"
  - "*.ini"

# Application log monitoring
app_log_file: "/var/log/auth.log" # Application log file to monitor
app_log_encoding: "utf-8"         # Log file encoding
app_log_follow: true              # Follow log file (tail -f behavior)

# Network monitoring
enable_network: false             # Enable network packet analysis
network_interface: "eth0"         # Network interface to monitor
capture_filter: "tcp port 80"     # Packet capture filter (BPF syntax)
promiscuous_mode: false           # Enable promiscuous mode
```

### Detection Configuration

```yaml
# Thresholds
port_scan_threshold: 10           # Ports before triggering port scan alert
brute_force_threshold: 5          # Failed logins before brute force alert
packet_rate_threshold: 100        # Packets/sec before DoS alert
anomaly_window: 60                # Time window for anomaly detection (seconds)

# Pattern matching
sql_injection_patterns:           # Additional SQL injection patterns
  - "union.*select"
  - "information_schema"
xss_patterns:                     # Additional XSS patterns
  - "javascript:"
  - "onload="
path_traversal_patterns:          # Additional path traversal patterns
  - "..%2f"
  - "..\\"

# Custom rules
app_rules:
  "Suspicious Command": "rm -rf|format|del.*\\\\"
  "Privilege Escalation": "sudo|su.*root"
  "Data Leakage": "password.*=|api_key.*="
```

### Output Configuration

```yaml
# TCP Sink (for external tools)
tcp_sink_enabled: false
tcp_sink_host: "127.0.0.1"
tcp_sink_port: 8765
tcp_sink_format: "json"           # Output format (json, syslog)

# WebSocket Sink (for web dashboards)
websocket_sink_enabled: false
websocket_sink_host: "127.0.0.1"
websocket_sink_port: 8765
websocket_sink_secure: false      # Enable WSS (WebSocket Secure)

# Email alerts
email_enabled: false
smtp_server: "smtp.gmail.com"
smtp_port: 587
smtp_username: ""
smtp_password: ""  # remove sample plaintext password
email_recipients:
  - "security@example.local"
  - "admin@example.local"

# Slack integration
slack_enabled: false
slack_webhook_url: "https://hooks.slack.com/services/..."
slack_channel: "#security-alerts"
```

### Security Configuration

```yaml
# Access control
allow_firewall_actions: false     # Allow automatic firewall rule creation
allow_system_commands: false      # Allow execution of system commands
require_mfa: false               # Require MFA for CLI access

# Encryption
encrypt_logs: false              # Encrypt log files
encryption_key: "your-256-bit-key"

# Audit logging
audit_enabled: true              # Enable audit logging
audit_file: "mlids_audit.log"    # Audit log file
```

## Command Line Configuration

### Override Configuration Values
```bash
# Specify main log file via CLI when starting
python index.py start

# Override monitoring directory
python index.py start --config monitor_dir=/tmp

# Multiple overrides
python index.py start --config enable_network=true
```

### Runtime Configuration
```bash
# Set configuration value
python index.py config --key port_scan_threshold --value 15

# Get configuration value
python index.py config --key port_scan_threshold

# List all configuration
python index.py config --list
```

## Environment Variables

MLIDS supports environment variable configuration:

```bash
export MLIDS_ENABLE_NETWORK="true"
export MLIDS_BRUTE_FORCE_THRESHOLD="10"
export MLIDS_TCP_SINK_PORT="8765"

python index.py start
```

### Environment Variable Mapping
- `MLIDS_LOGS_DIR` → `logs_dir`
Note: MLIDS no longer accepts a main logfile path via a command-line flag.
To change where logs are written set `logs_dir` in `config.yaml` or pass
`logs_dir` to `get_logger()` in code.
- `MLIDS_MONITOR_DIR` → `monitor_dir`
- `MLIDS_APP_LOG_FILE` → `app_log_file`
- `MLIDS_ENABLE_NETWORK` → `enable_network`
- `MLIDS_PORT_SCAN_THRESHOLD` → `port_scan_threshold`
- `MLIDS_BRUTE_FORCE_THRESHOLD` → `brute_force_threshold`

## Configuration Validation

### Validate Configuration File
```bash
python -c "from mlids.config import load_config; cfg = load_config('config.yaml'); print('Configuration valid')"
```

### Check Configuration Values
```bash
# List current configuration
python index.py config --list

# Validate specific values
python index.py config --key enable_network --validate
```

## Configuration Examples

### Development Environment
```yaml
# Logs will be written under the configured `logs_dir` (e.g. "dev_logs")
logs_dir: "dev_logs"
monitor_dir: "/home/user/projects"
enable_network: false
console_color: true
port_scan_threshold: 5
brute_force_threshold: 3
```

### Production Server
```yaml
# Logs will be written under the configured `logs_dir` (e.g. "/var/log/mlids")
logs_dir: "/var/log/mlids"
monitor_dir: "/var/www"
app_log_file: "/var/log/apache2/access.log"
enable_network: true
network_interface: "eth0"
tcp_sink_enabled: true
tcp_sink_host: "10.0.0.100"
tcp_sink_port: 514
allow_firewall_actions: true
```

### High Security Environment
```yaml
# Logs will be written under the configured `logs_dir` (e.g. "/var/log/mlids")
logs_dir: "/var/log/mlids"
encrypt_logs: true
require_mfa: true
mfa_totp_enabled: true
allow_firewall_actions: true
allow_system_commands: false
intel_ips:
  - "192.168.1.100"
  - "10.0.0.50"
actions:
  "Failed Login":
    - type: "block_ip"
      threshold: 3
  "Brute Force":
    - type: "webhook"
  url: "https://security.example.local/incident"
```

## Configuration Best Practices

### 1. Environment Separation
- Use different configurations for dev/staging/production
- Store sensitive values in environment variables
- Use relative paths for portability

### 2. Security Considerations
- Don't commit sensitive data to version control
- Use strong encryption keys
- Limit firewall and command execution permissions
- Enable MFA for production systems

### 3. Performance Tuning
- Adjust thresholds based on your environment
- Monitor resource usage and adjust sleep intervals
- Use appropriate log rotation settings

### 4. Monitoring Coverage
- Monitor critical system directories
- Include relevant application logs
- Configure appropriate network interfaces
- Set up external alerting systems

## Troubleshooting Configuration

### Common Issues

#### Configuration Not Loaded
```bash
# Check file exists and is readable
ls -la config.yaml

# Validate YAML syntax
python -c "import yaml; yaml.safe_load(open('config.yaml'))"
```

#### Invalid Configuration Values
```bash
# Check configuration validation
python index.py config --key invalid_key --validate
# Error: Invalid configuration key

# List valid keys
python index.py config --list
```

#### Permission Issues
```bash
# Check file permissions
ls -la config.yaml

# Fix permissions
chmod 644 config.yaml
```

### Configuration Debugging
```bash
# Enable debug logging
python index.py start --config log_level=DEBUG

# Check loaded configuration
python -c "from mlids.config import load_config; import pprint; pprint.pprint(vars(load_config('config.yaml')))"
```

## Advanced Configuration

### Custom Rules File
Create `custom_rules.yaml`:
```yaml
version: "1.0"
rules:
  "Advanced SQL Injection":
    pattern: "(?i)(union.*select|information_schema|load_file)"
    severity: "high"
    category: "database"

  "Command Injection":
    pattern: "(?i)(\\|\\||&&|;`)"
    severity: "critical"
    category: "system"

  "Suspicious File Access":
    pattern: "(?i)(/etc/passwd|/etc/shadow|\\.env)"
    severity: "medium"
    category: "file_access"
```

### Dynamic Configuration
```python
from mlids.config import Config

# Create configuration programmatically
cfg = Config()
cfg.dynamic_logfile = "dynamic_logs.json"  # demonstrate dynamic filename handling
cfg.enable_network = True
cfg.app_rules = {
    "Custom Rule": "custom.*pattern"
}

# Use configuration
from mlids.app import app_monitor
app_monitor(cfg, logger)
```

This configuration system provides flexibility for different deployment scenarios while maintaining security and performance best practices.