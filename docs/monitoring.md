# MLIDS Monitoring Guide

## Monitoring Overview

MLIDS provides comprehensive multi-layer intrusion detection through three primary monitoring components:

1. **Host Monitoring** - File system integrity and change detection
2. **Network Monitoring** - Packet analysis and traffic anomaly detection
3. **Application Monitoring** - Log analysis and pattern-based threat detection

## Host Monitoring

### File System Integrity
MLIDS monitors file system changes using the watchdog library to detect:

- **File Creation/Deletion** - Unauthorized file operations
- **File Modification** - Content changes and tampering
- **Directory Changes** - Structure modifications
- **Permission Changes** - Access control modifications

### Baseline Creation
```bash
# Automatic baseline creation on startup
python index.py start --dir "/etc"

# Manual baseline verification
python index.py analyze --search "baseline"
```

### Integrity Checking
MLIDS uses SHA256 hashing to detect file changes:

```python
# Example baseline entry
{
  "path": "/etc/passwd",
  "hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "size": 1024,
  "mtime": "2025-01-13T10:30:00Z"
}
```

### Exclusion Patterns
Configure files and directories to exclude from monitoring:

```yaml
# In config.yaml
exclude_patterns:
  - "*.log"
  - "*.tmp"
  - "cache/*"
  - "tmp/*"
  - "*.swp"
  - ".git/*"
```

## Network Monitoring

### Packet Analysis
MLIDS uses Scapy for comprehensive packet analysis:

- **Protocol Detection** - HTTP, HTTPS, FTP, SSH, etc.
- **Traffic Analysis** - Volume, frequency, and patterns
- **Anomaly Detection** - Statistical outlier analysis
- **Port Scanning** - Sequential port access detection

### Network Interfaces
```bash
# List available interfaces
python -c "import scapy.all as scapy; print([iface.name for iface in scapy.get_working_ifaces()])"

# Monitor specific interface
python index.py start --enable-net --interface "eth0"

# Monitor wireless interface
python index.py start --enable-net --interface "wlan0"
```

### Traffic Analysis
MLIDS analyzes network traffic for:

- **DoS Detection** - High packet rates from single sources
- **Port Scanning** - Sequential port access patterns
- **Protocol Anomalies** - Unusual packet structures
- **Traffic Spikes** - Sudden increases in network activity

### Packet Capture Filters
Configure BPF (Berkeley Packet Filter) syntax:

```yaml
# In config.yaml
capture_filter: "tcp port 80 or tcp port 443"
# or
capture_filter: "not host 192.168.1.1"
# or
capture_filter: "tcp and not port 22"
```

## Application Monitoring

### Log File Analysis
MLIDS monitors application logs for security events:

- **Authentication Failures** - Failed login attempts
- **SQL Injection** - Database attack patterns
- **XSS Attempts** - Cross-site scripting attacks
- **Path Traversal** - Directory traversal attacks
- **Command Injection** - System command execution attempts

### Built-in Detection Patterns

#### SQL Injection Patterns
```python
SQL_INJECTION_PATTERNS = re.compile(r"""
    (\%27)|(\')|(\-\-)|\%23|(#)|
    (\bOR\b\s+1=1)|(\bAND\b\s+1=1)|
    (union.*select)|(information_schema)|
    (load_file)|(into.*outfile)
""", re.IGNORECASE | re.VERBOSE)
```

#### XSS Patterns
```python
XSS_PATTERNS = re.compile(r"""
    (<script>)|(alert\()|(<img src=javascript:)|
    (javascript:)|(onload=)|(onerror=)|
    (<iframe)|(document\.cookie)
""", re.IGNORECASE | re.VERBOSE)
```

#### Command Injection Patterns
```python
CMD_INJECTION = re.compile(r"""
    (;|&&|\|\|)\s*(cat|type|whoami|id|dir|ls)\b|
    (\|.*cmd|\|.*powershell)|
    (\$\(.*\)|`.*`)
""", re.IGNORECASE | re.VERBOSE)
```

### Custom Rules
Define custom detection patterns:

```yaml
# In config.yaml
app_rules:
  "Custom Attack": "malicious.*pattern"
  "Suspicious User Agent": "bot|crawler|scanner"
  "Data Exfiltration": "large.*upload.*|download.*"
  "Privilege Escalation": "sudo.*root|su.*admin"
```

### Log Format Support
MLIDS supports various log formats:

- **Syslog** - Standard system logging
- **Apache/Nginx** - Web server access logs
- **Auth logs** - Authentication attempt logs
- **Application logs** - Custom application logging
- **Windows Event Logs** - Windows system events

## Real-time Monitoring

### Event Processing Pipeline

1. **Event Detection** - Monitors detect security events
2. **Event Classification** - Categorize events by type and severity
3. **Event Enrichment** - Add context and metadata
4. **Event Correlation** - Link related events
5. **Alert Generation** - Create actionable alerts
6. **Event Distribution** - Send to configured sinks

### Event Types

#### Host Events
```json
{
  "timestamp": "2025-01-13T10:30:15Z",
  "type": "File Modified",
  "details": {
    "path": "/etc/passwd",
    "action": "modified",
    "old_hash": "abc123...",
    "new_hash": "def456..."
  }
}
```

#### Network Events
```json
{
  "timestamp": "2025-01-13T10:30:20Z",
  "type": "Port Scan",
  "details": {
    "source_ip": "192.168.1.100",
    "ports_scanned": 15,
    "target_ports": [22, 80, 443, 3306]
  }
}
```

#### Application Events
```json
{
  "timestamp": "2025-01-13T10:30:25Z",
  "type": "SQL Injection",
  "details": {
    "line": "GET /search?q=' OR 1=1 --",
    "pattern": "(\\'|\\-\\-)",
    "severity": "high"
  }
}
```

## Alert Correlation

### Threat Intelligence Integration
MLIDS can integrate with threat intelligence feeds:

```yaml
# In config.yaml
intel_ips:
  - "192.168.1.100"  # Known malicious IP
  - "10.0.0.50"      # Suspicious IP
  - "192.168.1.200"  # Blocked IP

intel_domains:
  - "malicious.example.local"
  - "suspicious.net"
```

### Event Correlation Rules
```yaml
# In config.yaml
correlation_rules:
  "Brute Force Campaign":
    events: ["Failed Login", "Failed Login", "Failed Login"]
    window: 300  # 5 minutes
    threshold: 3

  "Targeted Attack":
    events: ["Port Scan", "SQL Injection", "File Access"]
    window: 3600  # 1 hour
    threshold: 2
```

## Performance Monitoring

### Resource Usage
MLIDS monitors its own resource consumption:

- **CPU Usage** - Processing overhead
- **Memory Usage** - RAM consumption
- **Disk I/O** - Log file operations
- **Network I/O** - Packet capture overhead

### Performance Tuning

```yaml
# In config.yaml
# Reduce CPU usage
sleep_idle: 0.2          # Increase sleep interval
log_window: 500          # Reduce log analysis window

# Reduce memory usage
max_cache_size: 1000     # Limit cached events
cleanup_interval: 3600   # Regular cleanup

# Reduce disk I/O
log_rotation: "1 hour"   # More frequent rotation
compression: true        # Compress old logs
```

## Monitoring Best Practices

### 1. Coverage Strategy
- **Critical Assets** - Monitor sensitive files and directories
- **Network Perimeter** - Monitor ingress/egress traffic
- **Application Logs** - Monitor authentication and access logs
- **System Logs** - Monitor OS-level security events

### 2. Threshold Tuning
- **Start Conservative** - Use higher thresholds initially
- **Monitor Baselines** - Establish normal activity patterns
- **Gradual Adjustment** - Fine-tune based on false positives
- **Environment Specific** - Adjust for your specific environment

### 3. Alert Management
- **Prioritize Alerts** - Focus on high-impact events first
- **Reduce Noise** - Filter known benign activities
- **Escalation Rules** - Define when to escalate alerts
- **Response Procedures** - Document incident response steps

### 4. Maintenance
- **Regular Updates** - Keep detection patterns current
- **Log Rotation** - Manage log file sizes
- **Performance Monitoring** - Track system resource usage
- **Backup Strategy** - Backup logs and configuration

## Advanced Monitoring Features

### Statistical Analysis
MLIDS uses statistical methods for anomaly detection:

- **Median Absolute Deviation (MAD)** - Robust outlier detection
- **Moving Averages** - Trend analysis
- **Standard Deviation** - Normal distribution analysis
- **Percentile Analysis** - Quantile-based thresholds

### Machine Learning Integration
Future versions may include:

- **Behavioral Analysis** - Learn normal user behavior
- **Predictive Detection** - Anticipate attack patterns
- **Automated Response** - AI-driven incident response
- **Threat Hunting** - Proactive threat discovery

## Troubleshooting Monitoring

### Common Issues

#### No Events Detected
```bash
# Check monitoring status
ps aux | grep mlids

# Verify file permissions
ls -la /var/log/
chmod 644 /var/log/auth.log

# Check configuration
python index.py analyze
```

#### High False Positive Rate
```bash
# Increase thresholds
python index.py config --key brute_force_threshold --value 10

# Add exclusion patterns
echo "exclude_patterns:" >> config.yaml
echo "  - 'cache/*'" >> config.yaml
```

#### Performance Issues
```bash
# Monitor resource usage
top -p $(pgrep mlids)

# Adjust performance settings
python index.py config --key sleep_idle --value 0.5
```

#### Network Monitoring Issues
```bash
# Check interface permissions
sudo python -c "import scapy.all as scapy; scapy.sniff(count=1)"

# Verify Npcap/libpcap installation
python -c "import scapy.all as scapy; print('Scapy version:', scapy.__version__)"
```

## Integration with External Tools

### SIEM Systems
```bash
# Send to Splunk
python index.py start --tcp-sink --tcp-host "splunk.example.local" --tcp-port 514

# Send to ELK Stack
python index.py start --tcp-sink --tcp-host "logstash.example.local" --tcp-port 5044
```

### Monitoring Dashboards
```bash
# Send to Grafana
python index.py start --tcp-sink --tcp-host "grafana.example.local" --tcp-port 2003

# Web dashboard
python index.py start --ws-sink --ws-port 8765
```

### Alert Management
```bash
# Integration with PagerDuty
python index.py start --webhook "https://events.pagerduty.com/webhook"

# Slack notifications
python index.py start --slack-webhook "https://hooks.slack.com/services/..."
```

This comprehensive monitoring system provides layered defense with real-time detection, alerting, and integration capabilities for modern security operations.