# MLIDS Examples and Use Cases

## Basic Usage Examples

### 1. Simple Network Monitoring
Monitor network traffic for suspicious activity:

```bash
# Start basic network monitoring
python index.py start --interface wlan0

# Monitor with custom thresholds
python index.py start --interface eth0 --config custom_config.yaml
```

**Expected Output:**
```
INFO: MLIDS starting...
INFO: Network monitoring enabled on interface: wlan0
INFO: Host monitoring enabled for directory: /var/log
INFO: Application monitoring enabled for file: /var/log/auth.log
INFO: MLIDS is running. Press Ctrl+C to stop.
```

### 2. File Integrity Monitoring
Monitor critical system files for unauthorized changes:

```bash
# Monitor specific directory
python index.py start --dir /etc

# Monitor multiple directories (advanced usage)
python index.py start --dir /etc --dir /var/www
```

**Configuration Example:**
```yaml
# config.yaml
monitoring:
  directory: "/etc"
  recursive: true
  exclude_patterns:
    - "*.log"
    - "*.tmp"
```

### 3. Log Analysis and Alerting
Monitor application logs for security events:

```bash
# Monitor authentication logs
python index.py start --app-log /var/log/auth.log

# Monitor web server logs
python index.py start --app-log /var/log/apache2/access.log
```

## Advanced Configuration Examples

### Custom Threshold Configuration
```yaml
# config.yaml
thresholds:
  port_scan_threshold: 15        # Alert after 15 ports scanned
  brute_force_threshold: 3       # Alert after 3 failed logins
  packet_rate_threshold: 500     # Alert at 500 packets/second
  anomaly_threshold: 2.5         # Statistical anomaly threshold

  # Time-based thresholds
  time_window: 300               # 5-minute analysis window
  alert_cooldown: 3600           # Don't repeat alerts for 1 hour
```

### Multi-Interface Monitoring
```yaml
# config.yaml
network:
  interfaces:
    - name: "eth0"
      monitor: true
      promiscuous: true
    - name: "wlan0"
      monitor: true
      promiscuous: false
  exclude_ips:
    - "192.168.1.1"     # Gateway
    - "192.168.1.100"   # Known monitoring server
```

### Integration with External Systems
```yaml
# config.yaml
sinks:
  tcp:
    enabled: true
    host: "192.168.1.200"
    port: 514
    protocol: "syslog"
  websocket:
    enabled: true
    host: "localhost"
    port: 8080
    secure: false
  file:
    enabled: true
    path: "/var/log/mlids/external.log"
    format: "json"
```

## Real-World Use Cases

### 1. Web Server Protection
Monitor web application for common attacks:

**Configuration:**
```yaml
# config.yaml
monitoring:
  app_log: "/var/log/apache2/access.log"
  patterns:
    - name: "sql_injection"
      regex: "(\\bUNION\\b|\\bSELECT\\b.*\\bFROM\\b|\\bINSERT\\b.*\\bINTO\\b)"
      severity: "HIGH"
    - name: "xss_attempt"
      regex: "(<script>|javascript:|on\\w+=)"
      severity: "MEDIUM"
    - name: "path_traversal"
      regex: "(\\.\\./|\\.\\.|%2e%2e)"
      severity: "HIGH"
```

**Usage:**
```bash
python index.py start --app-log /var/log/apache2/access.log
```

### 2. Database Server Monitoring
Protect database from unauthorized access:

**Configuration:**
```yaml
# config.yaml
monitoring:
  app_log: "/var/log/mysql/mysql.log"
  network:
    ports: [3306]  # MySQL port
  patterns:
    - name: "failed_login"
      regex: "Access denied for user"
      severity: "MEDIUM"
    - name: "suspicious_query"
      regex: "(DROP\\s+DATABASE|TRUNCATE\\s+TABLE)"
      severity: "CRITICAL"
```

### 3. VPN Server Security
Monitor VPN connections for anomalies:

**Configuration:**
```yaml
# config.yaml
network:
  ports: [1194, 500, 4500]  # OpenVPN, IKE
  protocols: ["UDP", "TCP"]
thresholds:
  connection_rate_threshold: 10  # New connections per minute
  bandwidth_threshold: 1000000  # 1MB/s
```

### 4. IoT Device Network
Monitor IoT devices for unusual behavior:

**Configuration:**
```yaml
# config.yaml
network:
  device_tracking: true
  known_devices:
    - mac: "AA:BB:CC:DD:EE:FF"
      name: "Smart Camera"
      expected_ports: [80, 443]
    - mac: "11:22:33:44:55:66"
      name: "IoT Hub"
      expected_ports: [1883, 8883]  # MQTT
  anomaly_detection:
    enabled: true
    method: "isolation_forest"
    contamination: 0.1
```

## Analysis and Reporting Examples

### Daily Security Report
Generate comprehensive daily security reports:

```bash
# Generate compliance report
python index.py analyze --report compliance --days 1

# Generate with custom output
python index.py analyze --report compliance --output-dir /var/reports/daily

# Include visualizations
python index.py analyze --report compliance --plot --plot-path /var/reports/daily/threats.png
```

**Sample Report Output:**
```
=== MLIDS COMPLIANCE REPORT ===
Period: Last 1 days
Total Events: 1,247
Compliance Status: PASS
Critical Events: 3

Top Event Types:
- Failed Login: 234
- Port Scan: 45
- File Access: 189
- Network Anomaly: 12

Recommendations:
• Consider implementing account lockout policies (high failed login count)
• Review firewall rules for scanned ports
```

### Threat Hunting Queries
Advanced search and analysis examples:

```bash
# Find brute force attacks
python index.py analyze --search "Failed Login" --days 7

# Find SQL injection attempts
python index.py analyze --search "SQL Injection"

# Find lateral movement indicators
python index.py analyze --search "Successful Login AND File Access"

# Find anomalies by IP
python index.py analyze --search "ip:192.168.1.100"

# Complex queries with time ranges
python index.py analyze --search "Failed Login AND timestamp:2025-01-13"
```

### Statistical Analysis
Use Python for advanced threat analysis:

```python
import pandas as pd
import matplotlib.pyplot as plt
from mlids.analyzer import Analyzer

# Load and analyze data (Analyzer reads rotated files from `logs/`)
analyzer = Analyzer(logs_dir='logs')
df = analyzer.load_data(days=30)

# Analyze attack patterns
attack_patterns = df[df['type'].isin(['SQL Injection', 'XSS', 'Brute Force'])]
patterns_by_hour = attack_patterns.groupby(attack_patterns['timestamp'].dt.hour).size()

# Visualize patterns
plt.figure(figsize=(12, 6))
patterns_by_hour.plot(kind='bar')
plt.title('Attack Patterns by Hour')
plt.xlabel('Hour of Day')
plt.ylabel('Number of Attacks')
plt.savefig('attack_patterns.png')

# Detect anomalies
from mlids.analysis import AnomalyDetector
detector = AnomalyDetector()
anomalies = detector.detect(df, method='mad', threshold=3.0)

print(f"Detected {len(anomalies)} anomalous events")
for anomaly in anomalies[:5]:
    print(f"- {anomaly['timestamp']}: {anomaly['type']} ({anomaly['score']:.2f})")
```

## Integration Examples

### SIEM Integration (Splunk)
Send events to Splunk for centralized logging:

```bash
# Configure TCP sink for Splunk
python index.py start --tcp-sink --tcp-host splunk.example.local --tcp-port 514

# Splunk search examples
# Search for all MLIDS events
index=mlids

# Search for high-severity events
index=mlids severity=HIGH

# Create dashboard panels
| timechart count by type
| stats count by details.ip | sort -count | head 10
```

### ELK Stack Integration
Send events to Elasticsearch for advanced analytics:

```bash
# Send to Logstash
python index.py start --tcp-sink --tcp-host logstash.example.local --tcp-port 5044
```

**Elasticsearch Queries:**
```json
{
  "query": {
    "bool": {
      "must": [
        {"match": {"type": "Failed Login"}},
        {"range": {"timestamp": {"gte": "now-24h"}}}
      ]
    }
  }
}
```

**Kibana Dashboard Configuration:**
```json
{
  "title": "MLIDS Security Dashboard",
  "panels": [
    {
      "type": "histogram",
      "query": {"match_all": {}},
      "field": "timestamp",
      "interval": "1h"
    },
    {
      "type": "pie",
      "query": {"match_all": {}},
      "field": "type"
    }
  ]
}
```

### Real-time Dashboard (WebSocket)
Create real-time security dashboard:

```javascript
// dashboard.js
const ws = new WebSocket('ws://localhost:8080');

ws.onmessage = function(event) {
  const message = JSON.parse(event.data);

  if (message.type === 'event') {
    addEventToDashboard(message.data);
    updateStats(message.data);
  } else if (message.type === 'stats') {
    updateGlobalStats(message.data);
  }
};

function addEventToDashboard(event) {
  const eventDiv = document.createElement('div');
  eventDiv.className = `event ${event.severity.toLowerCase()}`;
  eventDiv.innerHTML = `
    <span class="timestamp">${new Date(event.timestamp).toLocaleTimeString()}</span>
    <span class="type">${event.event_type}</span>
    <span class="details">${JSON.stringify(event.details)}</span>
  `;
  document.getElementById('events').prepend(eventDiv);
}

function updateStats(event) {
  // Update counters, charts, etc.
  const counter = document.getElementById(`${event.event_type.toLowerCase()}-count`);
  counter.textContent = parseInt(counter.textContent) + 1;
}
```

**HTML Dashboard:**
```html
<!DOCTYPE html>
<html>
<head>
  <title>MLIDS Real-time Dashboard</title>
  <style>
    .event { padding: 10px; margin: 5px; border-radius: 5px; }
    .high { background-color: #ffcccc; }
    .medium { background-color: #ffffcc; }
    .low { background-color: #ccffcc; }
    #events { max-height: 400px; overflow-y: auto; }
  </style>
</head>
<body>
  <h1>MLIDS Security Dashboard</h1>
  <div id="stats">
    <div>Failed Logins: <span id="failed login-count">0</span></div>
    <div>Port Scans: <span id="port scan-count">0</span></div>
    <div>SQL Injections: <span id="sql injection-count">0</span></div>
  </div>
  <div id="events"></div>
  <script src="dashboard.js"></script>
</body>
</html>
```

### Custom Alert System
Implement custom alerting based on event patterns:

```python
from mlids.events import EventHandler, Event
import smtplib
from email.mime.text import MIMEText

class EmailAlertHandler(EventHandler):
    def __init__(self, smtp_server, smtp_port, username, password, recipients):
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.username = username
        self.password = password
        self.recipients = recipients

    def handle_event(self, event: Event):
        if event.severity in ['HIGH', 'CRITICAL']:
            self.send_alert(event)

    def send_alert(self, event: Event):
        msg = MIMEText(f"""
        MLIDS Security Alert

        Type: {event.type}
        Severity: {event.severity}
        Timestamp: {event.timestamp}
        Details: {event.details}

        Please investigate immediately.
        """)

        msg['Subject'] = f'MLIDS Alert: {event.type}'
        msg['From'] = self.username
        msg['To'] = ', '.join(self.recipients)

        try:
            server = smtplib.SMTP(self.smtp_server, self.smtp_port)
            server.starttls()
            server.login(self.username, self.password)
            server.sendmail(self.username, self.recipients, msg.as_string())
            server.quit()
        except Exception as e:
            print(f"Failed to send email alert: {e}")

# Usage
email_handler = EmailAlertHandler(
    smtp_server='smtp.gmail.com',
    smtp_port=587,
    username='alerts@company.com',
    password='password',
    recipients=['security@company.com', 'admin@company.com']
)

mlids.register_handler(email_handler)
```

## Performance Optimization Examples

### High-Traffic Network Monitoring
Optimize for networks with high packet rates:

```yaml
# config.yaml
network:
  sampling_rate: 0.1  # Sample 10% of packets
  buffer_size: 10000  # Increase buffer for bursts
  worker_threads: 4   # Parallel processing

analysis:
  streaming: true     # Process events in real-time
  batch_size: 100     # Process in small batches
  cache_size: 1000    # Cache recent events
```

### Large-Scale Log Analysis
Handle large volumes of log data:

```yaml
# config.yaml
logging:
  compression: true
  rotation: hourly
  retention: 30  # days

analysis:
  parallel_processing: true
  chunk_size: 100000  # Process 100k events at a time
  memory_limit: 2048  # MB
```

### Resource-Constrained Environments
Optimize for low-resource systems:

```yaml
# config.yaml
monitoring:
  lightweight_mode: true
  disable_patterns:
    - "packet_analysis"  # Skip detailed packet inspection
    - "file_hashing"     # Skip file integrity checks

analysis:
  simple_stats: true   # Use basic statistics only
  disable_ml: true     # Disable machine learning features
```

## Custom Detection Rules

### Advanced Pattern Matching
Create custom detection patterns:

```python
from mlids.detection import PatternDetector
import re

class AdvancedSQLInjectionDetector(PatternDetector):
    def __init__(self):
        self.patterns = [
            re.compile(r'(\bUNION\b.*\bSELECT\b)', re.IGNORECASE),
            re.compile(r'(\bINSERT\b.*\bINTO\b.*\bSELECT\b)', re.IGNORECASE),
            re.compile(r'(\bUPDATE\b.*\bSET\b.*=.*\bSELECT\b)', re.IGNORECASE),
            re.compile(r'(;\s*DROP\s+TABLE)', re.IGNORECASE),
        ]
        self.context_patterns = [
            re.compile(r'(\bFROM\b\s+\w+\s*;\s*DROP)', re.IGNORECASE),
        ]

    def detect(self, data):
        threats = []
        for pattern in self.patterns:
            matches = pattern.findall(data)
            if matches:
                threats.extend(matches)

        # Check for context-aware patterns
        for pattern in self.context_patterns:
            if pattern.search(data):
                threats.append("Context-aware SQL injection detected")

        return threats

# Register custom detector
detector = AdvancedSQLInjectionDetector()
mlids.register_detector(detector, 'sql_injection_advanced')
```

### Behavioral Analysis
Implement user behavior analytics:

```python
from mlids.analysis import BehavioralAnalyzer
from collections import defaultdict
import time

class UserBehaviorAnalyzer(BehavioralAnalyzer):
    def __init__(self):
        self.user_sessions = defaultdict(list)
        self.normal_patterns = {}

    def analyze_session(self, user, events):
        """Analyze user session for anomalies"""
        session_start = min(event['timestamp'] for event in events)
        session_end = max(event['timestamp'] for event in events)
        duration = (session_end - session_start).total_seconds()

        # Calculate session metrics
        event_types = [event['type'] for event in events]
        failed_logins = event_types.count('Failed Login')
        file_accesses = event_types.count('File Access')
        unusual_hours = self._check_unusual_hours(session_start)

        # Score session
        score = 0
        if failed_logins > 3:
            score += 2
        if file_accesses > 20:
            score += 1
        if unusual_hours:
            score += 1
        if duration > 3600:  # Long session
            score += 1

        return {
            'user': user,
            'score': score,
            'duration': duration,
            'failed_logins': failed_logins,
            'file_accesses': file_accesses,
            'unusual_hours': unusual_hours
        }

    def _check_unusual_hours(self, timestamp):
        """Check if login time is unusual for user"""
        hour = timestamp.hour
        # Define normal hours (9 AM - 6 PM)
        return not (9 <= hour <= 18)

# Usage
behavior_analyzer = UserBehaviorAnalyzer()

# Analyze user sessions
suspicious_sessions = []
for user, events in user_sessions.items():
    analysis = behavior_analyzer.analyze_session(user, events)
    if analysis['score'] >= 3:
        suspicious_sessions.append(analysis)

print(f"Found {len(suspicious_sessions)} suspicious sessions")
```

These examples demonstrate the flexibility and power of MLIDS for various security monitoring scenarios. The system can be customized and extended to meet specific security requirements and integration needs.