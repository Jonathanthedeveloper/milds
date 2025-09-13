# MLIDS API Reference

## Command Line Interface

### Main Commands

#### `start`
Starts the MLIDS monitoring system with specified configuration.

**Syntax:**
```bash
python index.py start [OPTIONS]
```

**Options:**
- `--interface INTERFACE`: Network interface to monitor (default: auto-detect)
- `--dir DIRECTORY`: Directory to monitor for file changes (default: current directory)
- `--app-log FILE`: Application log file to monitor (default: auto-detect)
- `--config FILE`: Configuration file path (default: config.yaml)
Note: MLIDS writes logs to the `logs/` directory by default. Use the `--config` or
`logs_dir` setting to change the directory.
- `--tcp-sink`: Enable TCP event sink
- `--tcp-host HOST`: TCP sink host (default: localhost)
- `--tcp-port PORT`: TCP sink port (default: 9999)
- `--websocket-sink`: Enable WebSocket event sink
- `--websocket-host HOST`: WebSocket sink host (default: localhost)
- `--websocket-port PORT`: WebSocket sink port (default: 8080)
- `--verbose`: Enable verbose logging
- `--debug`: Enable debug mode

**Examples:**
```bash
# Start with default settings
python index.py start

# Start with specific network interface
python index.py start --interface wlan0

# Start with custom configuration
python index.py start --config /etc/mlids/config.yaml

# Start with TCP sink for external integration
python index.py start --tcp-sink --tcp-host 192.168.1.100 --tcp-port 514

# Start with WebSocket sink for real-time dashboard
python index.py start --websocket-sink --websocket-port 8080
```

#### `analyze`
Analyzes log data and generates reports.

**Syntax:**
```bash
python index.py analyze [OPTIONS]
```

**Options:**
- `--search QUERY`: Search query for filtering events
- `--report TYPE`: Generate specific report (compliance, summary)
- `--plot`: Generate visualization plots
- `--plot-path PATH`: Output path for plots (default: current directory)
- `--output-dir DIR`: Output directory for reports
- `--days DAYS`: Number of days to analyze (default: 30)
- `--format FORMAT`: Output format (json, csv, txt)

**Examples:**
```bash
# Basic analysis
python index.py analyze

# Search for specific events
python index.py analyze --search "Failed Login"

# Generate compliance report
python index.py analyze --report compliance

# Generate plots
python index.py analyze --plot

# Analyze last 7 days
python index.py analyze --days 7

# Export to CSV
python index.py analyze --format csv --output-dir /var/reports
```

#### `config`
Manages MLIDS configuration settings.

**Syntax:**
```bash
python index.py config [OPTIONS]
```

**Options:**
- `--list`: List all configuration settings
- `--get KEY`: Get value of specific configuration key
- `--set KEY VALUE`: Set configuration key to value
- `--reset`: Reset configuration to defaults
- `--validate`: Validate configuration file

**Examples:**
```bash
# List all settings
python index.py config --list

# Get specific setting
python index.py config --get port_scan_threshold

# Set threshold value
python index.py config --set port_scan_threshold 15

# Reset to defaults
python index.py config --reset

# Validate config file
python index.py config --validate
```

## Configuration API

### Configuration File Format

MLIDS uses YAML configuration files with the following structure:

```yaml
# MLIDS Configuration File
version: "1.0"

# Monitoring Settings
monitoring:
  enabled: true
  interface: "auto"  # Network interface to monitor
  directory: "/var/log"  # Directory for file monitoring
  app_log: "/var/log/auth.log"  # Application log file

# Detection Thresholds
thresholds:
  port_scan_threshold: 10
  brute_force_threshold: 5
  packet_rate_threshold: 100
  anomaly_threshold: 3.5

# Logging Configuration
logging:
  level: "INFO"
  # Note: supply the main logfile to the logger at runtime or via the CLI.
  # Logs are written to the `logs/` directory by default; configure `logs_dir` instead
  file: "(managed by application in logs/)"
  max_size: 10485760  # 10MB
  backup_count: 5
  format: "json"

# Event Sinks
sinks:
  tcp:
    enabled: false
    host: "localhost"
    port: 9999
  websocket:
    enabled: false
    host: "localhost"
    port: 8080

# Analysis Settings
analysis:
  window_size: 300  # Analysis window in seconds
  statistical_method: "mad"  # mad, zscore, isolation_forest
  alert_threshold: 0.95

# Integration Settings
integrations:
  splunk:
    enabled: false
  host: "splunk.example.local"
    port: 514
    token: ""
  elk:
    enabled: false
    elasticsearch_url: "http://localhost:9200"
    index_pattern: "mlids-*"
```

### Configuration Keys

#### Monitoring Settings
- `monitoring.enabled`: Enable/disable monitoring (boolean)
- `monitoring.interface`: Network interface name or "auto" (string)
- `monitoring.directory`: Directory path for file monitoring (string)
- `monitoring.app_log`: Application log file path (string)

#### Detection Thresholds
- `thresholds.port_scan_threshold`: Ports scanned before alert (integer)
- `thresholds.brute_force_threshold`: Failed logins before alert (integer)
- `thresholds.packet_rate_threshold`: Packets/second for DoS detection (integer)
- `thresholds.anomaly_threshold`: Statistical anomaly threshold (float)

#### Logging Configuration
- `logging.level`: Log level (DEBUG, INFO, WARNING, ERROR)
- `logging.file`: Log file path (string)
- `logging.max_size`: Maximum log file size in bytes (integer)
- `logging.backup_count`: Number of backup log files (integer)
- `logging.format`: Log format (json, text)

#### Event Sinks
- `sinks.tcp.enabled`: Enable TCP sink (boolean)
- `sinks.tcp.host`: TCP sink hostname (string)
- `sinks.tcp.port`: TCP sink port (integer)
- `sinks.websocket.enabled`: Enable WebSocket sink (boolean)
- `sinks.websocket.host`: WebSocket sink hostname (string)
- `sinks.websocket.port`: WebSocket sink port (integer)

## Event Data Structures

### Event Schema

All MLIDS events follow this JSON schema:

```json
{
  "timestamp": "2025-01-13T10:30:45Z",
  "type": "EventType",
  "severity": "LOW|MIDDLE|HIGH|CRITICAL",
  "source": "network|host|application",
  "details": {
    "ip": "192.168.1.100",
    "port": 80,
    "protocol": "TCP",
    "description": "Event description",
    "metadata": {}
  },
  "correlation_id": "uuid-string",
  "tags": ["tag1", "tag2"]
}
```

### Event Types

#### Network Events
- `Port Scan`: Port scanning activity detected
- `DoS Attack`: Denial of service attack detected
- `Packet Anomaly`: Unusual packet patterns
- `Rogue AP`: Unauthorized access point detected

#### Host Events
- `File Created`: New file created
- `File Modified`: File content modified
- `File Deleted`: File deleted
- `File Access`: File accessed (read/write)
- `Integrity Violation`: File integrity check failed

#### Application Events
- `Failed Login`: Authentication failure
- `Successful Login`: Authentication success
- `SQL Injection`: SQL injection attempt detected
- `XSS`: Cross-site scripting attempt detected
- `Command Injection`: Command injection attempt detected
- `Path Traversal`: Directory traversal attempt detected

#### System Events
- `Anomaly Detected`: Statistical anomaly in event patterns
- `Threshold Exceeded`: Configured threshold exceeded
- `Configuration Changed`: System configuration modified
- `Service Started`: MLIDS service started
- `Service Stopped`: MLIDS service stopped

## TCP Event Sink Protocol

### Connection
MLIDS establishes a TCP connection to the configured sink host and port, then sends JSON events as they occur.

### Message Format
Events are sent as JSON lines (one event per line):

```json
{"timestamp":"2025-01-13T10:30:45Z","type":"Failed Login","severity":"MEDIUM","source":"application","details":{"ip":"192.168.1.100","user":"admin"},"correlation_id":"550e8400-e29b-41d4-a716-446655440000","tags":["authentication","failure"]}
```

### Error Handling
- Connection failures are logged locally
- Automatic reconnection attempts every 30 seconds
- Events are buffered during connection outages (max 1000 events)

## WebSocket Event Sink Protocol

### Connection
MLIDS connects to a WebSocket server and sends real-time events.

### Message Types

#### Event Message
```json
{
  "type": "event",
  "data": {
    "timestamp": "2025-01-13T10:30:45Z",
    "event_type": "Failed Login",
    "severity": "MEDIUM",
    "details": {
      "ip": "192.168.1.100",
      "user": "admin"
    }
  }
}
```

#### Heartbeat Message
```json
{
  "type": "heartbeat",
  "timestamp": "2025-01-13T10:30:45Z",
  "uptime": 3600
}
```

#### Statistics Message
```json
{
  "type": "stats",
  "data": {
    "events_per_second": 2.5,
    "total_events": 15000,
    "active_alerts": 3
  }
}
```

### Client Implementation Example
```javascript
// WebSocket client for MLIDS events
const ws = new WebSocket('ws://localhost:8080');

ws.onmessage = function(event) {
  const message = JSON.parse(event.data);

  if (message.type === 'event') {
    handleSecurityEvent(message.data);
  } else if (message.type === 'stats') {
    updateDashboard(message.data);
  }
};

function handleSecurityEvent(event) {
  console.log(`Security Event: ${event.event_type} from ${event.details.ip}`);
  // Update UI, send alerts, etc.
}
```

## Python API

### Core Classes

#### MLIDS Class
Main class for running MLIDS monitoring.

```python
from mlids import MLIDS

# Initialize with configuration
mlids = MLIDS(config_file='config.yaml')

# Start monitoring
mlids.start()

# Stop monitoring
mlids.stop()
```

#### EventLogger Class
Handles event logging and storage.

```python
from mlids.logger import EventLogger

# Initialize logger (application writes to files under `logs/` by default)
logger = EventLogger(logs_dir='logs')

# Log an event
logger.log_event(
  event_type='Failed Login',
  details={'ip': '192.168.1.100', 'user': 'admin'},
  severity='MEDIUM'
)

# Search events (reads aggregated/rotated files from logs_dir)
events = logger.search_events('Failed Login', hours=24)
```

#### Analyzer Class
Provides analysis and reporting capabilities.

```python
from mlids.analyzer import Analyzer

# Initialize analyzer (reads aggregated rotated files from logs/ by default)
analyzer = Analyzer(logs_dir='logs')

# Generate summary report
summary = analyzer.generate_summary(days=30)

# Detect anomalies
anomalies = analyzer.detect_anomalies(window_hours=24)

# Export report
analyzer.export_report(format='json', output_file='report.json')
```

### Event Handling

#### Custom Event Handlers
```python
from mlids.events import EventHandler

class CustomHandler(EventHandler):
    def handle_event(self, event):
        # Custom event processing
        if event['type'] == 'Failed Login':
            self.send_alert(event)
        elif event['type'] == 'SQL Injection':
            self.block_ip(event['details']['ip'])

# Register custom handler
mlids.register_handler(CustomHandler())
```

#### Event Filtering
```python
from mlids.events import EventFilter

# Create filter for high-severity events
high_severity_filter = EventFilter(
    severity=['HIGH', 'CRITICAL']
)

# Create filter for specific event types
attack_filter = EventFilter(
    event_types=['SQL Injection', 'XSS', 'Brute Force']
)

# Apply filters
filtered_events = mlids.get_events(filters=[high_severity_filter, attack_filter])
```

### Configuration Management

#### Dynamic Configuration
```python
from mlids.config import ConfigManager

# Load configuration
config = ConfigManager('config.yaml')

# Get setting
threshold = config.get('thresholds.port_scan_threshold')

# Update setting
config.set('thresholds.port_scan_threshold', 15)

# Save configuration
config.save()

# Reload configuration
config.reload()
```

#### Configuration Validation
```python
from mlids.config import ConfigValidator

# Validate configuration
validator = ConfigValidator()
errors = validator.validate(config)

if errors:
    for error in errors:
        print(f"Configuration error: {error}")
else:
    print("Configuration is valid")
```

## Integration Examples

### Splunk Integration
```python
from mlids.integrations.splunk import SplunkSink

# Configure Splunk sink
splunk = SplunkSink(
  host='splunk.example.local',
    port=514,
    token='your-splunk-token'
)

# Send events to Splunk
mlids.add_sink(splunk)
```

### ELK Stack Integration
```python
from mlids.integrations.elk import ELKSink

# Configure ELK sink
elk = ELKSink(
    elasticsearch_url='http://localhost:9200',
    index_pattern='mlids-{timestamp:%Y.%m.%d}'
)

# Send events to Elasticsearch
mlids.add_sink(elk)
```

### Custom Integration
```python
from mlids.events import EventSink

class CustomSink(EventSink):
    def __init__(self, api_endpoint):
        self.api_endpoint = api_endpoint

    def send_event(self, event):
        # Send event to custom API
        import requests
        response = requests.post(self.api_endpoint, json=event)
        response.raise_for_status()

# Add custom sink
custom_sink = CustomSink('https://api.example.local/security-events')
mlids.add_sink(custom_sink)
```

## Error Codes

### System Errors
- `E001`: Configuration file not found
- `E002`: Invalid configuration format
- `E003`: Network interface not available
- `E004`: Log file permission denied
- `E005`: Required dependency missing

### Runtime Errors
- `E101`: Network monitoring failed
- `E102`: File monitoring failed
- `E103`: Log parsing failed
- `E104`: Sink connection failed
- `E105`: Analysis engine error

### Recovery Actions
```python
try:
    mlids.start()
except MLIDSError as e:
    if e.code == 'E001':
        print("Configuration file missing. Creating default config...")
        create_default_config()
    elif e.code == 'E003':
        print("Network interface unavailable. Using alternative interface...")
        mlids.set_interface('eth0')
    else:
        print(f"Error: {e.message}")
        mlids.stop()
```

This API reference provides comprehensive documentation for integrating with and extending MLIDS functionality.