# Multi-Level IDS (MLIDS) - AI Agent Instructions

## Project Overview
This is a Python-based CLI tool for multi-level intrusion detection across network, host, and application layers. The system monitors for threats like port scans, brute force attacks, SQL injection, XSS, file integrity violations, DoS attacks, and statistical anomalies.

## Architecture & Key Components

### Core Monitoring Modules
- **Network Monitor**: Uses Scapy for packet analysis, detects port scans, DoS, rogue APs, and packet anomalies
- **Host Monitor**: Uses Watchdog for file system monitoring with SHA256 integrity checking
- **Application Monitor**: Uses Tailer for log file monitoring with regex-based attack detection

### Data Flow
1. Events detected by monitors → logged as JSON entries with timestamps
2. Logs stored in `logs/` (configurable)
3. Analysis via Pandas for statistical anomaly detection using MAD (Median Absolute Deviation)
4. Correlation engine links related threats across monitoring layers

## Critical Patterns & Conventions

### 1. Dependency Handling
Always check library availability before use:
```python
try:
    import scapy.all
except ImportError:
    print("Warning: Scapy not installed. Network monitoring disabled.")
    scapy = None
```
Use graceful degradation - continue operation with reduced functionality when dependencies missing.

### 2. Event Logging Pattern
Standardize all alerts using `log_event()`:
```python
def log_event(event_type, details):
    entry = {'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'), 'type': event_type, 'details': details}
    # JSON line format for easy parsing
```

### 3. Threshold-Based Detection
Configure detection thresholds in `CONFIG` dict:
```python
CONFIG = {
    'port_scan_threshold': 10,  # Ports before triggering
    'brute_force_threshold': 5,  # Failed logins before triggering
    'packet_rate_threshold': 100,  # Packets/sec for DoS detection
}
```

### 4. Statistical Anomaly Detection
Use MAD (Median Absolute Deviation) for robust outlier detection:
```python
median = np.median(values)
mad = np.median([abs(v - median) for v in values])
if mad > 0 and abs(value - median) / mad > 3.5:
    log_event("Anomaly", f"Unusual value: {value}")
```

### 5. Cross-Platform Compatibility
Handle OS-specific paths and commands:
```python
'app_log_file': 'C:\\inetpub\\logs\\LogFiles\\W3SVC1\\u_ex*.log' if platform.system() == 'Windows' else '/var/log/apache2/access.log'
```

### 6. Threading Architecture
Use daemon threads for concurrent monitoring:
```python
threading.Thread(target=network_monitor, args=(args.interface,), daemon=True).start()
```

## Development Workflows

### Running the System
```bash
# Start monitoring with auto-detected interface
python index.py start

# Start with specific network interface
python index.py start --interface wlan0

# Monitor specific directory and log file
python index.py start --dir /var/log --app-log /var/log/auth.log
```

### Analysis Commands
```bash
# Basic log summary
python index.py analyze

# Search logs for specific terms
python index.py analyze --search "192.168.1.1"

# Configure thresholds
python index.py config --key port_scan_threshold --value 15
```

### Testing Dependencies
The system gracefully handles missing libraries. Test with:
```bash
pip install scapy watchdog tailer pandas numpy
```

## Key Files & Structure
- `index.py`: Main CLI application with all monitoring logic
- `consideration.md`: Feature roadmap and enhancement suggestions
- `logs/`: Directory for log output files (auto-created)

## Integration Points
- **External Libraries**: Scapy (network), Watchdog (filesystem), Tailer (logs), Pandas/NumPy (analysis)
- **System Integration**: iptables/netsh for automated responses, system log files
- **Cloud Ready**: Designed for IaaS/PaaS environments with elastic scaling considerations

## Common Patterns to Follow
1. Always add new threat types using the `log_event()` pattern
2. Use configurable thresholds from `CONFIG` dict
3. Implement statistical analysis with MAD for anomaly detection
4. Handle cross-platform differences explicitly
5. Add dependency checks with graceful degradation
6. Use threading for concurrent operations
7. Store all data in JSON format for easy analysis

## Extension Guidelines
When adding new detection modules:
1. Follow the threading pattern for concurrency
2. Use `log_event()` for standardized logging
3. Add configuration options to `CONFIG` dict
4. Include dependency checks
5. Consider cross-platform compatibility
6. Add correlation logic to link with existing threats