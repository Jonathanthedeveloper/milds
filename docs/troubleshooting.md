# MLIDS Troubleshooting Guide

## Common Issues and Solutions

### Installation Issues

#### Python Version Compatibility
**Problem:** MLIDS fails to start with Python version errors.

**Symptoms:**
```
ImportError: No module named 'scapy'
ModuleNotFoundError: No module named 'watchdog'
```

**Solutions:**
1. Check Python version:
```bash
python --version
# Should be Python 3.8 or higher
```

2. Install correct Python version:
```bash
# On Ubuntu/Debian
sudo apt update
sudo apt install python3.8 python3.8-venv

# On CentOS/RHEL
sudo yum install python38 python38-devel

# On Windows
# Download from python.org
```

3. Use virtual environment:
```bash
python -m venv mlids_env
source mlids_env/bin/activate  # Linux/Mac
# or
mlids_env\Scripts\activate     # Windows
pip install -r requirements.txt
```

#### Dependency Installation Failures
**Problem:** pip install fails for certain packages.

**Symptoms:**
```
ERROR: Failed building wheel for scapy
ERROR: Could not build wheels for watchdog
```

**Solutions:**
1. Install system dependencies:
```bash
# Ubuntu/Debian
sudo apt install python3-dev libpcap-dev

# CentOS/RHEL
sudo yum install python3-devel libpcap-devel

# macOS
brew install libpcap
```

2. Use pre-compiled wheels:
```bash
pip install --only-binary=all scapy watchdog
```

3. Install from source with specific compiler flags:
```bash
pip install --no-binary scapy scapy
```

### Network Monitoring Issues

#### Interface Detection Problems
**Problem:** MLIDS cannot find or monitor network interfaces.

**Symptoms:**
```
WARNING: Could not detect network interface
ERROR: No suitable interface found
```

**Solutions:**
1. List available interfaces:
```bash
# Linux
ip link show

# Windows
netsh interface show interface

# macOS
ifconfig
```

2. Specify interface manually:
```bash
python index.py start --interface eth0
# or
python index.py start --interface "Wi-Fi"
```

3. Check interface permissions:
```bash
# Linux - ensure user has packet capture permissions
sudo setcap cap_net_raw=eip $(which python)
# or run as root (not recommended for production)
```

#### Packet Capture Failures
**Problem:** Network monitoring starts but no packets are captured.

**Symptoms:**
```
WARNING: Packet capture failed
INFO: 0 packets captured in last minute
```

**Solutions:**
1. Check interface status:
```bash
# Linux
ip link show eth0

# Windows
netsh interface show interface "Wi-Fi"
```

2. Verify promiscuous mode:
```bash
# Linux
ip link set eth0 promisc on
```

3. Check firewall rules:
```bash
# Linux
sudo iptables -L
sudo ufw status

# Windows
netsh advfirewall show allprofiles
```

4. Test with tcpdump/wireshark:
```bash
# Verify packets are visible
sudo tcpdump -i eth0 -c 5
```

### File Monitoring Issues

#### Permission Denied Errors
**Problem:** File monitoring fails due to permission issues.

**Symptoms:**
```
ERROR: Permission denied: /var/log/auth.log
WARNING: File monitoring disabled
```

**Solutions:**
1. Check file permissions:
```bash
ls -la /var/log/auth.log
```

2. Grant read permissions:
```bash
# Add user to appropriate group
sudo usermod -a -G adm $USER

# Or grant specific permissions
sudo chmod 644 /var/log/auth.log
```

3. Run with elevated permissions (if necessary):
```bash
sudo python index.py start
```

4. Use alternative log location:
```bash
python index.py start --app-log /home/user/app.log
```

#### File System Events Not Detected
**Problem:** File changes are not being detected.

**Symptoms:**
```
INFO: File monitoring started
# But no file change events logged
```

**Solutions:**
1. Check if watchdog is properly installed:
```python
python -c "import watchdog; print(watchdog.__version__)"
```

2. Verify directory permissions:
```bash
ls -ld /var/log/
```

3. Test watchdog directly:
```python
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class TestHandler(FileSystemEventHandler):
    def on_modified(self, event):
        print(f"Modified: {event.src_path}")

observer = Observer()
observer.schedule(TestHandler(), "/tmp/test", recursive=True)
observer.start()

# Create/modify a file in /tmp/test and see if events are detected
```

4. Check for file system limitations:
```bash
# Some file systems don't support inotify
df -T /var/log
```

### Application Log Monitoring Issues

#### Log File Parsing Errors
**Problem:** Application logs are not being parsed correctly.

**Symptoms:**
```
WARNING: Failed to parse log line: invalid format
ERROR: Log parsing regex failed
```

**Solutions:**
1. Check log file format:
```bash
head -10 /var/log/auth.log
```

2. Verify log format matches expected pattern:
```python
# Test regex pattern
import re

log_line = "Jan 13 10:30:45 server sshd[1234]: Failed password for admin from 192.168.1.100"
pattern = r'(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\w+)\s+(\w+)\[(\d+)\]:\s+(.+)'

match = re.match(pattern, log_line)
if match:
    print("Pattern matches")
else:
    print("Pattern does not match")
```

3. Customize log parsing patterns:
```yaml
# In config.yaml
app_log_patterns:
  - name: "sshd_failed"
    pattern: '(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\w+)\s+sshd\[(\d+)\]:\s+Failed password for (\w+) from (\d+\.\d+\.\d+\.\d+)'
    fields: ["timestamp", "hostname", "pid", "user", "ip"]
```

4. Handle log rotation:
```bash
# Ensure MLIDS can read rotated logs
ls -la /var/log/auth.log*
```

#### Log File Not Found
**Problem:** Specified log file doesn't exist.

**Symptoms:**
```
ERROR: Log file not found: /var/log/auth.log
```

**Solutions:**
1. Check if file exists:
```bash
ls -la /var/log/auth.log
```

2. Find correct log file location:
```bash
# Common locations
find /var/log -name "*auth*" -o -name "*secure*"
```

3. Configure alternative log file:
```bash
python index.py start --app-log /var/log/secure
```

4. Create log file if it doesn't exist:
```bash
sudo touch /var/log/auth.log
sudo chmod 644 /var/log/auth.log
```

### Configuration Issues

#### Invalid Configuration File
**Problem:** MLIDS fails to start due to configuration errors.

**Symptoms:**
```
ERROR: Invalid configuration file
WARNING: Configuration validation failed
```

**Solutions:**
1. Validate YAML syntax:
```bash
python -c "import yaml; yaml.safe_load(open('config.yaml'))"
```

2. Check for common YAML errors:
```yaml
# Correct
thresholds:
  port_scan_threshold: 10

# Incorrect (missing colon)
thresholds:
  port_scan_threshold 10
```

3. Use configuration validation:
```bash
python index.py config --validate
```

4. Reset to default configuration:
```bash
python index.py config --reset
```

#### Configuration Not Applied
**Problem:** Configuration changes are not taking effect.

**Symptoms:**
```
INFO: Configuration loaded
# But settings don't work as expected
```

**Solutions:**
1. Check configuration file location:
```bash
python index.py start --config /path/to/config.yaml
```

2. Verify configuration values:
```bash
python index.py config --list
```

3. Restart MLIDS after configuration changes:
```bash
# Stop current instance
# Then restart
python index.py start
```

4. Check for syntax errors in config file:
```python
import yaml
with open('config.yaml', 'r') as f:
    config = yaml.safe_load(f)
    print(config)
```

### Performance Issues

#### High CPU Usage
**Problem:** MLIDS consumes excessive CPU resources.

**Symptoms:**
```
# CPU usage > 50%
# System becomes slow
```

**Solutions:**
1. Reduce monitoring scope:
```yaml
# In config.yaml
monitoring:
  enabled: true
  # Monitor specific directory instead of entire filesystem
  directory: "/var/log"
```

2. Adjust analysis intervals:
```yaml
analysis:
  window_size: 600  # Increase from 300 seconds
```

3. Disable unnecessary features:
```yaml
sinks:
  tcp:
    enabled: false  # Disable if not needed
  websocket:
    enabled: false
```

4. Use sampling for high-traffic networks:
```yaml
network:
  sampling_rate: 0.1  # Sample 10% of packets
```

#### High Memory Usage
**Problem:** MLIDS uses excessive memory.

**Symptoms:**
```
# Memory usage > 500MB
# System runs out of memory
```

**Solutions:**
1. Reduce log retention:
```yaml
logging:
  max_size: 10485760  # 10MB instead of 100MB
  backup_count: 3     # Fewer backup files
```

2. Limit event buffering:
```yaml
events:
  max_buffer_size: 1000  # Limit buffered events
```

3. Use streaming analysis:
```yaml
analysis:
  streaming: true
  batch_size: 100
```

#### Disk Space Issues
**Problem:** Log files consume too much disk space.

**Symptoms:**
```
# Disk usage > 80%
# Log files growing rapidly
```

**Solutions:**
1. Enable log rotation:
```yaml
logging:
  rotation: true
  max_size: 10485760  # 10MB
  backup_count: 5
```

2. Compress old logs:
```bash
# Manual compression
gzip /path/to/old/logs/*.log

# Automatic compression
logrotate -f /etc/logrotate.d/mlids
```

3. Use external logging:
```yaml
logging:
  external: true
  syslog_host: "syslog.example.local"
```

### Event Sink Issues

#### TCP Sink Connection Failures
**Problem:** Cannot connect to TCP event sink.

**Symptoms:**
```
ERROR: TCP connection failed
WARNING: Events not sent to sink
```

**Solutions:**
1. Check network connectivity:
```bash
telnet sink.host.com 9999
```

2. Verify sink service is running:
```bash
netstat -tlnp | grep 9999
```

3. Check firewall rules:
```bash
# Linux
sudo ufw allow 9999

# Windows
netsh advfirewall firewall add rule name="MLIDS TCP" dir=in action=allow protocol=TCP localport=9999
```

4. Test connection manually:
```bash
echo "test" | nc sink.host.com 9999
```

#### WebSocket Sink Issues
**Problem:** WebSocket connections fail or drop.

**Symptoms:**
```
ERROR: WebSocket connection failed
WARNING: WebSocket reconnecting
```

**Solutions:**
1. Check WebSocket server:
```bash
curl -I http://websocket.host.com:8080
```

2. Verify WebSocket protocol:
```javascript
// Test with simple client
const ws = new WebSocket('ws://localhost:8080');
ws.onopen = () => console.log('Connected');
ws.onerror = (error) => console.log('Error:', error);
```

3. Check proxy/firewall settings:
```bash
# Ensure WebSocket traffic is allowed
# Check for proxy servers blocking ws:// protocol
```

4. Enable heartbeat monitoring:
```yaml
websocket:
  heartbeat_interval: 30
  reconnect_delay: 5
```

### Analysis and Reporting Issues

#### Analysis Performance Problems
**Problem:** Log analysis takes too long or fails.

**Symptoms:**
```
WARNING: Analysis timeout
ERROR: Memory error during analysis
```

**Solutions:**
1. Reduce analysis scope:
```bash
python index.py analyze --days 7  # Instead of 30
```

2. Use sampling for large datasets:
```bash
python index.py analyze --sample 0.1  # 10% sample
```

3. Optimize analysis queries:
```bash
# Use specific search terms
python index.py analyze --search "Failed Login"

# Instead of analyzing all events
python index.py analyze
```

4. Increase system resources:
```bash
# Add more memory or use larger instance
```

#### Report Generation Failures
**Problem:** Cannot generate reports or plots.

**Symptoms:**
```
ERROR: Report generation failed
ImportError: No module named 'matplotlib'
```

**Solutions:**
1. Install visualization dependencies:
```bash
pip install matplotlib seaborn plotly
```

2. Check disk space for report output:
```bash
df -h
```

3. Use alternative output formats:
```bash
python index.py analyze --format csv  # Instead of plots
```

4. Fix matplotlib backend:
```python
import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend
```

### Integration Issues

#### Splunk Integration Problems
**Problem:** Events not appearing in Splunk.

**Symptoms:**
```
INFO: Events sent to Splunk
# But no events in Splunk dashboard
```

**Solutions:**
1. Check Splunk configuration:
```bash
# Verify Splunk is listening on correct port
netstat -tlnp | grep 514
```

2. Verify token authentication:
```bash
# Test with curl
curl -H "Authorization: Splunk <token>" https://splunk.example.local:8089/services/collector/event -d '{"event": "test"}'
```

3. Check data format:
```bash
# Ensure events are in correct format for Splunk
```

#### ELK Stack Integration Issues
**Problem:** Events not indexed in Elasticsearch.

**Symptoms:**
```
ERROR: Elasticsearch connection failed
WARNING: Events not sent to ELK
```

**Solutions:**
1. Check Elasticsearch cluster status:
```bash
curl http://localhost:9200/_cluster/health
```

2. Verify index permissions:
```bash
curl http://localhost:9200/_cat/indices/mlids-*
```

3. Check Logstash pipeline:
```bash
# Verify Logstash config
cat /etc/logstash/conf.d/mlids.conf
```

4. Test Elasticsearch connection:
```bash
curl -X POST http://localhost:9200/mlids-test/_doc -H 'Content-Type: application/json' -d '{"test": "event"}'
```

### System Integration Issues

#### Service Startup Problems
**Problem:** MLIDS fails to start as a system service.

**Symptoms:**
```
ERROR: Service failed to start
systemctl status mlids
```

**Solutions:**
1. Check service configuration:
```bash
cat /etc/systemd/system/mlids.service
```

2. Fix service file:
```ini
[Unit]
Description=MLIDS Intrusion Detection System
After=network.target

[Service]
Type=simple
User=mlids
ExecStart=/usr/bin/python /opt/mlids/index.py start
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

3. Reload systemd and restart:
```bash
sudo systemctl daemon-reload
sudo systemctl restart mlids
```

4. Check service logs:
```bash
sudo journalctl -u mlids -f
```

#### Cron Job Issues
**Problem:** Scheduled analysis jobs fail.

**Symptoms:**
```
# Cron job doesn't run
# No reports generated
```

**Solutions:**
1. Check cron configuration:
```bash
crontab -l
```

2. Fix cron job:
```bash
# Add to crontab
0 2 * * * /usr/bin/python /opt/mlids/index.py analyze --report compliance
```

3. Check cron logs:
```bash
grep CRON /var/log/syslog
```

4. Test cron job manually:
```bash
/usr/bin/python /opt/mlids/index.py analyze --report compliance
```

### Debugging Tools

#### Enable Debug Logging
```bash
# Start with debug mode
python index.py start --debug

# Or set in config
logging:
  level: "DEBUG"
```

#### Packet Capture Debugging
```bash
# Use tcpdump to verify packet capture
sudo tcpdump -i eth0 -w capture.pcap

# Analyze with Wireshark
wireshark capture.pcap
```

#### Log Analysis Debugging
```python
# Test log parsing
from mlids.app_monitor import LogParser

parser = LogParser()
test_line = "Jan 13 10:30:45 server sshd[1234]: Failed password for admin"
parsed = parser.parse_line(test_line)
print(parsed)
```

#### Performance Profiling
```python
import cProfile
import pstats

cProfile.run('mlids.start()', 'profile.stats')
p = pstats.Stats('profile.stats')
p.sort_stats('cumulative').print_stats(10)
```

#### Memory Usage Analysis
```python
import tracemalloc

tracemalloc.start()
# Run MLIDS for a while
current, peak = tracemalloc.get_traced_memory()
print(f"Current memory usage: {current / 1024 / 1024:.1f} MB")
print(f"Peak memory usage: {peak / 1024 / 1024:.1f} MB")
```

### Getting Help

#### Log File Locations
 - Main logs directory: `logs/` (contains `mlids.json` and rotated backups)
- System logs: `/var/log/syslog` (Linux), `Event Viewer` (Windows)
- Application logs: `/var/log/mlids/` (if configured)

#### Support Information
When reporting issues, include:
1. MLIDS version: `python index.py --version`
2. Python version: `python --version`
3. Operating system: `uname -a` (Linux/Mac), `systeminfo` (Windows)
4. Configuration file: `config.yaml`
5. Recent log entries: Last 50 lines from files in `logs/` (e.g. `tail -n 50 logs/mlids.json`)
6. Error messages: Complete error output
7. Steps to reproduce: Detailed reproduction steps

#### Community Resources
- GitHub Issues: Report bugs and request features
- Documentation: Check docs/ folder for detailed guides
- Mailing List: Subscribe for updates and discussions

This troubleshooting guide covers the most common issues and their solutions. For complex problems, consider enabling debug logging and collecting detailed system information before seeking help.