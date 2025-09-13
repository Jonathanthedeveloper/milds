# MLIDS Analysis and Reporting Guide

## Analysis Overview

MLIDS provides comprehensive log analysis capabilities for security event investigation, reporting, and compliance. The analysis system supports real-time monitoring, historical analysis, and automated reporting.

## Log Analysis Commands

### Basic Log Analysis
```bash
# View recent events summary
python index.py analyze

# Search for specific events
python index.py analyze --search "Failed Login"

# Search with multiple terms
python index.py analyze --search "SQL Injection OR XSS"
```

### Advanced Search Queries
```bash
# Search by IP address
python index.py analyze --search "192.168.1.100"

# Search by event type
python index.py analyze --search "type:File Modified"

# Search by time range
python index.py analyze --search "timestamp:2025-01-13"

# Complex queries
python index.py analyze --search "Failed Login AND ip:192.168.1.100"
```

## Reporting Features

### Compliance Reports
```bash
# Generate compliance report
python index.py analyze --report compliance

# Custom report output location
python index.py analyze --report compliance --output-dir "/var/reports"
```

### Visual Reports
```bash
# Generate event type summary plot
python index.py analyze --plot

# Custom plot output
python index.py analyze --plot --plot-path "/var/reports/threat_summary.png"
```

### Automated Reporting
```bash
# Daily compliance report
0 2 * * * /path/to/mlids/python index.py analyze --report compliance

# Weekly threat summary
0 3 * * 1 /path/to/mlids/python index.py analyze --plot
```

## Data Analysis with Pandas

# Loading Log Data
```python
import pandas as pd
import json
import glob
import os

def load_logs_from_dir(logs_dir='logs'):
    """Aggregate JSON-line logs from the configured logs directory.

    This will include rotated files whose names start with `mlids_logs`.
    """
    pattern = os.path.join(logs_dir, 'mlids_logs*')
    files = sorted([p for p in glob.glob(pattern) if os.path.isfile(p)])
    logs = []
    for fname in files:
        with open(fname, 'r', encoding='utf-8') as f:
            for line in f:
                try:
                    logs.append(json.loads(line.strip()))
                except Exception:
                    continue
    return pd.DataFrame(logs)

df = load_logs_from_dir()
print(df.head())
```

### Event Type Analysis
```python
# Event type distribution
event_counts = df['type'].value_counts()
print(event_counts)

# Event type over time
df['timestamp'] = pd.to_datetime(df['timestamp'])
events_over_time = df.groupby([df['timestamp'].dt.date, 'type']).size().unstack()
print(events_over_time)
```

### IP Address Analysis
```python
# Extract IP addresses from events
def extract_ip(event):
    details = event.get('details', {})
    return details.get('ip') or details.get('src_ip')

df['ip'] = df.apply(extract_ip, axis=1)

# Top source IPs
top_ips = df['ip'].value_counts().head(10)
print(top_ips)

# Failed login attempts by IP
failed_logins = df[df['type'] == 'Failed Login']
failed_by_ip = failed_logins['ip'].value_counts()
print(failed_by_ip)
```

### Time-based Analysis
```python
# Events per hour
events_per_hour = df.groupby(df['timestamp'].dt.hour).size()
print(events_per_hour)

# Peak activity times
peak_hours = events_per_hour.nlargest(5)
print("Peak activity hours:")
print(peak_hours)

# Daily patterns
daily_pattern = df.groupby([df['timestamp'].dt.dayofweek, df['timestamp'].dt.hour]).size()
print(daily_pattern)
```

## Statistical Analysis

### Anomaly Detection
```python
import numpy as np

# Median Absolute Deviation (MAD) for outlier detection
def detect_anomalies(data, threshold=3.5):
    median = np.median(data)
    mad = np.median([abs(x - median) for x in data])
    if mad == 0:
        return []
    anomalies = []
    for i, value in enumerate(data):
        z_score = abs(value - median) / mad
        if z_score > threshold:
            anomalies.append((i, value, z_score))
    return anomalies

# Detect anomalous event frequencies
event_freq = df.groupby(df['timestamp'].dt.hour).size()
anomalies = detect_anomalies(event_freq.values)
print("Detected anomalies:")
for hour, count, z_score in anomalies:
    print(f"Hour {hour}: {count} events (z-score: {z_score:.2f})")
```

### Trend Analysis
```python
# Moving averages
event_freq = df.groupby(df['timestamp'].dt.date).size()
moving_avg = event_freq.rolling(window=7).mean()
print("7-day moving average:")
print(moving_avg)

# Trend detection
from scipy import stats
slope, intercept, r_value, p_value, std_err = stats.linregress(
    range(len(event_freq)), event_freq.values
)
print(f"Trend slope: {slope:.2f} (r-squared: {r_value**2:.2f})")
```

## Visualization

### Basic Plots
```python
import matplotlib.pyplot as plt

# Event type distribution
event_counts = df['type'].value_counts()
event_counts.plot(kind='bar', figsize=(10, 6))
plt.title('Event Types Distribution')
plt.xlabel('Event Type')
plt.ylabel('Count')
plt.xticks(rotation=45)
plt.tight_layout()
plt.savefig('event_distribution.png')
plt.show()
```

### Time Series Analysis
```python
# Events over time
df['timestamp'] = pd.to_datetime(df['timestamp'])
events_over_time = df.groupby(df['timestamp'].dt.date).size()

plt.figure(figsize=(12, 6))
events_over_time.plot(kind='line', marker='o')
plt.title('Security Events Over Time')
plt.xlabel('Date')
plt.ylabel('Number of Events')
plt.grid(True)
plt.tight_layout()
plt.savefig('events_over_time.png')
plt.show()
```

### Advanced Visualizations
```python
# Heatmap of events by hour and day
import seaborn as sns

hourly_events = df.groupby([df['timestamp'].dt.dayofweek, df['timestamp'].dt.hour]).size()
hourly_events = hourly_events.unstack()

plt.figure(figsize=(12, 8))
sns.heatmap(hourly_events, cmap='YlOrRd', annot=True, fmt='g')
plt.title('Security Events by Day and Hour')
plt.xlabel('Hour of Day')
plt.ylabel('Day of Week')
plt.tight_layout()
plt.savefig('events_heatmap.png')
plt.show()
```

## Custom Analysis Scripts

### Threat Hunting Script
```python
#!/usr/bin/env python3
"""
MLIDS Threat Hunting Script
"""

import pandas as pd
import json
from datetime import datetime, timedelta
import argparse

def load_recent_logs(hours=24, logs_dir='logs'):
    """Load logs from the last N hours, aggregating rotated files in `logs_dir`."""
    cutoff = datetime.now() - timedelta(hours=hours)
    logs = []
    pattern = os.path.join(logs_dir, 'mlids_logs*')
    for fname in sorted([p for p in glob.glob(pattern) if os.path.isfile(p)]):
        with open(fname, 'r', encoding='utf-8') as f:
            for line in f:
                try:
                    entry = json.loads(line.strip())
                except Exception:
                    continue
                try:
                    timestamp = datetime.fromisoformat(entry['timestamp'].replace('Z', '+00:00'))
                except Exception:
                    continue
                if timestamp > cutoff:
                    logs.append(entry)

    return pd.DataFrame(logs)

def hunt_brute_force(df, threshold=5, window_minutes=30):
    """Hunt for brute force attacks"""
    failed_logins = df[df['type'] == 'Failed Login'].copy()
    failed_logins['timestamp'] = pd.to_datetime(failed_logins['timestamp'])

    # Group by IP and time window
    failed_logins['time_window'] = failed_logins['timestamp'].dt.floor(f'{window_minutes}min')

    brute_force = failed_logins.groupby(['details.ip', 'time_window']).size()
    suspicious = brute_force[brute_force >= threshold]

    return suspicious

def hunt_lateral_movement(df):
    """Hunt for potential lateral movement"""
    # Look for successful logins followed by suspicious activity
    successful_logins = df[df['type'] == 'Successful Login']
    suspicious_activity = df[df['type'].isin(['File Access', 'Command Execution'])]

    # Find IPs with both successful login and suspicious activity
    login_ips = set(successful_logins['details'].apply(lambda x: x.get('ip', '')))
    activity_ips = set(suspicious_activity['details'].apply(lambda x: x.get('ip', '')))

    lateral_ips = login_ips.intersection(activity_ips)
    return lateral_ips

def main():
    parser = argparse.ArgumentParser(description='MLIDS Threat Hunting')
    parser.add_argument('--hours', type=int, default=24, help='Hours to look back')
    parser.add_argument('--brute-threshold', type=int, default=5, help='Brute force threshold')
    args = parser.parse_args()

    print(f"Loading logs from last {args.hours} hours...")
    df = load_recent_logs(args.hours)

    if df.empty:
        print("No recent logs found.")
        return

    print(f"Analyzing {len(df)} events...")

    # Brute force detection
    print("\n=== BRUTE FORCE DETECTION ===")
    brute_force = hunt_brute_force(df, args.brute_threshold)
    if not brute_force.empty:
        print("Potential brute force attacks:")
        for (ip, window), count in brute_force.items():
            print(f"  {ip}: {count} failed logins in {window}")
    else:
        print("No brute force attacks detected.")

    # Lateral movement detection
    print("\n=== LATERAL MOVEMENT DETECTION ===")
    lateral_ips = hunt_lateral_movement(df)
    if lateral_ips:
        print("IPs with potential lateral movement:")
        for ip in lateral_ips:
            print(f"  {ip}")
    else:
        print("No lateral movement indicators detected.")

if __name__ == '__main__':
    main()
```

### Compliance Report Generator
```python
#!/usr/bin/env python3
"""
MLIDS Compliance Report Generator
"""

import pandas as pd
import json
from datetime import datetime, timedelta
from typing import Dict, List
import argparse

class ComplianceReporter:
    def __init__(self, logs_dir='logs'):
        # Analyzer reads rotated files from the logs directory
        self.logs_dir = logs_dir
        self.df = self._load_logs()

    def _load_logs(self) -> pd.DataFrame:
        """Aggregate rotated JSON-line logs from the configured logs directory."""
        import glob
        logs = []
        pattern = os.path.join(self.logs_dir, 'mlids_logs*')
        files = sorted([p for p in glob.glob(pattern) if os.path.isfile(p)])
        if not files:
            print(f"No log files found in {self.logs_dir}")
            return pd.DataFrame()

        for fname in files:
            try:
                with open(fname, 'r', encoding='utf-8') as f:
                    for line in f:
                        try:
                            logs.append(json.loads(line.strip()))
                        except Exception:
                            continue
            except Exception:
                continue

        df = pd.DataFrame(logs)
        if not df.empty and 'timestamp' in df.columns:
            df['timestamp'] = pd.to_datetime(df['timestamp'])
        return df

    def generate_report(self, days=30) -> Dict:
        """Generate compliance report"""
        cutoff = datetime.now() - timedelta(days=days)
        recent_logs = self.df[self.df['timestamp'] > cutoff]

        report = {
            'period': f"Last {days} days",
            'total_events': len(recent_logs),
            'event_summary': recent_logs['type'].value_counts().to_dict(),
            'critical_events': self._get_critical_events(recent_logs),
            'compliance_status': self._check_compliance(recent_logs),
            'recommendations': self._generate_recommendations(recent_logs)
        }

        return report

    def _get_critical_events(self, df: pd.DataFrame) -> List[Dict]:
        """Extract critical security events"""
        critical_types = ['Brute Force', 'SQL Injection', 'Command Injection']
        critical = df[df['type'].isin(critical_types)]

        events = []
        for _, row in critical.iterrows():
            events.append({
                'timestamp': row['timestamp'].isoformat(),
                'type': row['type'],
                'details': row['details'],
                'severity': self._calculate_severity(row)
            })

        return events

    def _check_compliance(self, df: pd.DataFrame) -> Dict:
        """Check compliance status"""
        # Example compliance checks
        checks = {
            'failed_login_monitoring': len(df[df['type'] == 'Failed Login']) > 0,
            'intrusion_detection': len(df[df['type'].isin(['SQL Injection', 'XSS'])]) >= 0,
            'file_integrity': len(df[df['type'].isin(['File Modified', 'File Created'])]) >= 0,
            'log_rotation': True,  # Assume log rotation is configured
            'alert_system': True   # Assume alerting is configured
        }

        passed = sum(checks.values())
        total = len(checks)

        return {
            'status': 'PASS' if passed == total else 'WARN' if passed >= total * 0.8 else 'FAIL',
            'passed_checks': passed,
            'total_checks': total,
            'details': checks
        }

    def _calculate_severity(self, event) -> str:
        """Calculate event severity"""
        high_severity = ['Brute Force', 'Command Injection', 'Privilege Escalation']
        medium_severity = ['SQL Injection', 'XSS', 'Path Traversal']

        if event['type'] in high_severity:
            return 'HIGH'
        elif event['type'] in medium_severity:
            return 'MEDIUM'
        else:
            return 'LOW'

    def _generate_recommendations(self, df: pd.DataFrame) -> List[str]:
        """Generate security recommendations"""
        recommendations = []

        # Check for common issues
        failed_logins = len(df[df['type'] == 'Failed Login'])
        if failed_logins > 100:
            recommendations.append("High number of failed logins detected. Consider implementing account lockout policies.")

        sql_injections = len(df[df['type'] == 'SQL Injection'])
        if sql_injections > 0:
            recommendations.append("SQL injection attempts detected. Ensure input validation and parameterized queries.")

        if len(df[df['type'] == 'Brute Force']) > 0:
            recommendations.append("Brute force attacks detected. Implement rate limiting and CAPTCHA.")

        # Check monitoring coverage
        event_types = set(df['type'].unique())
        if 'File Modified' not in event_types:
            recommendations.append("Consider enabling file integrity monitoring for critical system files.")

        if 'Port Scan' not in event_types:
            recommendations.append("Consider enabling network monitoring for comprehensive threat detection.")

        return recommendations

    def export_report(self, report: Dict, format='json'):
        """Export report in specified format"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

        if format == 'json':
            filename = f'compliance_report_{timestamp}.json'
            with open(filename, 'w') as f:
                json.dump(report, f, indent=2, default=str)

        elif format == 'csv':
            filename = f'compliance_report_{timestamp}.csv'
            # Convert nested dicts to strings for CSV
            flat_report = {
                'period': report['period'],
                'total_events': report['total_events'],
                'compliance_status': report['compliance_status']['status'],
                'passed_checks': report['compliance_status']['passed_checks'],
                'total_checks': report['compliance_status']['total_checks']
            }
            pd.DataFrame([flat_report]).to_csv(filename, index=False)

        print(f"Report exported to {filename}")
        return filename

def main():
    parser = argparse.ArgumentParser(description='MLIDS Compliance Reporter')
    parser.add_argument('--days', type=int, default=30, help='Report period in days')
    parser.add_argument('--format', choices=['json', 'csv'], default='json', help='Output format')
    args = parser.parse_args()

    # Use the default logs directory unless otherwise specified via config
    reporter = ComplianceReporter(logs_dir='logs')
    report = reporter.generate_report(args.days)

    print("=== MLIDS COMPLIANCE REPORT ===")
    print(f"Period: {report['period']}")
    print(f"Total Events: {report['total_events']}")
    print(f"Compliance Status: {report['compliance_status']['status']}")
    print(f"Checks Passed: {report['compliance_status']['passed_checks']}/{report['compliance_status']['total_checks']}")

    if report['critical_events']:
        print(f"\nCritical Events: {len(report['critical_events'])}")
        for event in report['critical_events'][:5]:  # Show first 5
            print(f"  {event['timestamp']}: {event['type']} ({event['severity']})")

    if report['recommendations']:
        print(f"\nRecommendations: {len(report['recommendations'])}")
        for rec in report['recommendations']:
            print(f"  • {rec}")

    reporter.export_report(report, args.format)

if __name__ == '__main__':
    main()
```

## Integration with External Tools

### Splunk Integration
```bash
# Configure MLIDS to send to Splunk
python index.py start --tcp-sink --tcp-host "splunk.example.local" --tcp-port 514

# Splunk search queries
# Search for failed logins
index=mlids type="Failed Login"

# Search for SQL injection
index=mlids type="SQL Injection"

# Dashboard panels
| timechart count by type
| stats count by details.ip | sort -count | head 10
```

### ELK Stack Integration
```bash
# Send to Logstash
python index.py start --tcp-sink --tcp-host "logstash.example.local" --tcp-port 5044

# Elasticsearch queries
GET /mlids-*/_search
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

### Grafana Dashboards
```bash
# Send metrics to Graphite
python index.py start --tcp-sink --tcp-host "graphite.example.local" --tcp-port 2003

# Grafana query examples
# Event rate over time
rate(mlids_events_total[5m])

# Top source IPs
topk(10, sum(rate(mlids_events_by_ip[5m])) by (ip))
```

This analysis system provides comprehensive security event investigation, automated reporting, and integration capabilities for enterprise security operations.