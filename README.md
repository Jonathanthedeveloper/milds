# MLIDS - Multi-Level Intrusion Detection System

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://python.org)
[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)]()

MLIDS is a comprehensive, lightweight intrusion detection system that monitors network traffic, host activities, and application logs for security threats. It provides real-time detection of port scans, brute force attacks, SQL injection, XSS, file integrity violations, and statistical anomalies.

## 🚀 Quick Start

### Basic Installation

#### Option 1: Install as Package (Recommended)

```bash
# Install in development mode (recommended)
pip install -e .

# Or install for production use
pip install .

# Or use the installation script
python install.py development
```

After installation, use MLIDS from anywhere:

```bash
mlids --help
mlids start --dir /var/log
mlids analyze
```

#### Option 2: Run from Source

1. **Clone and setup environment:**
```bash
git clone <repository-url>
cd milds
python -m venv .venv
```

2. **Activate virtual environment:**
```bash
# Windows PowerShell
.\.venv\Scripts\activate

# Linux/macOS
source .venv/bin/activate
```

3. **Install dependencies:**
```bash
pip install -r requirements.txt
```

4. **Start monitoring:**
```bash
# Basic monitoring (host + application)
python index.py start

# With network monitoring
python index.py start --interface wlan0

# Custom configuration
python index.py start --config config.yaml
```

## 📋 Table of Contents

- [Features](#-features)
- [Architecture](#-architecture)
- [Installation](#-installation)
- [Configuration](#-configuration)
- [Usage](#-usage)
- [Analysis & Reporting](#-analysis--reporting)
- [API Reference](#-api-reference)
- [Examples](#-examples)
- [Troubleshooting](#-troubleshooting)
- [Contributing](#-contributing)
- [License](#-license)

## ✨ Features

### 🔍 Multi-Layer Detection
- **Network Layer**: Packet analysis, port scanning, DoS detection
- **Host Layer**: File integrity monitoring, system event tracking
- **Application Layer**: Log analysis, pattern matching, anomaly detection

### 📊 Advanced Analytics
- Real-time statistical analysis using MAD (Median Absolute Deviation)
- Machine learning-based anomaly detection
- Comprehensive reporting and visualization
- Custom threat hunting queries

### 🔗 Flexible Integration
- TCP/WebSocket event sinks for real-time streaming
- SIEM integration (Splunk, ELK Stack)
- RESTful API for programmatic access
- Custom alerting and notification systems

### 🛠️ Enterprise Ready
- Configurable detection thresholds
- Log rotation and retention policies
- Cross-platform compatibility (Windows, Linux, macOS)
- Docker container support
- High-performance architecture

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Network       │    │     Host        │    │  Application    │
│   Monitor       │    │     Monitor     │    │    Monitor      │
│                 │    │                 │    │                 │
│ • Packet Analysis│    │ • File Integrity │    │ • Log Parsing   │
│ • Port Scanning │    │ • System Events │    │ • Pattern Match │
│ • DoS Detection │    │ • Change Detect │    │ • Attack Detect │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
                    ┌─────────────────┐
                    │   Event         │
                    │   Dispatcher    │
                    │                 │
                    │ • Correlation   │
                    │ • Filtering     │
                    │ • Routing       │
                    └─────────────────┘
                                 │
                    ┌─────────────────┐
                    │   Analysis      │
                    │   Engine        │
                    │                 │
                    │ • Statistics    │
                    │ • ML Models     │
                    │ • Reporting     │
                    └─────────────────┘
```

## Detailed Documentation

### [Installation Guide](docs/installation.md)
- System requirements and dependencies
- Platform-specific installation instructions
- Virtual environment setup
- Docker deployment
- Troubleshooting common installation issues

### [Configuration Guide](docs/configuration.md)
- Configuration file format (YAML)
- Detection thresholds and parameters
- Monitoring settings
- Integration configuration
- Advanced options and customization

### [Getting Started](docs/getting-started.md)
- Basic usage examples
- First monitoring session
- Understanding MLIDS output
- Common workflows
- Best practices for initial setup

### [🔍 Monitoring Guide](docs/monitoring.md)
- Network monitoring capabilities
- Host monitoring features
- Application log monitoring
- Real-time alerting
- Performance optimization

### [Analysis & Reporting](docs/analysis.md)
- Log analysis commands
- Statistical analysis with Pandas
- Visualization and reporting
- Custom analysis scripts
- Integration with external tools

### [API Reference](docs/api.md)
- Command-line interface
- Configuration API
- Event data structures
- TCP/WebSocket protocols
- Python API for integration

### [💡 Examples & Use Cases](docs/examples.md)
- Real-world deployment scenarios
- Custom detection rules
- Integration examples
- Performance optimization
- Advanced configuration patterns

### [Troubleshooting](docs/troubleshooting.md)
- Common issues and solutions
- Debug logging and diagnostics
- Performance tuning
- Integration problems
- Getting help and support

## Use Cases

### Web Application Security
```bash
# Monitor web server logs for attacks
python index.py start --app-log /var/log/apache2/access.log
```

### Network Security Monitoring
```bash
# Monitor network traffic for threats
python index.py start --interface eth0 --enable-net
```

### Database Security
```bash
# Monitor database access patterns
python index.py start --app-log /var/log/mysql/mysql.log
```

### IoT Device Security
```bash
# Monitor IoT network traffic
python index.py start --interface wlan0 --config iot_config.yaml
```

## Sample Output

```
INFO: MLIDS v1.0.0 starting...
INFO: Network monitoring enabled on interface: wlan0
INFO: Host monitoring enabled for directory: /var/log
INFO: Application monitoring enabled for file: /var/log/auth.log
INFO: Event dispatcher initialized with TCP sink
INFO: MLIDS is running. Press Ctrl+C to stop.

[2025-01-13 10:30:45] INFO: Port scan detected from 192.168.1.100 (15 ports)
[2025-01-13 10:31:12] WARNING: Failed login attempt for user 'admin' from 192.168.1.100
[2025-01-13 10:32:01] CRITICAL: SQL injection attempt detected in URL parameter
[2025-01-13 10:32:15] INFO: File integrity violation: /etc/passwd modified
```

## System Requirements

- **Python**: 3.8 or higher
- **Memory**: 512MB minimum, 2GB recommended
- **Disk**: 100MB for installation, variable for logs
- **Network**: Packet capture permissions (root/admin on Linux/Windows)
- **Dependencies**: See [Installation Guide](docs/installation.md)

## Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

- [Documentation](docs/)
- [Issue Tracker](https://github.com/ORG_OWNER/mlids/issues)
- [Discussions](https://github.com/ORG_OWNER/mlids/discussions)
- [Mailing List](mailto:mlids-users@googlegroups.com)

## Version History

### v1.0.0 (Current)
- Multi-layer intrusion detection
- Real-time event correlation
- Statistical anomaly detection
- TCP/WebSocket event sinks
- Comprehensive logging and reporting
- Cross-platform compatibility

### Future Releases
- [ ] Machine learning integration
- [ ] Cloud deployment support
- [ ] Advanced threat intelligence
- [ ] Distributed monitoring
- [ ] REST API enhancements

---

**MLIDS** - Keeping your systems secure, one event at a time.
