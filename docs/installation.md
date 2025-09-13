# MLIDS Installation Guide

## System Requirements

### Minimum Requirements
- Python 3.8 or higher
- 2GB RAM
- 1GB free disk space
- Windows 10+ / Linux / macOS

### Recommended Requirements
- Python 3.10 or higher
- 4GB RAM
- 2GB free disk space
- Modern multi-core CPU

## Operating System Support

### Windows
- Windows 10, 11
- Windows Server 2019, 2022
- Requires Npcap for network monitoring

### Linux
- Ubuntu 18.04+
- CentOS/RHEL 7+
- Debian 9+
- Most modern distributions

### macOS
- macOS 10.15+
- Requires Xcode Command Line Tools

## Installation Steps

### 1. Clone or Download
```bash
git clone https://github.com/ORG_OWNER/mlids.git
cd mlids
```

### 2. Create Virtual Environment
```bash
# Windows
python -m venv .venv
.\.venv\Scripts\activate

# Linux/macOS
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Install Optional Dependencies

#### For Network Monitoring
```bash
# Windows - Install Npcap from https://npcap.com/
# Linux - Install libpcap development headers
sudo apt-get install libpcap-dev  # Ubuntu/Debian
sudo yum install libpcap-devel    # CentOS/RHEL

pip install scapy
```

#### For Enhanced Logging
```bash
pip install rich pyyaml
```

#### For Data Analysis and Visualization
```bash
pip install pandas numpy matplotlib
```

#### For Web Dashboard
```bash
pip install websockets
```

## Platform-Specific Setup

### Windows Setup
1. Install Python 3.10+ from python.org
2. Install Npcap for network monitoring
3. Run PowerShell as Administrator for network features
4. Add Python to PATH during installation

### Linux Setup
1. Install Python 3.10+ using package manager
2. Install development headers for optional features
3. Configure firewall rules if needed
4. Set up log file permissions

### macOS Setup
1. Install Python 3.10+ using Homebrew or python.org
2. Install Xcode Command Line Tools
3. Configure firewall permissions
4. Set up log monitoring permissions

## Post-Installation Verification

### Verify Core Installation
```bash
python -c "import mlids; print('MLIDS core installed successfully')"
```

### Verify Optional Components
```bash
# Network monitoring
python -c "import scapy; print('Network monitoring available')"

# Enhanced logging
python -c "import rich; print('Rich logging available')"

# Data analysis
python -c "import pandas, numpy; print('Data analysis available')"

# Web features
python -c "import websockets; print('Web features available')"
```

### Test Basic Functionality
```bash
# Create test log file
echo "Test log entry" > test.log

# Test basic monitoring
python index.py start --dir "." --app-log "test.log"

# Should see monitoring start messages
```

## Configuration

### Basic Configuration
Create a `config.yaml` file in the project root:

```yaml
# Note: supply the main logfile to the logger at runtime or via the CLI.
logs_dir: "logs"
monitor_dir: "/var/log"
app_log_file: "/var/log/auth.log"
enable_network: false
console_color: true
```

### Advanced Configuration
See [Configuration Guide](configuration.md) for detailed options.

## Troubleshooting Installation

### Common Issues

#### Import Errors
```
ModuleNotFoundError: No module named 'scapy'
```
**Solution**: Install optional dependencies
```bash
pip install scapy
```

#### Permission Errors
```
PermissionError: [Errno 13] Permission denied
```
**Solution**: Run with appropriate permissions or configure file access

#### Network Interface Issues
```
ScapyPermissionError: Cannot access network interfaces
```
**Solution**:
- Windows: Install Npcap and run as Administrator
- Linux: Install libpcap-dev and run with sudo if needed

### Getting Help
- Check the [Troubleshooting Guide](troubleshooting.md)
- Review the [Examples](examples.md)
- Check GitHub issues for similar problems

## Next Steps
1. Review the [Getting Started Guide](getting-started.md)
2. Configure your monitoring setup
3. Test with sample data
4. Set up automated monitoring