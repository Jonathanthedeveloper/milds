#!/usr/bin/env python
"""
Test script to verify MLIDS package installation
"""

import sys
import subprocess

def _check_import(module_name, description):
    """Test if a module can be imported"""
    try:
        __import__(module_name)
        print(f"✓ {description}: Available")
        return True
    except ImportError:
        print(f"✗ {description}: Not available")
        return False

def _check_command(command, description):
    """Test if a command can be executed"""
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            print(f"✓ {description}: Working")
            return True
        else:
            print(f"✗ {description}: Failed (exit code {result.returncode})")
            return False
    except (subprocess.TimeoutExpired, FileNotFoundError):
        print(f"✗ {description}: Not available")
        return False

def main():
    print("MLIDS Package Verification Test")
    print("=" * 40)

    # Test core Python imports
    print("\nTesting core dependencies:")
    core_deps = [
        ('milds', 'MLIDS package'),
        ('milds.config', 'Configuration module'),
        ('milds.logger', 'Logger module'),
        ('milds.host', 'Host monitor module'),
        ('milds.net', 'Network monitor module'),
        ('milds.app', 'Application monitor module'),
        ('milds.events', 'Events module'),
    ]

    core_ok = True
    for module, desc in core_deps:
        if not _check_import(module, desc):
            core_ok = False

    # Test optional dependencies
    print("\nTesting optional dependencies:")
    optional_deps = [
        ('scapy', 'Network packet analysis'),
        ('watchdog', 'File system monitoring'),
        ('pandas', 'Data analysis'),
        ('numpy', 'Numerical computing'),
        ('tailer', 'Log file monitoring'),
        ('matplotlib', 'Plotting'),
        ('websockets', 'WebSocket support'),
        ('pyotp', 'MFA support'),
    ]

    optional_ok = True
    for module, desc in optional_deps:
        _check_import(module, desc)  # Don't fail on optional deps

    # Test CLI commands
    print("\nTesting CLI commands:")
    cli_tests = [
        (['python', '-m', 'milds', '--help'], 'Python module execution'),
        (['mlids', '--help'], 'Direct command execution'),
    ]

    cli_ok = True
    for cmd, desc in cli_tests:
        if not _check_command(cmd, desc):
            cli_ok = False

    # Summary
    print("\n" + "=" * 40)
    print("Test Summary:")

    if core_ok and cli_ok:
        print("✓ MLIDS is properly installed and ready to use!")
        print("\nYou can now run:")
        print("  mlids start --dir /path/to/monitor")
        print("  mlids analyze")
        print("  python -m milds --help")
    else:
        print("✗ Some issues were found. Please check the output above.")

        if not core_ok:
            print("\n- Core dependencies are missing. Try: pip install -e .")
        if not cli_ok:
            print("\n- CLI commands not working. Try restarting your terminal")
            print("  or use: python -m milds [command]")

    return 0 if (core_ok and cli_ok) else 1

if __name__ == '__main__':
    sys.exit(main())