#!/usr/bin/env python3
"""
Test runner for MLIDS (Multi-Level Intrusion Detection System)

This script provides an easy way to run the test suite with proper setup.
"""

import sys
import subprocess
import os
from pathlib import Path

def run_tests():
    """Run the test suite."""
    print("Running MLIDS test suite...")

    # Ensure we're in the project root
    project_root = Path(__file__).parent
    os.chdir(project_root)

    # Check if pytest is available
    try:
        import pytest
    except ImportError:
        print("pytest not found. Installing...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pytest"])

    # Run tests
    cmd = [sys.executable, "-m", "pytest"]
    if len(sys.argv) > 1:
        cmd.extend(sys.argv[1:])

    try:
        result = subprocess.run(cmd, check=False)
        return result.returncode
    except KeyboardInterrupt:
        print("\nTest run interrupted.")
        return 1

def run_specific_test(test_name):
    """Run a specific test file or test function."""
    print(f"Running specific test: {test_name}")

    project_root = Path(__file__).parent
    os.chdir(project_root)

    cmd = [sys.executable, "-m", "pytest", f"tests/{test_name}"]
    if len(sys.argv) > 2:
        cmd.extend(sys.argv[2:])

    try:
        result = subprocess.run(cmd, check=False)
        return result.returncode
    except KeyboardInterrupt:
        print("\nTest run interrupted.")
        return 1

def show_help():
    """Show help information."""
    print("""
MLIDS Test Runner

Usage:
    python run_tests.py                    # Run all tests
    python run_tests.py <test_file>        # Run specific test file
    python run_tests.py --help             # Show this help

Examples:
    python run_tests.py test_config.py     # Run config tests
    python run_tests.py test_app.py -v     # Run app tests with verbose output
    python run_tests.py -k "test_sql"      # Run tests matching "test_sql"

Available test files:
    test_config.py    - Configuration loading and validation
    test_logger.py    - Logger setup and functionality
    test_events.py    - Event dispatching and actions
    test_host.py      - File monitoring
    test_net.py       - Network monitoring
    test_app.py       - App log monitoring

Requirements:
    pytest (will be installed automatically if missing)
    """)

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] in ["--help", "-h", "help"]:
        show_help()
        sys.exit(0)

    if len(sys.argv) > 1 and not sys.argv[1].startswith("-"):
        # Run specific test
        test_name = sys.argv[1]
        if not test_name.endswith(".py"):
            test_name += ".py"
        sys.exit(run_specific_test(test_name))
    else:
        # Run all tests
        sys.exit(run_tests())