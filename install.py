#!/usr/bin/env python
"""
MLIDS Installation Script
Helps users install MLIDS in different modes
"""

import subprocess
import sys
import os
from pathlib import Path

def run_command(cmd, description):
    """Run a command and return success status"""
    print(f"\n{description}...")
    try:
        result = subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True)
        print("✓ Success!")
        return True
    except subprocess.CalledProcessError as e:
        print(f"✗ Failed: {e}")
        print(f"Error output: {e.stderr}")
        return False

def main():
    print("MLIDS - Multi-Level Intrusion Detection System")
    print("=" * 50)

    if len(sys.argv) > 1:
        mode = sys.argv[1].lower()
    else:
        print("\nInstallation modes:")
        print("1. development - Install in development mode (recommended for development)")
        print("2. production  - Install for production use")
        print("3. user        - Install for current user only")
        print("\nUsage: python install.py [mode]")

        mode = input("\nChoose installation mode (development/production/user): ").lower().strip()

    # Check if we're in the right directory
    if not Path('setup.py').exists() and not Path('pyproject.toml').exists():
        print("Error: Please run this script from the MLIDS project root directory")
        sys.exit(1)

    success = False

    if mode in ['dev', 'development']:
        print("\nInstalling MLIDS in development mode...")
        success = run_command(
            f"{sys.executable} -m pip install -e .",
            "Installing in development mode"
        )

    elif mode in ['prod', 'production']:
        print("\nInstalling MLIDS for production...")
        success = run_command(
            f"{sys.executable} -m pip install .",
            "Installing for production"
        )

    elif mode in ['user']:
        print("\nInstalling MLIDS for current user...")
        success = run_command(
            f"{sys.executable} -m pip install --user .",
            "Installing for current user"
        )

    else:
        print(f"Error: Unknown mode '{mode}'")
        print("Valid modes: development, production, user")
        sys.exit(1)

    if success:
        print("\n" + "=" * 50)
        print("✓ MLIDS installed successfully!")
        print("\nYou can now use MLIDS by running:")
        print("  mlids --help")
        print("  python -m milds --help")
        print("\nExample usage:")
        print("  mlids start --dir /var/log")
        print("  mlids analyze")
        print("  mlids config --key port_scan_threshold --value 15")

        # Test the installation
        print("\nTesting installation...")
        test_success = run_command("mlids --help", "Testing MLIDS command")
        if not test_success:
            print("\nNote: If 'mlids' command is not found, you may need to:")
            print("1. Restart your terminal/command prompt")
            print("2. Add Python scripts directory to your PATH")
            print("3. Or use 'python -m milds' instead")

    else:
        print("\n✗ Installation failed!")
        print("Please check the error messages above and try again.")
        sys.exit(1)

if __name__ == '__main__':
    main()