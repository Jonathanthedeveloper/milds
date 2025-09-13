#!/usr/bin/env python
"""
MLIDS - Multi-Level Intrusion Detection System
Main entry point for the CLI application
"""

import sys
import os

# Add the parent directory to the path so we can import from the project root
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import the main CLI function from index.py
try:
    from index import main
except ImportError:
    print("Error: Could not import 'main' from 'index.py'. Please ensure 'index.py' is in the same directory.")
    sys.exit(1)

if __name__ == '__main__':
    main()