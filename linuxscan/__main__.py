#!/usr/bin/env python3
"""
LinuxScan Package Entry Point
Allows execution via 'python -m linuxscan'
"""

import sys
from .enhanced_cli import main

if __name__ == "__main__":
    main()