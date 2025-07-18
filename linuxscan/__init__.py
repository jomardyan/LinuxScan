"""
Linux Security Scanner Package
A high-performance security scanning tool for remote Linux servers
"""

__version__ = "1.0.0"
__author__ = "Security Scanner Team"
__email__ = "contact@linuxscan.dev"
__description__ = "High-performance security scanning tool for remote Linux servers"

from .scanner import SecurityScanner

__all__ = ['SecurityScanner']