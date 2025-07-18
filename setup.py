#!/usr/bin/env python3
"""
Setup configuration for Linux Security Scanner
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read the contents of README file
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text()

# Read requirements
requirements = []
with open('requirements.txt', 'r') as f:
    requirements = [line.strip() for line in f if line.strip() and not line.startswith('#')]

setup(
    name="linuxscan",
    version="1.0.0",
    author="Security Scanner Team",
    author_email="contact@linuxscan.dev",
    description="High-performance security scanning tool for remote Linux servers",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/jomardyan/LinuxScan",
    project_urls={
        "Bug Tracker": "https://github.com/jomardyan/LinuxScan/issues",
        "Documentation": "https://github.com/jomardyan/LinuxScan#readme",
        "Source Code": "https://github.com/jomardyan/LinuxScan",
    },
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Information Technology",
        "Topic :: System :: Systems Administration",
        "Topic :: Security",
        "Topic :: System :: Networking :: Monitoring",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
        "Environment :: Console",
    ],
    python_requires=">=3.7",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=6.0",
            "pytest-asyncio>=0.18.0",
            "pytest-cov>=3.0.0",
            "black>=22.0.0",
            "flake8>=4.0.0",
            "mypy>=0.950",
        ],
    },
    entry_points={
        "console_scripts": [
            "linuxscan=linuxscan.enhanced_cli:cli_main",
            "linux-security-scanner=linuxscan.enhanced_cli:cli_main",
        ],
    },
    include_package_data=True,
    package_data={
        "linuxscan": ["*.md", "*.txt"],
    },
    keywords=[
        "security", "scanner", "linux", "network", "vulnerability", 
        "assessment", "pentesting", "security-audit", "port-scanner",
        "ssl", "ssh", "security-testing"
    ],
    zip_safe=False,
)