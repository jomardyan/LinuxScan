#!/usr/bin/env python3
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Author: Hayk Jomardyan
#
"""
Setup configuration for Linux Security Scanner
"""

import sys
from setuptools import setup, find_packages
from pathlib import Path

# If no arguments provided, launch GUI setup
if len(sys.argv) == 1:
    try:
        from rich.console import Console
        console = Console()
        console.print("🚀 Launching LinuxScan Interactive Setup...")
        # Add the project root to Python path for imports
        project_root = Path(__file__).parent
        sys.path.insert(0, str(project_root))
        from linuxscan.gui import LinuxScanGUI
        gui = LinuxScanGUI()
        gui.run()
        sys.exit(0)
    except ImportError as e:
        try:
            from rich.console import Console
            console = Console()
            console.print(f"[red]Error loading GUI: {e}[/red]")
            console.print("[yellow]GUI mode requires all dependencies to be installed[/yellow]")
            console.print("[cyan]Install dependencies first:[/cyan]")
            console.print("  pip install -r requirements.txt")
            console.print("\n[cyan]Or run setup with a command:[/cyan]")
            console.print("  python setup.py install")
            console.print("  python setup.py develop")
            console.print("  python setup.py --help")
        except Exception:
            print(f"Error loading GUI: {e}")
            print("GUI mode requires all dependencies to be installed")
            print("Install dependencies first:")
            print("  pip install -r requirements.txt")
            print("\nOr run setup with a command:")
            print("  python setup.py install")
            print("  python setup.py develop")
            print("  python setup.py --help")
        sys.exit(1)
    except Exception as e:
        try:
            from rich.console import Console
            console = Console()
            console.print(f"[red]Error launching GUI: {e}[/red]")
            console.print("[yellow]Falling back to standard setup usage...[/yellow]")
            console.print("[cyan]Available commands:[/cyan]")
            console.print("  python setup.py install")
            console.print("  python setup.py develop")
            console.print("  python setup.py --help")
        except Exception:
            print(f"Error launching GUI: {e}")
            print("Falling back to standard setup usage...")
            print("Available commands:")
            print("  python setup.py install")
            print("  python setup.py develop")
            print("  python setup.py --help")
        sys.exit(1)

# Read the contents of README file
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text()

setup(
    name="linuxscan",
    version="1.0.0",
    author="Security Scanner Team",
    author_email="contact@linuxscan.dev",
    description="High-performance security scanning tool for remote Linux servers",
    long_description=long_description,
    long_description_content_type="text/markdown",
    license="Apache-2.0",
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