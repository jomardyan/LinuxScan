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
LinuxScan - Main Entry Point
A comprehensive security scanning tool for remote Linux servers

This is the main entry point for the LinuxScan application.
"""

import sys
import os
import subprocess
import importlib.util
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.text import Text

console = Console()

# Add the project root to Python path for imports
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

def check_system_dependencies():
    """Check for required system dependencies"""
    system_deps = {
        'nmap': 'nmap',
        'netstat': 'net-tools',
        'ss': 'iproute2',
        'dig': 'dnsutils',
        'python3': 'python3',
        'pip3': 'python3-pip'
    }
    
    missing_deps = []
    for command, package in system_deps.items():
        if not subprocess.run(['which', command], capture_output=True, text=True).returncode == 0:
            missing_deps.append((command, package))
    
    return missing_deps

def check_python_dependencies():
    """Check for required Python dependencies"""
    required_modules = [
        'rich', 'click', 'nmap', 'paramiko', 'cryptography',
        'aiohttp', 'psutil', 'bs4', 'scapy', 'netaddr',
        'dns', 'yaml', 'yara', 'requests', 'netifaces'
    ]
    
    missing_modules = []
    for module in required_modules:
        if importlib.util.find_spec(module) is None:
            missing_modules.append(module)
    
    return missing_modules

def display_dependency_status():
    """Display dependency status in a formatted table"""
    console.print("\n🔍 Checking System Dependencies...")
    
    # Check system dependencies
    missing_system = check_system_dependencies()
    
    # Check Python dependencies
    missing_python = check_python_dependencies()
    
    # Display results
    if missing_system or missing_python:
        console.print("\n⚠️  Missing Dependencies Found", style="bold red")
        
        if missing_system:
            console.print("\n📦 Missing System Dependencies:")
            sys_table = Table(show_header=True, header_style="bold magenta")
            sys_table.add_column("Command", style="dim")
            sys_table.add_column("Package", style="dim")
            
            for command, package in missing_system:
                sys_table.add_row(command, package)
            
            console.print(sys_table)
            console.print("\nInstall system dependencies with:")
            console.print("  sudo apt-get update")
            console.print("  sudo apt-get install " + " ".join([pkg for _, pkg in missing_system]))
        
        if missing_python:
            console.print("\n🐍 Missing Python Dependencies:")
            py_table = Table(show_header=True, header_style="bold magenta")
            py_table.add_column("Module", style="dim")
            
            for module in missing_python:
                py_table.add_row(module)
            
            console.print(py_table)
            console.print("\nInstall Python dependencies with:")
            console.print("  pip install -r requirements.txt")
        
        console.print("\n🛠️  Setup Options:")
        console.print("1. Run automatic setup: python setup.py")
        console.print("2. Install dependencies manually (see above)")
        console.print("3. View installation guide: cat INSTALL.md")
        
        return False
    else:
        console.print("✅ All dependencies are installed!", style="bold green")
        return True

def main():
    """Main entry point for LinuxScan application"""
    try:
        # Check dependencies before proceeding
        if not display_dependency_status():
            console.print("\n❓ Would you like to run the setup process now? [y/N]", style="bold yellow")
            try:
                response = input().strip().lower()
                if response in ['y', 'yes']:
                    console.print("\n🚀 Starting setup process...")
                    subprocess.run([sys.executable, 'setup.py'], cwd=project_root)
                    return
                else:
                    console.print("Setup skipped. Please install dependencies manually.")
                    sys.exit(1)
            except KeyboardInterrupt:
                console.print("\nSetup cancelled by user")
                sys.exit(0)
        
        # Try to import LinuxScan modules
        from linuxscan.enhanced_cli import main as cli_main
        
        # If no arguments provided, launch GUI
        if len(sys.argv) == 1:
            console.print("🚀 Launching LinuxScan Interactive Interface...")
            try:
                from linuxscan.gui import LinuxScanGUI
                gui = LinuxScanGUI()
                gui.run()
                return
            except ImportError as e:
                console.print(f"Error loading GUI: {e}")
                console.print("GUI mode requires all dependencies to be installed")
                console.print("Falling back to CLI mode...")
                console.print("\nFor CLI usage, run: python run.py --help")
                sys.exit(1)
        else:
            # Call the enhanced CLI with command line arguments
            cli_main()
    except ImportError as e:
        console.print(f"Error importing LinuxScan modules: {e}", style="bold red")
        console.print("Please ensure all dependencies are installed:")
        console.print("  pip install -r requirements.txt")
        console.print("Or run setup: python setup.py")
        sys.exit(1)
    except KeyboardInterrupt:
        console.print("\nScan interrupted by user")
        sys.exit(0)
    except Exception as e:
        console.print(f"Unexpected error: {e}", style="bold red")
        sys.exit(1)

if __name__ == "__main__":
    main()