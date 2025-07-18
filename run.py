#!/usr/bin/env python3
"""
LinuxScan - Main Entry Point
A comprehensive security scanning tool for remote Linux servers

This is the main entry point for the LinuxScan application.
"""

import sys
import os
from pathlib import Path
from rich.console import Console

console = Console()

# Add the project root to Python path for imports
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

def main():
    """Main entry point for LinuxScan application"""
    try:
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
        print(f"Error importing LinuxScan modules: {e}")
        print("Please ensure all dependencies are installed:")
        print("  pip install -r requirements.txt")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()