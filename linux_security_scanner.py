#!/usr/bin/env python3
"""
LinuxScan - Interactive Security Scanner
Legacy entry point for backward compatibility and interactive mode
"""

import sys
import os
from pathlib import Path

# Add the project root to Python path for imports
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

def main():
    """Main entry point for interactive LinuxScan application"""
    try:
        from linuxscan.enhanced_cli import main as cli_main
        from linuxscan.gui import LinuxScanGUI
        
        # If no arguments provided, launch GUI
        if len(sys.argv) == 1:
            print("🚀 Launching LinuxScan Interactive Interface...")
            gui = LinuxScanGUI()
            gui.run()
        else:
            # Use CLI with arguments
            cli_main()
    except ImportError as e:
        print(f"Error importing LinuxScan modules: {e}")
        print("Please ensure all dependencies are installed:")
        print("  pip install -r requirements.txt")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nApplication interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()