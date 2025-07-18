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