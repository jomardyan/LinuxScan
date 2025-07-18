#!/bin/bash

echo "Linux Security Scanner Setup"
echo "==========================="

# Check Python version
python_version=$(python3 --version 2>&1 | awk '{print $2}')
required_version="3.7"

if [ "$(printf '%s\n' "$required_version" "$python_version" | sort -V | head -n1)" != "$required_version" ]; then 
    echo "Error: Python $required_version or higher is required"
    exit 1
fi

echo "✓ Python version check passed"

# Install requirements
echo "Installing required packages..."
pip3 install -r requirements.txt

# Make scanner executable
chmod +x linux_security_scanner.py

# Check if nmap is installed
if ! command -v nmap &> /dev/null; then
    echo ""
    echo "⚠ Warning: nmap is not installed"
    echo "For full functionality, please install nmap:"
    echo "  Ubuntu/Debian: sudo apt-get install nmap"
    echo "  CentOS/RHEL: sudo yum install nmap"
    echo "  macOS: brew install nmap"
fi

echo ""
echo "✓ Setup complete!"
echo ""
echo "To run the scanner:"
echo "  sudo python3 linux_security_scanner.py"
echo ""
echo "Note: Root privileges are recommended for accurate scanning"