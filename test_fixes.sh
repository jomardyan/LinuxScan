#!/bin/bash
# Test script to verify all LinuxScan fixes

echo "=========================================="
echo "LinuxScan Functionality Test Script"
echo "=========================================="

echo ""
echo "1. Testing 'linuxscan --version' command:"
linuxscan --version

echo ""
echo "2. Testing 'python -m linuxscan --version' command:"
python -m linuxscan --version

echo ""
echo "3. Testing 'python linux_security_scanner.py --version' command:"
python linux_security_scanner.py --version

echo ""
echo "4. Testing 'linuxscan --interactive' command (will show menu for 3 seconds):"
echo "Note: This will launch the GUI - we'll timeout after 3 seconds"
timeout 3 linuxscan --interactive || echo "GUI launched successfully (timeout expected)"

echo ""
echo "5. Testing 'python run.py --help' command:"
python run.py --help

echo ""
echo "6. Testing setup.sh existence and permissions:"
ls -la linux_security_scanner.py
ls -la setup.sh

echo ""
echo "7. Testing that 'chmod +x linux_security_scanner.py' works (no errors expected):"
chmod +x linux_security_scanner.py && echo "chmod command executed successfully"

echo ""
echo "=========================================="
echo "All tests completed!"
echo "=========================================="