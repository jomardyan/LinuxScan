#!/bin/bash

# Minimal test version to debug the issue
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${SCRIPT_DIR}/venv"
LOG_FILE="${SCRIPT_DIR}/setup.log"
PYTHON_MIN_VERSION="3.7"

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

log() { echo -e "${GREEN}[INFO]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
debug() { echo -e "${BLUE}[DEBUG]${NC} $1"; }

# Simple Python version check
check_python_version() {
    debug "Checking Python version..."
    
    if command -v python3 &> /dev/null; then
        local python_version=$(python3 --version 2>&1 | awk '{print $2}')
        debug "Found Python: python3 version $python_version"
        
        local major=$(echo "$python_version" | cut -d. -f1)
        local minor=$(echo "$python_version" | cut -d. -f2)
        
        if [[ $major -eq 3 && $minor -ge 7 ]]; then
            success "Python version check passed: $python_version"
            export PYTHON_CMD="python3"
            return 0
        else
            error "Python 3.7+ required (found $python_version)"
            return 1
        fi
    else
        error "Python 3 not found"
        return 1
    fi
}

echo "Testing Python version check..."
if check_python_version; then
    echo "Python check: OK"
else
    echo "Python check: FAILED"
fi
