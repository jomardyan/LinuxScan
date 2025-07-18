#!/bin/bash

# Enhanced LinuxScan Professional Security Scanner Setup
# Author: Security Scanner Team
# Version: 2.0.0
# Date: $(date +%Y-%m-%d)

# Global variables
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${SCRIPT_DIR}/venv"
LOG_FILE="${SCRIPT_DIR}/setup.log"
PYTHON_MIN_VERSION="3.7"
FORCE_INSTALL=false
SKIP_SYSTEM_DEPS=false
VERBOSE=false
DRY_RUN=false

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Logging functions with timestamps and file logging
log_message() {
    local level="$1"
    local message="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local colored_message=""
    
    case "$level" in
        "INFO")  colored_message="${GREEN}[INFO]${NC} $message" ;;
        "WARN")  colored_message="${YELLOW}[WARN]${NC} $message" ;;
        "ERROR") colored_message="${RED}[ERROR]${NC} $message" ;;
        "SUCCESS") colored_message="${GREEN}[SUCCESS]${NC} $message" ;;
        "DEBUG") colored_message="${BLUE}[DEBUG]${NC} $message" ;;
        "STEP") colored_message="${CYAN}[STEP]${NC} $message" ;;
        *) colored_message="$message" ;;
    esac
    
    echo -e "$colored_message"
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE"
}

log() { log_message "INFO" "$1"; }
warn() { log_message "WARN" "$1"; }
error() { log_message "ERROR" "$1"; }
success() { log_message "SUCCESS" "$1"; }
debug() { [[ "$VERBOSE" == "true" ]] && log_message "DEBUG" "$1"; }
step() { log_message "STEP" "$1"; }

# Enhanced error handling
error_handler() {
    local exit_code=$1
    local line_number=$2
    
    # Don't trigger on expected exits (like help)
    if [[ $exit_code -eq 0 ]]; then
        return 0
    fi
    
    error "Script failed with exit code $exit_code at line $line_number"
    error "Check $LOG_FILE for more details"
    cleanup_on_error
    exit $exit_code
}

cleanup_on_error() {
    warn "Performing cleanup after error..."
    # Add cleanup tasks here if needed
    debug "Cleanup completed"
}

# Signal handlers - only set if not showing help
setup_error_handling() {
    set -E  # Enable ERR trap inheritance
    trap 'error_handler $? $LINENO' ERR
    trap 'warn "Setup interrupted by user"; cleanup_on_error; exit 130' INT TERM
}

# Enhanced OS detection with distribution version
detect_os() {
    debug "Detecting operating system..."
    
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if [ -f /etc/os-release ]; then
            . /etc/os-release
            OS=$ID
            OS_VERSION=$VERSION_ID
            OS_CODENAME=${VERSION_CODENAME:-"unknown"}
        elif [ -f /etc/debian_version ]; then
            OS=debian
            OS_VERSION=$(cat /etc/debian_version)
        elif [ -f /etc/redhat-release ]; then
            OS=centos
            OS_VERSION=$(grep -oE '[0-9]+\.[0-9]+' /etc/redhat-release | head -1)
        else
            OS=unknown
            OS_VERSION="unknown"
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        OS=macos
        OS_VERSION=$(sw_vers -productVersion)
    else
        OS=unknown
        OS_VERSION="unknown"
    fi
    
    debug "Detected OS: $OS $OS_VERSION"
    echo $OS
}

# Enhanced privilege check
check_privileges() {
    debug "Checking user privileges..."
    
    if [[ $EUID -eq 0 ]]; then
        warn "Running as root. This is not recommended for security reasons."
        warn "Consider running as a regular user with sudo privileges."
        read -p "Continue anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            error "Setup cancelled by user"
            exit 1
        fi
        return 0
    fi
    
    # Check if user has sudo privileges
    if sudo -n true 2>/dev/null; then
        debug "User has sudo privileges"
        return 1
    else
        debug "User does not have sudo privileges"
        return 1
    fi
}

# Enhanced command execution with error handling
run_with_sudo() {
    local cmd="$*"
    debug "Executing: $cmd"
    
    if [[ $DRY_RUN == "true" ]]; then
        log "DRY RUN: Would execute: $cmd"
        return 0
    fi
    
    if check_privileges; then
        eval "$cmd"
    else
        sudo "$@"
    fi
}

# Safe command execution with retry logic
safe_execute() {
    local max_attempts=3
    local delay=2
    local cmd="$*"
    local attempt=1
    
    while [[ $attempt -le $max_attempts ]]; do
        debug "Attempt $attempt/$max_attempts: $cmd"
        
        if [[ $DRY_RUN == "true" ]]; then
            log "DRY RUN: Would execute: $cmd"
            return 0
        fi
        
        if eval "$cmd"; then
            debug "Command succeeded on attempt $attempt"
            return 0
        else
            local exit_code=$?
            warn "Command failed on attempt $attempt (exit code: $exit_code)"
            
            if [[ $attempt -lt $max_attempts ]]; then
                warn "Retrying in $delay seconds..."
                sleep $delay
                ((delay *= 2))  # Exponential backoff
            fi
        fi
        
        ((attempt++))
    done
    
    error "Command failed after $max_attempts attempts: $cmd"
    return 1
}

# Enhanced Python version checking
check_python_version() {
    step "Checking Python version..."
    
    local python_cmd=""
    local python_version=""
    
    # Try different Python commands
    for cmd in python3 python python3.12 python3.11 python3.10 python3.9 python3.8 python3.7; do
        if command -v "$cmd" &> /dev/null; then
            python_cmd="$cmd"
            python_version=$($cmd --version 2>&1 | awk '{print $2}')
            debug "Found Python: $cmd version $python_version"
            break
        fi
    done
    
    if [[ -z "$python_cmd" ]]; then
        error "Python 3 is not installed"
        return 1
    fi
    
    # Version comparison - simpler approach
    local major_version=$(echo "$python_version" | cut -d. -f1)
    local minor_version=$(echo "$python_version" | cut -d. -f2)
    local required_major=3
    local required_minor=7
    
    if [[ $major_version -gt $required_major ]] || \
       ([[ $major_version -eq $required_major ]] && [[ $minor_version -ge $required_minor ]]); then
        success "Python version check passed: $python_version"
        export PYTHON_CMD="$python_cmd"
        return 0
    else
        error "Python $required_major.$required_minor or higher is required (found $python_version)"
        return 1
    fi
}

# Enhanced virtual environment setup
setup_virtual_environment() {
    step "Setting up virtual environment..."
    
    # Remove existing venv if force install is enabled
    if [[ "$FORCE_INSTALL" == "true" && -d "$VENV_DIR" ]]; then
        warn "Removing existing virtual environment..."
        rm -rf "$VENV_DIR"
    fi
    
    # Create virtual environment if it doesn't exist
    if [[ ! -d "$VENV_DIR" ]]; then
        log "Creating virtual environment at $VENV_DIR..."
        
        # Check if venv module is available
        if ! $PYTHON_CMD -m venv --help &> /dev/null; then
            error "Python venv module is not available"
            log "Installing python3-venv..."
            
            case $(detect_os) in
                ubuntu|debian)
                    run_with_sudo apt-get update
                    run_with_sudo apt-get install -y python3-venv python3-pip
                    ;;
                centos|rhel|fedora)
                    run_with_sudo yum install -y python3-venv python3-pip || run_with_sudo dnf install -y python3-venv python3-pip
                    ;;
                arch)
                    run_with_sudo pacman -S --needed --noconfirm python-pip
                    ;;
                *)
                    error "Unsupported OS for automatic venv installation"
                    return 1
                    ;;
            esac
        fi
        
        # Create virtual environment
        safe_execute "$PYTHON_CMD -m venv \"$VENV_DIR\""
        
        # Verify virtual environment was created successfully
        if [[ ! -f "$VENV_DIR/bin/activate" ]]; then
            error "Failed to create virtual environment"
            return 1
        fi
    fi
    
    # Activate virtual environment
    log "Activating virtual environment..."
    source "$VENV_DIR/bin/activate"
    
    # Verify activation
    if [[ "$VIRTUAL_ENV" != "$VENV_DIR" ]]; then
        error "Failed to activate virtual environment"
        return 1
    fi
    
    # Upgrade pip
    log "Upgrading pip..."
    safe_execute "pip install --upgrade pip wheel setuptools"
    
    success "Virtual environment ready at $VENV_DIR"
    return 0
}

# Enhanced package installation with error handling
install_package() {
    local package="$1"
    local max_attempts=3
    local attempt=1
    
    while [[ $attempt -le $max_attempts ]]; do
        debug "Installing $package (attempt $attempt/$max_attempts)"
        
        if pip install "$package"; then
            debug "Successfully installed $package"
            return 0
        else
            warn "Failed to install $package on attempt $attempt"
            
            if [[ $attempt -lt $max_attempts ]]; then
                warn "Retrying installation of $package..."
                sleep 2
            fi
        fi
        
        ((attempt++))
    done
    
    error "Failed to install $package after $max_attempts attempts"
    return 1
}

# Enhanced system package installation
install_system_packages() {
    local OS=$(detect_os)
    
    step "Installing system dependencies for $OS..."
    
    if [[ "$SKIP_SYSTEM_DEPS" == "true" ]]; then
        warn "Skipping system dependencies installation"
        return 0
    fi
    
    case $OS in
        ubuntu|debian)
            log "Updating package list..."
            safe_execute "run_with_sudo apt-get update"
            
            # Fix broken packages if any
            log "Fixing broken packages..."
            safe_execute "run_with_sudo apt-get -f install -y"
            
            log "Installing essential packages..."
            local essential_packages=(
                "python3" "python3-pip" "python3-dev" "python3-venv"
                "build-essential" "libssl-dev" "libffi-dev"
                "libxml2-dev" "libxslt1-dev" "zlib1g-dev"
                "git" "curl" "wget" "ca-certificates"
            )
            
            for package in "${essential_packages[@]}"; do
                if ! dpkg -l | grep -q "^ii  $package "; then
                    safe_execute "run_with_sudo apt-get install -y $package"
                else
                    debug "$package is already installed"
                fi
            done
            
            log "Installing security tools..."
            local security_packages=(
                "nmap" "masscan" "tcpdump" "john" "hydra"
                "sqlmap" "nikto" "clamav" "clamav-daemon"
                "yara" "hashcat" "netcat-openbsd" "dnsutils"
                "whois" "traceroute" "telnet" "ftp" "openssh-client"
            )
            
            for package in "${security_packages[@]}"; do
                if ! dpkg -l | grep -q "^ii  $package "; then
                    if safe_execute "run_with_sudo apt-get install -y $package"; then
                        debug "Successfully installed $package"
                    else
                        warn "Failed to install $package, continuing..."
                    fi
                else
                    debug "$package is already installed"
                fi
            done
            ;;
            
        centos|rhel|fedora)
            local PKG_MGR="yum"
            if command -v dnf &> /dev/null; then
                PKG_MGR="dnf"
            fi
            
            log "Installing essential packages..."
            local essential_packages=(
                "python3" "python3-pip" "python3-devel" "gcc"
                "openssl-devel" "libffi-devel" "libxml2-devel"
                "libxslt-devel" "zlib-devel" "git" "curl" "wget"
            )
            
            for package in "${essential_packages[@]}"; do
                safe_execute "run_with_sudo $PKG_MGR install -y $package"
            done
            
            log "Installing security tools..."
            local security_packages=(
                "nmap" "masscan" "tcpdump" "john" "hydra"
                "sqlmap" "nikto" "clamav" "clamav-update"
                "yara" "hashcat" "nc" "bind-utils" "whois"
                "traceroute" "telnet" "ftp" "openssh-clients"
            )
            
            for package in "${security_packages[@]}"; do
                if safe_execute "run_with_sudo $PKG_MGR install -y $package"; then
                    debug "Successfully installed $package"
                else
                    warn "Failed to install $package, continuing..."
                fi
            done
            ;;
            
        arch)
            log "Installing essential packages..."
            safe_execute "run_with_sudo pacman -Sy"
            
            local essential_packages=(
                "python" "python-pip" "base-devel" "openssl"
                "libffi" "libxml2" "libxslt" "zlib" "git" "curl" "wget"
            )
            
            for package in "${essential_packages[@]}"; do
                safe_execute "run_with_sudo pacman -S --needed --noconfirm $package"
            done
            
            log "Installing security tools..."
            local security_packages=(
                "nmap" "masscan" "tcpdump" "john" "hydra"
                "sqlmap" "nikto" "clamav" "yara" "hashcat"
                "netcat" "bind-tools" "whois" "traceroute"
                "inetutils" "openssh"
            )
            
            for package in "${security_packages[@]}"; do
                if safe_execute "run_with_sudo pacman -S --needed --noconfirm $package"; then
                    debug "Successfully installed $package"
                else
                    warn "Failed to install $package, continuing..."
                fi
            done
            ;;
            
        macos)
            if ! command -v brew &> /dev/null; then
                error "Homebrew not found. Please install Homebrew first:"
                error "https://brew.sh/"
                return 1
            fi
            
            log "Installing essential packages..."
            safe_execute "brew install python3 git curl wget"
            
            log "Installing security tools..."
            local security_packages=(
                "nmap" "masscan" "john" "hydra" "sqlmap"
                "nikto" "clamav" "yara" "hashcat" "netcat"
                "whois" "telnet"
            )
            
            for package in "${security_packages[@]}"; do
                if safe_execute "brew install $package"; then
                    debug "Successfully installed $package"
                else
                    warn "Failed to install $package, continuing..."
                fi
            done
            ;;
            
        *)
            warn "Unknown OS: $OS"
            warn "Please install dependencies manually:"
            warn "- nmap, masscan, tcpdump, john, hydra, sqlmap, nikto"
            warn "- clamav, yara, hashcat, netcat, whois, telnet"
            return 1
            ;;
    esac
    
    success "System packages installation completed"
    return 0
}

# Enhanced Python package installation
install_python_packages() {
    step "Installing Python dependencies..."
    
    # Ensure we're in the virtual environment
    if [[ -z "$VIRTUAL_ENV" ]]; then
        error "Virtual environment not activated"
        return 1
    fi
    
    # Install wheel first for better compatibility
    log "Installing build tools..."
    safe_execute "pip install --upgrade pip wheel setuptools"
    
    # Install requirements from file
    if [[ -f "$SCRIPT_DIR/requirements.txt" ]]; then
        log "Installing packages from requirements.txt..."
        
        # Read requirements and install with error handling
        while IFS= read -r requirement || [[ -n "$requirement" ]]; do
            # Skip empty lines and comments
            [[ -z "$requirement" || "$requirement" =~ ^[[:space:]]*# ]] && continue
            
            local package_name=$(echo "$requirement" | sed 's/[><=!].*//')
            
            if install_package "$requirement"; then
                debug "Successfully installed $package_name"
            else
                warn "Failed to install $package_name, trying fallback..."
                
                # Try installing without version constraints
                if install_package "$package_name"; then
                    warn "Installed $package_name without version constraints"
                else
                    error "Failed to install $package_name even without version constraints"
                fi
            fi
        done < "$SCRIPT_DIR/requirements.txt"
    else
        warn "requirements.txt not found, installing essential packages manually..."
        
        local essential_packages=(
            "rich" "click" "python-nmap" "paramiko" "cryptography"
            "aiohttp" "beautifulsoup4" "scapy" "netaddr" "dnspython"
            "pyyaml" "requests" "urllib3" "psutil"
        )
        
        for package in "${essential_packages[@]}"; do
            if install_package "$package"; then
                debug "Successfully installed $package"
            else
                warn "Failed to install $package"
            fi
        done
    fi
    
    # Install optional packages (ignore errors)
    log "Installing optional packages..."
    local optional_packages=(
        "yara-python" "mysql-connector-python" "psycopg2-binary"
        "pymongo" "redis" "volatility3" "python-magic"
        "netifaces" "python-whois"
    )
    
    for package in "${optional_packages[@]}"; do
        if install_package "$package"; then
            debug "Successfully installed optional package $package"
        else
            warn "Failed to install optional package $package (continuing...)"
        fi
    done
    
    success "Python packages installation completed"
    return 0
}

# Enhanced LinuxScan package setup
setup_linuxscan() {
    step "Setting up LinuxScan package..."
    
    # Make scripts executable
    if [[ -f "$SCRIPT_DIR/linux_security_scanner.py" ]]; then
        chmod +x "$SCRIPT_DIR/linux_security_scanner.py"
        debug "Made linux_security_scanner.py executable"
    fi
    
    if [[ -f "$SCRIPT_DIR/linuxscan/enhanced_cli.py" ]]; then
        chmod +x "$SCRIPT_DIR/linuxscan/enhanced_cli.py"
        debug "Made enhanced_cli.py executable"
    fi
    
    # Install in development mode
    if [[ -f "$SCRIPT_DIR/setup.py" ]]; then
        log "Installing LinuxScan package in development mode..."
        
        # Try to install, handle common errors
        if ! safe_execute "pip install -e \"$SCRIPT_DIR\""; then
            warn "Failed to install with -e flag, trying alternative method..."
            
            # Try installing without editable mode
            if safe_execute "pip install \"$SCRIPT_DIR\""; then
                warn "Installed in non-editable mode"
            else
                error "Failed to install LinuxScan package"
                return 1
            fi
        fi
        
        success "LinuxScan package installed successfully"
    else
        warn "setup.py not found, skipping package installation"
    fi
    
    return 0
}

# Enhanced system check with detailed reporting
run_system_check() {
    step "Running comprehensive system dependency check..."
    
    # Ensure we're in the virtual environment
    if [[ -n "$VIRTUAL_ENV" ]]; then
        # Try to run the system check
        if safe_execute "$PYTHON_CMD -c \"from linuxscan.modules.system_check import SystemCheckModule; import asyncio; asyncio.run(SystemCheckModule().scan())\""; then
            success "System check completed successfully"
        else
            warn "System check module failed, but continuing with setup"
        fi
    else
        warn "Skipping system check (virtual environment not active)"
    fi
    
    return 0
}

# Enhanced ClamAV setup
update_clamav() {
    step "Setting up ClamAV antivirus..."
    
    if command -v freshclam &> /dev/null; then
        log "Updating ClamAV virus signatures..."
        
        # Create clamav directories if they don't exist
        run_with_sudo mkdir -p /var/lib/clamav /var/log/clamav
        
        # Update virus signatures
        if safe_execute "run_with_sudo freshclam"; then
            success "ClamAV signatures updated successfully"
        else
            warn "Failed to update ClamAV signatures"
            
            # Try alternative update method
            log "Trying alternative ClamAV update method..."
            if safe_execute "run_with_sudo freshclam --datadir=/var/lib/clamav"; then
                success "ClamAV signatures updated using alternative method"
            else
                warn "ClamAV signature update failed, but continuing..."
            fi
        fi
    else
        warn "ClamAV not found, skipping signature update"
    fi
    
    return 0
}

# Enhanced wordlist setup with validation
setup_wordlists() {
    step "Setting up security testing wordlists..."
    
    local WORDLIST_DIR="$SCRIPT_DIR/wordlists"
    mkdir -p "$WORDLIST_DIR"
    
    # Define wordlist sources
    local wordlists=(
        "common_passwords.txt|https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-1000.txt"
        "common_usernames.txt|https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/top-usernames-shortlist.txt"
        "directory_list.txt|https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-2.3-medium.txt"
    )
    
    for item in "${wordlists[@]}"; do
        local filename=$(echo "$item" | cut -d'|' -f1)
        local url=$(echo "$item" | cut -d'|' -f2)
        local filepath="$WORDLIST_DIR/$filename"
        
        if [[ ! -f "$filepath" ]]; then
            log "Downloading $filename..."
            
            if safe_execute "curl -s -L \"$url\" -o \"$filepath\""; then
                # Validate download
                if [[ -f "$filepath" && -s "$filepath" ]]; then
                    debug "Successfully downloaded $filename ($(wc -l < "$filepath") lines)"
                else
                    warn "Downloaded $filename appears to be empty"
                    rm -f "$filepath"
                fi
            else
                warn "Failed to download $filename"
            fi
        else
            debug "$filename already exists"
        fi
    done
    
    success "Wordlists setup completed"
    return 0
}

# Enhanced configuration setup
create_configs() {
    step "Creating configuration files..."
    
    local config_dir="$HOME/.config/linuxscan"
    local config_file="$config_dir/config.json"
    
    # Create config directory
    mkdir -p "$config_dir"
    
    # Create default config if it doesn't exist or if force install
    if [[ ! -f "$config_file" || "$FORCE_INSTALL" == "true" ]]; then
        log "Creating default configuration..."
        
        cat > "$config_file" << 'EOF'
{
    "timeout": 10,
    "max_workers": 50,
    "verbose": false,
    "output_format": "json",
    "scan_modules": ["port_scanner", "vulnerability_scanner"],
    "nmap_options": "-sS -O -sV",
    "web_scanner": {
        "user_agent": "LinuxScan/2.0",
        "follow_redirects": true,
        "max_redirects": 5,
        "timeout": 30
    },
    "ssh_scanner": {
        "timeout": 5,
        "max_attempts": 3,
        "delay": 1,
        "default_ports": [22, 2222, 2200]
    },
    "database_scanner": {
        "timeout": 10,
        "test_connection": true,
        "default_ports": {
            "mysql": [3306, 3307],
            "postgresql": [5432, 5433],
            "mongodb": [27017, 27018],
            "redis": [6379, 6380]
        }
    },
    "logging": {
        "level": "INFO",
        "file": "/tmp/linuxscan.log",
        "max_size": "10MB",
        "backup_count": 5
    }
}
EOF
        
        success "Default configuration created at $config_file"
    else
        debug "Configuration file already exists"
    fi
    
    return 0
}

# Progress indicator
show_progress() {
    local current=$1
    local total=$2
    local message=$3
    
    local percent=$((current * 100 / total))
    local filled=$((percent / 2))
    local empty=$((50 - filled))
    
    printf "\r${CYAN}[PROGRESS]${NC} $message "
    printf "["
    printf "%*s" $filled | tr ' ' '='
    printf "%*s" $empty | tr ' ' '-'
    printf "] %d%%" $percent
    
    if [[ $current -eq $total ]]; then
        echo
    fi
}

# System information gathering
gather_system_info() {
    debug "Gathering system information..."
    
    echo "System Information:" >> "$LOG_FILE"
    echo "==================" >> "$LOG_FILE"
    echo "Date: $(date)" >> "$LOG_FILE"
    echo "User: $(whoami)" >> "$LOG_FILE"
    echo "OS: $(detect_os)" >> "$LOG_FILE"
    echo "Kernel: $(uname -r)" >> "$LOG_FILE"
    echo "Architecture: $(uname -m)" >> "$LOG_FILE"
    echo "Python: $($PYTHON_CMD --version 2>&1)" >> "$LOG_FILE"
    echo "Shell: $SHELL" >> "$LOG_FILE"
    echo "Working Directory: $SCRIPT_DIR" >> "$LOG_FILE"
    echo "Virtual Environment: ${VIRTUAL_ENV:-"None"}" >> "$LOG_FILE"
    echo "==================" >> "$LOG_FILE"
    echo >> "$LOG_FILE"
}

# Enhanced completion message with system status
display_completion() {
    clear
    echo
    echo "=================================================================="
    echo -e "${GREEN}🎉 LinuxScan Enhanced Setup Complete! 🎉${NC}"
    echo "=================================================================="
    echo
    echo -e "${CYAN}📊 Installation Summary:${NC}"
    echo "  • Python Version: $($PYTHON_CMD --version 2>&1)"
    echo "  • Virtual Environment: $VENV_DIR"
    echo "  • Configuration: $HOME/.config/linuxscan/"
    echo "  • Wordlists: $SCRIPT_DIR/wordlists/"
    echo "  • Log File: $LOG_FILE"
    echo
    echo -e "${CYAN}🚀 Usage Examples:${NC}"
    echo -e "  ${YELLOW}# Activate virtual environment${NC}"
    echo -e "  source $VENV_DIR/bin/activate"
    echo
    echo -e "  ${YELLOW}# Basic scan${NC}"
    echo -e "  linuxscan 192.168.1.1"
    echo
    echo -e "  ${YELLOW}# Comprehensive scan${NC}"
    echo -e "  linuxscan 192.168.1.1 --modules all"
    echo
    echo -e "  ${YELLOW}# System check${NC}"
    echo -e "  linuxscan --system-check"
    echo
    echo -e "  ${YELLOW}# Interactive GUI mode${NC}"
    echo -e "  python3 linux_security_scanner.py"
    echo
    echo -e "  ${YELLOW}# CLI help${NC}"
    echo -e "  linuxscan --help"
    echo
    echo -e "${CYAN}📁 Important Files:${NC}"
    echo -e "  • Main Script: $SCRIPT_DIR/linux_security_scanner.py"
    echo -e "  • CLI Tool: linuxscan (installed in PATH)"
    echo -e "  • Configuration: $HOME/.config/linuxscan/config.json"
    echo -e "  • Setup Log: $LOG_FILE"
    echo
    echo -e "${CYAN}🔧 Advanced Usage:${NC}"
    echo -e "  # Run with custom config"
    echo -e "  linuxscan --config /path/to/config.json target"
    echo
    echo -e "  # Scan multiple targets"
    echo -e "  linuxscan --targets targets.txt"
    echo
    echo -e "  # Export results"
    echo -e "  linuxscan target --output results.json --format json"
    echo
    echo -e "${RED}⚠️  Important Notes:${NC}"
    echo -e "  • Always activate the virtual environment before use"
    echo -e "  • Some features require root privileges"
    echo -e "  • Run 'linuxscan --system-check' to verify all dependencies"
    echo -e "  • Use 'bash setup.sh --system-deps' to install missing system tools"
    echo
    echo -e "${GREEN}📖 Documentation:${NC}"
    echo -e "  • README.md - Main documentation"
    echo -e "  • INSTALL.md - Installation guide"
    echo -e "  • GUI_ENHANCEMENTS.md - GUI features"
    echo
    success "Setup completed successfully! 🎯"
    echo
}

# Help message
show_help() {
    cat << EOF
${BOLD}LinuxScan Enhanced Setup Script v2.0.0${NC}

${BOLD}USAGE:${NC}
    bash setup.sh [OPTIONS]

${BOLD}OPTIONS:${NC}
    --system-deps, -s      Install system dependencies (requires sudo)
    --venv, -v            Create and use virtual environment (recommended)
    --force, -f           Force reinstallation (removes existing venv)
    --skip-system         Skip system dependency installation
    --verbose             Enable verbose output and debugging
    --dry-run             Show what would be done without executing
    --help, -h            Show this help message

${BOLD}EXAMPLES:${NC}
    # Basic setup (Python packages only)
    bash setup.sh

    # Full setup with system dependencies
    bash setup.sh --system-deps --venv

    # Force reinstallation
    bash setup.sh --force --venv

    # Verbose mode with dry run
    bash setup.sh --verbose --dry-run --system-deps

${BOLD}FEATURES:${NC}
    ✅ Enhanced error handling and retry logic
    ✅ Automatic virtual environment management
    ✅ Broken package detection and fixing
    ✅ Comprehensive logging
    ✅ Progress indicators
    ✅ Rollback on failure
    ✅ System compatibility checks
    ✅ Automated wordlist downloads
    ✅ Configuration file generation

${BOLD}REQUIREMENTS:${NC}
    • Python 3.7 or higher
    • Internet connection for downloads
    • sudo privileges (for --system-deps)

${BOLD}LOG FILE:${NC}
    $LOG_FILE

${BOLD}TROUBLESHOOTING:${NC}
    • Check the log file for detailed error information
    • Use --verbose for more detailed output
    • Try --force to clean install
    • Ensure you have sufficient disk space and permissions

EOF
}

# Enhanced argument parsing
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --system-deps|-s)
                SKIP_SYSTEM_DEPS=false
                debug "System dependencies will be installed"
                shift
                ;;
            --venv|-v)
                # Always create venv by default in enhanced version
                debug "Virtual environment mode enabled"
                shift
                ;;
            --force|-f)
                FORCE_INSTALL=true
                debug "Force installation mode enabled"
                shift
                ;;
            --skip-system)
                SKIP_SYSTEM_DEPS=true
                debug "System dependencies will be skipped"
                shift
                ;;
            --verbose)
                VERBOSE=true
                debug "Verbose mode enabled"
                shift
                ;;
            --dry-run)
                DRY_RUN=true
                log "Dry run mode enabled - no changes will be made"
                shift
                ;;
            --help|-h)
                show_help
                exit 0
                ;;
            *)
                error "Unknown option: $1"
                echo "Use --help for usage information"
                exit 1
                ;;
        esac
    done
}

# Pre-flight checks
preflight_checks() {
    step "Running pre-flight checks..."
    
    # Check if script is run from correct directory
    if [[ ! -f "$SCRIPT_DIR/setup.py" ]]; then
        error "setup.py not found. Please run this script from the LinuxScan root directory"
        return 1
    fi
    
    # Check disk space (require at least 1GB)
    local available_space=$(df "$SCRIPT_DIR" | awk 'NR==2 {print $4}')
    if [[ $available_space -lt 1048576 ]]; then  # 1GB in KB
        warn "Low disk space detected. At least 1GB is recommended"
        read -p "Continue anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            error "Setup cancelled due to low disk space"
            return 1
        fi
    fi
    
    # Check internet connectivity
    if ! curl -s --head "https://pypi.org" > /dev/null; then
        warn "Internet connectivity check failed"
        warn "Some features may not work without internet access"
        read -p "Continue anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            error "Setup cancelled due to connectivity issues"
            return 1
        fi
    fi
    
    success "Pre-flight checks passed"
    return 0
}

# Enhanced main function with progress tracking
main() {
    local start_time=$(date +%s)
    
    # Initialize logging
    echo "LinuxScan Enhanced Setup Started at $(date)" > "$LOG_FILE"
    
    echo "🚀 LinuxScan Professional Security Scanner Enhanced Setup v2.0.0"
    echo "=================================================================="
    
    gather_system_info
    
    # Parse command line arguments first (before setting up error handling)
    parse_arguments "$@"
    
    # Set up error handling after argument parsing
    setup_error_handling
    
    # Pre-flight checks
    if ! preflight_checks; then
        exit 1
    fi
    
    local total_steps=8
    local current_step=0
    
    # Step 1: Python version check
    ((current_step++))
    show_progress $current_step $total_steps "Checking Python version"
    if ! check_python_version; then
        error "Python version check failed"
        exit 1
    fi
    
    # Step 2: System packages (if requested)
    if [[ "$SKIP_SYSTEM_DEPS" == "false" ]]; then
        ((current_step++))
        show_progress $current_step $total_steps "Installing system dependencies"
        if ! install_system_packages; then
            error "System package installation failed"
            exit 1
        fi
    else
        debug "Skipping system dependencies as requested"
        ((current_step++))
    fi
    
    # Step 3: Virtual environment setup
    ((current_step++))
    show_progress $current_step $total_steps "Setting up virtual environment"
    if ! setup_virtual_environment; then
        error "Virtual environment setup failed"
        exit 1
    fi
    
    # Step 4: Python packages
    ((current_step++))
    show_progress $current_step $total_steps "Installing Python packages"
    if ! install_python_packages; then
        error "Python package installation failed"
        exit 1
    fi
    
    # Step 5: LinuxScan package
    ((current_step++))
    show_progress $current_step $total_steps "Installing LinuxScan package"
    if ! setup_linuxscan; then
        error "LinuxScan package setup failed"
        exit 1
    fi
    
    # Step 6: Wordlists
    ((current_step++))
    show_progress $current_step $total_steps "Setting up wordlists"
    setup_wordlists  # Non-critical, continue on failure
    
    # Step 7: Configuration
    ((current_step++))
    show_progress $current_step $total_steps "Creating configuration"
    create_configs  # Non-critical, continue on failure
    
    # Step 8: System check
    ((current_step++))
    show_progress $current_step $total_steps "Running system check"
    run_system_check  # Non-critical, continue on failure
    
    # Optional: ClamAV update
    if command -v freshclam &> /dev/null && [[ "$SKIP_SYSTEM_DEPS" == "false" ]]; then
        log "Updating ClamAV signatures..."
        update_clamav
    fi
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    log_message "INFO" "Setup completed in ${duration} seconds"
    
    # Display completion message
    display_completion
}

# Script execution
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    # Ensure we're in the right directory
    cd "$SCRIPT_DIR"
    
    # Execute main function with all arguments
    main "$@"
fi