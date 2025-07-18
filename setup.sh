#!/bin/bash

set -e  # Exit on any error

echo "🚀 LinuxScan Professional Security Scanner Setup"
echo "================================================="

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

# Function to detect OS
detect_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if [ -f /etc/os-release ]; then
            . /etc/os-release
            OS=$ID
        elif [ -f /etc/debian_version ]; then
            OS=debian
        elif [ -f /etc/redhat-release ]; then
            OS=centos
        else
            OS=unknown
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        OS=macos
    else
        OS=unknown
    fi
    echo $OS
}

# Function to check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        return 0
    else
        return 1
    fi
}

# Function to run command with sudo if needed
run_with_sudo() {
    if check_root; then
        "$@"
    else
        sudo "$@"
    fi
}

# Function to install system packages
install_system_packages() {
    local OS=$(detect_os)
    
    log "Detected OS: $OS"
    log "Installing system dependencies..."
    
    case $OS in
        ubuntu|debian)
            log "Updating package list..."
            run_with_sudo apt-get update
            
            log "Installing essential packages..."
            run_with_sudo apt-get install -y \
                python3 \
                python3-pip \
                python3-dev \
                python3-venv \
                build-essential \
                libssl-dev \
                libffi-dev \
                libxml2-dev \
                libxslt1-dev \
                zlib1g-dev \
                git \
                curl \
                wget
            
            log "Installing security tools..."
            run_with_sudo apt-get install -y \
                nmap \
                masscan \
                tcpdump \
                john \
                hydra \
                sqlmap \
                nikto \
                clamav \
                clamav-daemon \
                yara \
                hashcat \
                netcat-openbsd \
                dnsutils \
                whois \
                traceroute \
                telnet \
                ftp \
                openssh-client
            ;;
        centos|rhel|fedora)
            if command -v dnf &> /dev/null; then
                PKG_MGR="dnf"
            else
                PKG_MGR="yum"
            fi
            
            log "Installing essential packages..."
            run_with_sudo $PKG_MGR install -y \
                python3 \
                python3-pip \
                python3-devel \
                gcc \
                openssl-devel \
                libffi-devel \
                libxml2-devel \
                libxslt-devel \
                zlib-devel \
                git \
                curl \
                wget
            
            log "Installing security tools..."
            run_with_sudo $PKG_MGR install -y \
                nmap \
                masscan \
                tcpdump \
                john \
                hydra \
                sqlmap \
                nikto \
                clamav \
                clamav-update \
                yara \
                hashcat \
                nc \
                bind-utils \
                whois \
                traceroute \
                telnet \
                ftp \
                openssh-clients
            ;;
        arch)
            log "Installing essential packages..."
            run_with_sudo pacman -S --needed --noconfirm \
                python \
                python-pip \
                base-devel \
                openssl \
                libffi \
                libxml2 \
                libxslt \
                zlib \
                git \
                curl \
                wget
            
            log "Installing security tools..."
            run_with_sudo pacman -S --needed --noconfirm \
                nmap \
                masscan \
                tcpdump \
                john \
                hydra \
                sqlmap \
                nikto \
                clamav \
                yara \
                hashcat \
                netcat \
                bind-tools \
                whois \
                traceroute \
                inetutils \
                openssh
            ;;
        macos)
            if ! command -v brew &> /dev/null; then
                error "Homebrew not found. Please install Homebrew first:"
                error "https://brew.sh/"
                exit 1
            fi
            
            log "Installing essential packages..."
            brew install python3 git curl wget
            
            log "Installing security tools..."
            brew install \
                nmap \
                masscan \
                john \
                hydra \
                sqlmap \
                nikto \
                clamav \
                yara \
                hashcat \
                netcat \
                whois \
                telnet
            ;;
        *)
            warn "Unknown OS: $OS"
            warn "Please install dependencies manually:"
            warn "- nmap, masscan, tcpdump, john, hydra, sqlmap, nikto"
            warn "- clamav, yara, hashcat, netcat, whois, telnet"
            ;;
    esac
}

# Function to check Python version
check_python_version() {
    log "Checking Python version..."
    
    if ! command -v python3 &> /dev/null; then
        error "Python 3 is not installed"
        exit 1
    fi
    
    python_version=$(python3 --version 2>&1 | awk '{print $2}')
    required_version="3.7"
    
    if [ "$(printf '%s\n' "$required_version" "$python_version" | sort -V | head -n1)" != "$required_version" ]; then 
        error "Python $required_version or higher is required (found $python_version)"
        exit 1
    fi
    
    success "Python version check passed: $python_version"
}

# Function to create virtual environment
setup_virtual_environment() {
    log "Setting up virtual environment..."
    
    if [ ! -d "venv" ]; then
        python3 -m venv venv
        log "Virtual environment created"
    fi
    
    log "Activating virtual environment..."
    source venv/bin/activate
    
    log "Upgrading pip..."
    pip install --upgrade pip
    
    success "Virtual environment ready"
}

# Function to install Python packages
install_python_packages() {
    log "Installing Python dependencies..."
    
    # Install wheel first for better compatibility
    pip install wheel
    
    # Install requirements
    if [ -f "requirements.txt" ]; then
        log "Installing from requirements.txt..."
        pip install -r requirements.txt
    else
        warn "requirements.txt not found, installing essential packages manually..."
        pip install \
            rich \
            click \
            python-nmap \
            paramiko \
            cryptography \
            aiohttp \
            beautifulsoup4 \
            scapy \
            netaddr \
            dnspython \
            pyyaml \
            requests \
            urllib3
    fi
    
    # Install optional packages (ignore errors)
    log "Installing optional packages..."
    pip install --ignore-installed \
        yara-python \
        mysql-connector-python \
        psycopg2-binary \
        pymongo \
        redis \
        volatility3 \
        python-magic \
        netifaces \
        python-whois || warn "Some optional packages failed to install"
    
    success "Python packages installed"
}

# Function to setup LinuxScan package
setup_linuxscan() {
    log "Setting up LinuxScan package..."
    
    # Make scripts executable
    chmod +x linux_security_scanner.py
    if [ -f "linuxscan/enhanced_cli.py" ]; then
        chmod +x linuxscan/enhanced_cli.py
    fi
    
    # Install in development mode
    if [ -f "setup.py" ]; then
        pip install -e .
        success "LinuxScan package installed in development mode"
    else
        warn "setup.py not found, skipping package installation"
    fi
}

# Function to run system check
run_system_check() {
    log "Running system dependency check..."
    
    # Try to run the system check
    if python3 -c "from linuxscan.modules.system_check import SystemCheckModule; import asyncio; asyncio.run(SystemCheckModule().scan())" 2>/dev/null; then
        success "System check completed successfully"
    else
        warn "System check failed, but continuing with setup"
    fi
}

# Function to update ClamAV signatures
update_clamav() {
    log "Updating ClamAV virus signatures..."
    
    if command -v freshclam &> /dev/null; then
        run_with_sudo freshclam || warn "Failed to update ClamAV signatures"
    else
        warn "ClamAV not found, skipping signature update"
    fi
}

# Function to setup wordlists for security testing
setup_wordlists() {
    log "Setting up wordlists for security testing..."
    
    WORDLIST_DIR="wordlists"
    mkdir -p "$WORDLIST_DIR"
    
    # Download common wordlists
    if [ ! -f "$WORDLIST_DIR/common_passwords.txt" ]; then
        log "Downloading common password list..."
        curl -s -L "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-1000.txt" \
            -o "$WORDLIST_DIR/common_passwords.txt" || warn "Failed to download password list"
    fi
    
    if [ ! -f "$WORDLIST_DIR/common_usernames.txt" ]; then
        log "Downloading common username list..."
        curl -s -L "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/top-usernames-shortlist.txt" \
            -o "$WORDLIST_DIR/common_usernames.txt" || warn "Failed to download username list"
    fi
    
    success "Wordlists setup completed"
}

# Function to create configuration files
create_configs() {
    log "Creating configuration files..."
    
    # Create config directory
    mkdir -p ~/.config/linuxscan
    
    # Create default config if it doesn't exist
    if [ ! -f ~/.config/linuxscan/config.json ]; then
        cat > ~/.config/linuxscan/config.json << EOF
{
    "timeout": 10,
    "max_workers": 50,
    "verbose": false,
    "output_format": "json",
    "scan_modules": ["port_scanner", "vulnerability_scanner"],
    "nmap_options": "-sS -O -sV",
    "web_scanner": {
        "user_agent": "LinuxScan/1.0",
        "follow_redirects": true,
        "max_redirects": 5
    },
    "ssh_scanner": {
        "timeout": 5,
        "max_attempts": 3,
        "delay": 1
    },
    "database_scanner": {
        "timeout": 10,
        "test_connection": true
    }
}
EOF
        success "Default configuration created"
    fi
}

# Function to display completion message
display_completion() {
    echo
    echo "================================================="
    echo -e "${GREEN}🎉 LinuxScan Setup Complete! 🎉${NC}"
    echo "================================================="
    echo
    echo -e "${CYAN}Usage Examples:${NC}"
    echo -e "  ${YELLOW}# Basic scan${NC}"
    echo -e "  linuxscan 192.168.1.1"
    echo
    echo -e "  ${YELLOW}# Comprehensive scan${NC}"
    echo -e "  linuxscan 192.168.1.1 --modules all"
    echo
    echo -e "  ${YELLOW}# System check${NC}"
    echo -e "  linuxscan --system-check"
    echo
    echo -e "  ${YELLOW}# Interactive mode${NC}"
    echo -e "  python3 linux_security_scanner.py"
    echo
    echo -e "${CYAN}Configuration:${NC}"
    echo -e "  Config file: ~/.config/linuxscan/config.json"
    echo -e "  Wordlists: ./wordlists/"
    echo
    echo -e "${CYAN}Documentation:${NC}"
    echo -e "  README.md - Main documentation"
    echo -e "  INSTALL.md - Installation guide"
    echo -e "  SSH_SCANNER_DOCS.md - SSH scanner documentation"
    echo
    echo -e "${RED}Note:${NC} Some features require root privileges for optimal functionality"
    echo "      Run with sudo for full access to network interfaces and system info"
    echo
    success "Setup completed successfully!"
}

# Main setup function
main() {
    log "Starting LinuxScan setup..."
    
    # Check if we should install system packages
    if [ "$1" = "--system-deps" ] || [ "$1" = "-s" ]; then
        log "Installing system dependencies..."
        install_system_packages
        update_clamav
    fi
    
    # Check Python version
    check_python_version
    
    # Setup virtual environment (optional)
    if [ "$1" = "--venv" ] || [ "$1" = "-v" ]; then
        setup_virtual_environment
    fi
    
    # Install Python packages
    install_python_packages
    
    # Setup LinuxScan package
    setup_linuxscan
    
    # Setup wordlists
    setup_wordlists
    
    # Create configuration files
    create_configs
    
    # Run system check
    run_system_check
    
    # Display completion message
    display_completion
}

# Handle command line arguments
case "$1" in
    --help|-h)
        echo "LinuxScan Setup Script"
        echo "Usage: $0 [options]"
        echo
        echo "Options:"
        echo "  --system-deps, -s    Install system dependencies"
        echo "  --venv, -v          Setup virtual environment"
        echo "  --help, -h          Show this help message"
        echo
        echo "Examples:"
        echo "  $0                  # Basic setup (Python packages only)"
        echo "  $0 --system-deps    # Full setup with system dependencies"
        echo "  $0 --venv          # Setup with virtual environment"
        exit 0
        ;;
    *)
        main "$1"
        ;;
esac