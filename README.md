# LinuxScan v2.0 - Advanced Security Scanner

A comprehensive, professional security scanning tool for Linux systems with advanced capabilities including IoT device discovery, cryptographic analysis, memory forensics, and steganography detection.

## 🚀 Features

### 🔍 **Core Scanning Capabilities**
- **Port Scanning**: Enhanced port scanning with service detection and banner grabbing
- **Vulnerability Assessment**: CVE-based vulnerability detection with severity scoring
- **Network Discovery**: Comprehensive network topology analysis
- **Web Application Security**: OWASP-based web application testing
- **SSH Security Audit**: SSH configuration analysis and brute force testing
- **Database Security**: Database vulnerability assessment and configuration review

### 🔐 **Advanced Security Analysis**
- **Cryptographic Security Audit**: SSL/TLS analysis, cipher suite evaluation, certificate validation
- **Memory Analysis**: Process analysis, malware detection, memory dump investigation
- **Steganography Detection**: Hidden data discovery in images, audio, and documents
- **Malware Analysis**: Signature-based detection and behavioral analysis
- **Digital Forensics**: Evidence preservation and timeline reconstruction
- **Traffic Analysis**: Network traffic monitoring and anomaly detection

### 🌐 **Specialized Scanners**
- **IoT Device Discovery**: Smart device identification and security assessment
- **Compliance Auditing**: PCI DSS, HIPAA, SOX, GDPR compliance checking
- **Configuration Analysis**: Security configuration review and hardening recommendations
- **System Health Check**: Dependency verification and auto-installation

### 🎯 **Scan Modes**
- **Stealth Mode**: Minimal footprint scanning
- **Aggressive Mode**: Fast, comprehensive assessment
- **Balanced Mode**: Optimal speed/accuracy balance
- **Passive Mode**: Monitor-only, no active probing
- **Red Team Mode**: Offensive security testing
- **Blue Team Mode**: Defensive monitoring
- **Compliance Mode**: Regulatory compliance scanning
- **Forensics Mode**: Evidence gathering and analysis
- **Custom Mode**: User-defined parameters

### 🖥️ **User Interface**
- **Interactive GUI**: Rich terminal interface with 21 scan types
- **Command Line Interface**: Full CLI support with advanced options
- **Python API**: Programmatic access for integration
- **Multiple Entry Points**: GUI, CLI, and script compatibility

## 📦 Installation

### Prerequisites
```bash
# Ubuntu/Debian
sudo apt update && sudo apt install -y python3 python3-pip nmap

# CentOS/RHEL
sudo yum install -y python3 python3-pip nmap

# macOS
brew install python3 nmap
```

### Quick Installation
```bash
# From PyPI (Recommended)
pip install linuxscan

# From Source
git clone https://github.com/jomardyan/LinuxScan.git
cd LinuxScan
pip install -e .
```

### Development Installation
```bash
git clone https://github.com/jomardyan/LinuxScan.git
cd LinuxScan
pip install -e ".[dev]"
```

## 🚀 Quick Start

### Interactive GUI Mode
```bash
# Launch interactive interface
python run.py

# Or use the package command
linuxscan --interactive

# Or use Python module
python -m linuxscan --interactive
```

### Command Line Usage
```bash
# Basic scan
python run.py 192.168.1.1

# CIDR network scan
python run.py 192.168.1.0/24

# Multiple targets
python run.py 192.168.1.1,192.168.1.2,example.com

# Specific scan types
python run.py target.com --modules vulnerability_scanner,web_scanner

# Custom timeout and output
python run.py target.com --timeout 60 --output-format json --output-file results.json
```

### Python API
```python
from linuxscan import SecurityScanner

# Initialize scanner
scanner = SecurityScanner(timeout=30)

# Scan single target
results = await scanner.scan_target('192.168.1.1')

# Scan network
results = await scanner.scan_network(['192.168.1.0/24'])

# Access specific modules
crypto_results = await scanner.crypto_scanner.scan('example.com')
```

## 🎯 Available Scan Types

### Basic Scans
1. **Quick Scan** - Fast port and vulnerability scanning
2. **Advanced Scan** - Custom module selection with detailed configuration
3. **Mode Scan** - Interactive scan mode selection (9 modes available)
4. **Network Discovery** - Network topology and device discovery

### Security Assessments
5. **Vulnerability Assessment** - Comprehensive CVE-based vulnerability detection
6. **Web Application Scan** - OWASP-based web security testing
7. **SSH Security Audit** - SSH configuration and brute force testing
8. **Database Security Scan** - Database vulnerability assessment
9. **Compliance Audit** - Regulatory compliance checking (PCI, HIPAA, SOX, GDPR)
10. **Crypto Security Audit** - SSL/TLS and cryptographic analysis

### Advanced Analysis
11. **Memory Analysis** - Process analysis and memory forensics
12. **Steganography Detection** - Hidden data discovery
13. **Malware Analysis** - Malware detection and behavioral analysis
14. **Forensics Investigation** - Digital evidence collection
15. **Traffic Analysis** - Network traffic monitoring
16. **IoT Device Scan** - Smart device discovery and security assessment

### System & Utilities
17. **System Check** - Dependency verification and auto-installation
18. **View Scan History** - Previous scan results review
19. **Commands & Scripts Menu** - Available commands and usage examples
20. **Configuration** - Scanner settings and preferences
21. **Help & Documentation** - Built-in help system

## 🔧 Configuration

### Environment Variables
```bash
export LINUXSCAN_TIMEOUT=30
export LINUXSCAN_THREADS=20
export LINUXSCAN_OUTPUT_FORMAT=json
export LINUXSCAN_VERBOSE=true
```

### Configuration File
```json
{
  "timeout": 30,
  "max_threads": 50,
  "output_format": "json",
  "enable_auto_install": true,
  "default_modules": ["port_scanner", "vulnerability_scanner"],
  "compliance_frameworks": ["pci", "hipaa", "gdpr"]
}
```

## 📊 Output Formats

- **JSON** - Machine-readable structured data
- **CSV** - Spreadsheet-compatible format
- **HTML** - Web browser viewable reports
- **TXT** - Human-readable text format
- **XML** - Structured markup format
- **YAML** - Human-readable configuration format

## 🛡️ Security Features

### Real-time Monitoring
- Live scan progress with per-host results
- Automatic reverse DNS resolution
- Real-time vulnerability detection
- Interactive result display

### Advanced Detection
- Zero-day vulnerability patterns
- Behavioral malware analysis
- Cryptographic weakness detection
- IoT device fingerprinting
- Network anomaly detection

## 🚨 Usage Examples

### Network Security Assessment
```bash
# Comprehensive network scan
python run.py 192.168.1.0/24 --modules port_scanner,vulnerability_scanner,web_scanner

# Stealth reconnaissance
python run.py target.com --modules network_scanner --stealth

# Red team assessment
python run.py target.com --modules ssh_scanner,web_scanner,vulnerability_scanner --aggressive
```

### Compliance Auditing
```bash
# PCI DSS compliance check
python run.py target.com --modules config_scanner,crypto_scanner --compliance pci

# HIPAA compliance audit
python run.py target.com --modules vulnerability_scanner,config_scanner --compliance hipaa
```

### IoT Security Assessment
```bash
# IoT device discovery
python run.py 192.168.1.0/24 --modules iot_scanner

# Smart home security audit
python run.py 192.168.1.0/24 --modules iot_scanner,network_scanner --iot-focused
```

## 🔍 Advanced Features

### CIDR Range Scanning
- Automatic host discovery
- Live results for each responsive host
- Reverse DNS resolution
- Progress tracking per host

### Reverse DNS Integration
- Automatic hostname resolution
- Enhanced target identification
- Network mapping capabilities

### Module System
- Modular architecture
- Plugin-based scanning
- Custom module development
- API integration support

## 🛠️ Dependencies

### Required Dependencies
- Python 3.7+
- nmap
- python-nmap
- requests
- paramiko
- cryptography
- rich
- psutil
- click

### Optional Dependencies
- tcpdump (traffic analysis)
- tshark (packet analysis)
- volatility (memory analysis)
- steghide (steganography detection)
- openssl (SSL/TLS analysis)
- sqlmap (SQL injection testing)

### Auto-Installation
```bash
# Install missing dependencies automatically
python run.py --auto-install

# Check system dependencies
python run.py --check-deps
```

## 🔗 Integration

### API Integration
```python
import asyncio
from linuxscan import SecurityScanner

async def security_audit():
    scanner = SecurityScanner()
    
    # Network scan
    network_results = await scanner.scan_network(['192.168.1.0/24'])
    
    # Crypto audit
    crypto_results = await scanner.crypto_scanner.scan('example.com')
    
    # IoT discovery
    iot_results = await scanner.iot_scanner.scan('192.168.1.0/24')
    
    return {
        'network': network_results,
        'crypto': crypto_results,
        'iot': iot_results
    }

# Run audit
results = asyncio.run(security_audit())
```

### Webhook Integration
```bash
# Send results to webhook
python run.py target.com --webhook https://api.example.com/security-results

# Slack integration
python run.py target.com --slack-webhook https://hooks.slack.com/services/...
```

## 📋 Compliance Frameworks

Supported compliance frameworks:
- **PCI DSS** - Payment Card Industry Data Security Standard
- **HIPAA** - Health Insurance Portability and Accountability Act
- **SOX** - Sarbanes-Oxley Act
- **GDPR** - General Data Protection Regulation
- **NIST** - National Institute of Standards and Technology
- **ISO 27001** - Information Security Management
- **CIS** - Center for Internet Security
- **OWASP** - Open Web Application Security Project

## 🚀 Getting Started Guide

### Step 1: Installation
```bash
pip install linuxscan
```

### Step 2: Basic Usage
```bash
# Launch interactive mode
python run.py

# Or scan a target directly
python run.py 192.168.1.1
```

### Step 3: Explore Features
1. Try different scan modes
2. Use CIDR notation for network scans
3. Explore specialized scanners (IoT, crypto, memory)
4. Configure compliance frameworks
5. Export results in different formats

### Step 4: Integration
1. Use Python API for automation
2. Set up webhooks for notifications
3. Integrate with SIEM systems
4. Create custom scanning workflows

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🔒 Security

For security issues, please email security@linuxscan.com

## 📞 Support

- 📧 Email: support@linuxscan.com
- 💬 Discord: [LinuxScan Community](https://discord.gg/linuxscan)
- 📖 Documentation: [https://docs.linuxscan.com](https://docs.linuxscan.com)
- 🐛 Issues: [GitHub Issues](https://github.com/jomardyan/LinuxScan/issues)

---

**LinuxScan v2.0** - Advanced Security Scanner for the Modern Age 🛡️

### Command Line Interface

```bash
# Scan single IP
linuxscan 192.168.1.1

# Scan CIDR range
linuxscan 192.168.1.0/24

# Scan multiple targets with custom settings
linuxscan -t 192.168.1.1,10.0.0.1 --timeout 10 --max-workers 100

# Export results
linuxscan 192.168.1.1 -o results.json --format json

# Use configuration file
linuxscan -c config.json 192.168.1.1

# SSH Security Assessment
linuxscan 192.168.1.1 --modules ssh_scanner

# SSH Brute Force Testing (Red Team)
linuxscan 192.168.1.1 --modules ssh_scanner --ssh-brute-force

# Custom SSH credentials testing
linuxscan 192.168.1.1 --ssh-brute-force --ssh-usernames admin,root --ssh-passwords password,123456

# SSH Configuration Audit
linuxscan 192.168.1.1 --ssh-config-audit --ssh-credentials admin:password

# Interactive mode (original behavior)
linuxscan --interactive
```

### Python API

```python
import asyncio
from linuxscan import SecurityScanner

async def main():
    scanner = SecurityScanner()
    await scanner.scan_network(['192.168.1.1'])
    
    # Export results
    scanner.export_json('results.json')
    scanner.export_csv('results.csv')
    scanner.export_html('results.html')

asyncio.run(main())
```

### Configuration Management

```python
from linuxscan.config import ConfigManager

config = ConfigManager()
config.update_config(timeout=10, verbose=True)
config.save_config('my_config.json')
```

## 📋 CLI Options

```
usage: linuxscan [-h] [-t TARGET_LIST] [-f TARGET_FILE] [-c CONFIG_FILE] 
                 [-o OUTPUT_FILE] [--format {json,csv,html}] [--timeout TIMEOUT] 
                 [--max-workers MAX_WORKERS] [--interactive] [--no-banner] 
                 [-v] [--version] [targets ...]

Options:
  -h, --help            Show help message
  -t, --targets         Comma-separated list of targets
  -f, --file           File containing targets (one per line)
  -c, --config         Configuration file (JSON format)
  -o, --output         Output file for results
  --format             Output format: json, csv, html (default: json)
  --timeout            Connection timeout in seconds (default: 5)
  --max-workers        Maximum concurrent workers (default: 50)
  --interactive        Run in interactive mode
  --no-banner          Suppress banner display
  -v, --verbose        Enable verbose output
  --version            Show version information
```

## 🔒 Security Checks

The scanner performs the following security assessments:

1. **Port Scanning**: Identifies open ports and running services
2. **SSL/TLS Analysis**: 
   - Certificate expiration
   - Certificate details
   - Weak configurations
3. **SSH Security & Red Team Assessment**:
   - SSH service detection and banner grabbing
   - SSH protocol analysis and algorithm enumeration
   - Vulnerability scanning with CVE mapping
   - Brute force testing with common credentials
   - Configuration auditing and compliance checking
   - SSH key enumeration and analysis
   - Red team assessment capabilities
4. **Vulnerability Detection**:
   - Known CVEs
   - Service-specific vulnerabilities
   - Configuration weaknesses

## 📊 Export Options

Results can be exported in three formats:

- **JSON**: Complete scan data for programmatic processing
- **CSV**: Simplified tabular format for spreadsheet analysis
- **HTML**: Professional report with styling and detailed findings

## 🧪 Testing

Run the test suite:
```bash
pytest tests/
```

Run tests with coverage:
```bash
pytest tests/ --cov=linuxscan --cov-report=html
```

## 🛠️ Development

### Code Style
```bash
black linuxscan/
flake8 linuxscan/
```

### Type Checking
```bash
mypy linuxscan/
```

### Building Package
```bash
python -m build
```

## 📋 Requirements

- Python 3.7+
- Linux/macOS/Windows
- Root/Administrator privileges (recommended)
- Network connectivity to target hosts

## ⚠️ Security Considerations

- Always obtain proper authorization before scanning
- Use responsibly and ethically
- Be aware of network policies and regulations
- Scanner may trigger IDS/IPS alerts

## 🚀 Performance Tips

1. The scanner uses asynchronous operations for optimal performance
2. Adjust timeout values for slower networks
3. Use CIDR notation efficiently for large network scans
4. Consider breaking very large scans into smaller batches

## 🐛 Troubleshooting

**Permission Denied**: Run with sudo/root privileges
**Slow Scans**: Check network connectivity and firewall rules
**Missing Features**: Ensure nmap is installed for full functionality

## 📄 License

This tool is for educational and authorized security testing only. Users are responsible for complying with applicable laws and regulations.