# Linux Security Scanner

A high-performance, professional security scanning tool for remote Linux servers with powerful capabilities and an intuitive console UI/UX. Now available as a Python package with enhanced CLI and API features.

## 🚀 Features

- **High-Performance Scanning**: Asynchronous operations for fast, concurrent scanning
- **Comprehensive Security Assessment**:
  - Port scanning with service detection
  - SSL certificate validation
  - SSH configuration analysis
  - Vulnerability detection
  - OS fingerprinting
- **Professional Console UI**: Rich, interactive console interface with real-time progress
- **Command-Line Interface**: Full CLI support with non-interactive mode
- **Python API**: Programmatic access for integration
- **Configuration Management**: JSON-based configuration with defaults
- **Batch Scanning**: Support for CIDR notation for network-wide scans
- **Security Scoring**: Automated security assessment with scoring and recommendations
- **Multiple Export Formats**: JSON, CSV, and HTML report generation
- **Test Suite**: Comprehensive testing with pytest
- **PyPI Ready**: Packaged for easy installation via pip

## 📦 Installation

### From PyPI (Recommended)
```bash
pip install linuxscan
```

### From Source
```bash
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

## 🔧 Quick Start

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
3. **SSH Security**:
   - Protocol version checks
   - Authentication methods
   - Weak algorithm detection
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