# Linux Security Scanner

A high-performance, professional security scanning tool for remote Linux servers with powerful capabilities and an intuitive console UI/UX.

## Features

- **High-Performance Scanning**: Asynchronous operations for fast, concurrent scanning
- **Comprehensive Security Assessment**:
  - Port scanning with service detection
  - SSL certificate validation
  - SSH configuration analysis
  - Vulnerability detection
  - OS fingerprinting
- **Professional Console UI**: Rich, interactive console interface with real-time progress
- **Batch Scanning**: Support for CIDR notation for network-wide scans
- **Security Scoring**: Automated security assessment with scoring and recommendations
- **Multiple Export Formats**: JSON, CSV, and HTML report generation

## Installation

1. Clone or download the repository
2. Run the setup script:
   ```bash
   chmod +x setup.sh
   ./setup.sh
   ```

Or manually install dependencies:
```bash
pip3 install -r requirements.txt
sudo apt-get install nmap  # For Debian/Ubuntu
```

## Usage

Run the scanner with root privileges for best results:
```bash
sudo python3 linux_security_scanner.py
```

### Examples

1. **Single IP scan**:
   ```
   λ 192.168.1.100
   ```

2. **Multiple IPs**:
   ```
   λ 192.168.1.100, 192.168.1.101, 192.168.1.102
   ```

3. **CIDR range scan**:
   ```
   λ 192.168.1.0/24
   ```

4. **Mixed targets**:
   ```
   λ 192.168.1.100, 10.0.0.0/28, 172.16.0.1
   ```

## Security Checks

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

## Export Options

Results can be exported in three formats:

- **JSON**: Complete scan data for programmatic processing
- **CSV**: Simplified tabular format for spreadsheet analysis
- **HTML**: Professional report with styling and detailed findings

## Requirements

- Python 3.7+
- Linux/macOS/Windows
- Root/Administrator privileges (recommended)
- Network connectivity to target hosts

## Security Considerations

- Always obtain proper authorization before scanning
- Use responsibly and ethically
- Be aware of network policies and regulations
- Scanner may trigger IDS/IPS alerts

## Performance Tips

1. The scanner uses asynchronous operations for optimal performance
2. Adjust timeout values for slower networks
3. Use CIDR notation efficiently for large network scans
4. Consider breaking very large scans into smaller batches

## Troubleshooting

**Permission Denied**: Run with sudo/root privileges
**Slow Scans**: Check network connectivity and firewall rules
**Missing Features**: Ensure nmap is installed for full functionality

## License

This tool is for educational and authorized security testing only. Users are responsible for complying with applicable laws and regulations.