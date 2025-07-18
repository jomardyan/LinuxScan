# Linux Security Scanner Installation Guide

## Installation Options

### Option 1: Install from PyPI (Recommended)
```bash
pip install linuxscan
```

### Option 2: Install from Source
```bash
git clone https://github.com/jomardyan/LinuxScan.git
cd LinuxScan
pip install -e .
```

### Option 3: Development Installation
```bash
git clone https://github.com/jomardyan/LinuxScan.git
cd LinuxScan
pip install -e ".[dev]"
```

## Quick Start

### Command Line Usage
```bash
# Scan single IP
linuxscan 192.168.1.1

# Scan CIDR range
linuxscan 192.168.1.0/24

# Scan multiple targets
linuxscan -t 192.168.1.1,10.0.0.1,172.16.0.1

# Scan with custom timeout and workers
linuxscan --timeout 10 --max-workers 100 192.168.1.1

# Export results to file
linuxscan -o results.json --format json 192.168.1.1

# Use configuration file
linuxscan -c config.json 192.168.1.1

# Interactive mode
linuxscan --interactive
```

### Python API Usage
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

# Create config manager
config = ConfigManager()

# Update settings
config.update_config(
    timeout=10,
    max_workers=100,
    verbose=True
)

# Save configuration
config.save_config('my_config.json')

# Create sample config file
config.create_sample_config('sample_config.json')
```

## Configuration File Format

```json
{
  "timeout": 5,
  "max_workers": 50,
  "max_ports": 1000,
  "enable_ssl_check": true,
  "enable_ssh_check": true,
  "enable_vuln_check": true,
  "output_format": "json",
  "verbose": false,
  "save_raw_output": false,
  "custom_ports": [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3389],
  "excluded_ports": []
}
```

## Development

### Running Tests
```bash
pytest tests/
```

### Code Formatting
```bash
black linuxscan/
```

### Type Checking
```bash
mypy linuxscan/
```

### Building Package
```bash
python -m build
```

## Features

- ✅ High-performance asynchronous scanning
- ✅ Port scanning and service detection
- ✅ SSL certificate validation
- ✅ SSH security assessment
- ✅ Security scoring and recommendations
- ✅ Multiple export formats (JSON, CSV, HTML)
- ✅ Command-line interface
- ✅ Python API
- ✅ Configuration management
- ✅ Comprehensive test suite
- ✅ Ready for PyPI distribution