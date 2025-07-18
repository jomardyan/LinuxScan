# SSH Security Scanner Implementation

## Overview

The SSH Security Scanner is a comprehensive red team assessment tool that provides extensive SSH security testing capabilities. This implementation adds professional-grade SSH security assessment features to the LinuxScan project.

## Features Implemented

### 1. SSH Service Detection
- **Port 22 availability checking**
- **SSH banner grabbing** to identify service versions
- **SSH protocol version detection**
- **Service availability validation**

### 2. SSH Protocol Analysis
- **Key exchange algorithm enumeration**
- **Encryption algorithm detection** (client-to-server and server-to-client)
- **MAC algorithm identification**
- **Host key algorithm discovery**
- **Compression algorithm analysis**

### 3. Vulnerability Assessment
- **CVE-based vulnerability scanning** for known SSH vulnerabilities
- **Weak algorithm detection**:
  - Weak encryption algorithms (arcfour, DES, 3DES-CBC, etc.)
  - Weak MAC algorithms (HMAC-MD5, HMAC-SHA1-96, etc.)
  - Weak key exchange algorithms (DH-group1-SHA1, etc.)
- **SSH version vulnerability mapping**
- **Compression vulnerability analysis**

### 4. Brute Force Testing (Red Team Mode)
- **Common credential testing** with 30+ usernames and 25+ passwords
- **Custom credential list support**
- **Rate limiting** to avoid detection
- **Timing analysis** for account lockout detection
- **Successful login tracking**
- **Failed attempt logging**
- **Response time analysis**

### 5. Configuration Auditing
- **SSH configuration file analysis** (when credentials are provided)
- **Insecure setting detection**:
  - PermitRootLogin enabled
  - Password authentication enabled
  - Empty password authentication
  - X11 forwarding enabled
  - TCP forwarding enabled
  - High MaxAuthTries values
- **Security recommendation generation**

### 6. SSH Key Analysis
- **SSH key enumeration** (when accessible)
- **Key type identification**
- **Key strength assessment**
- **Authorized keys analysis**

## Technical Implementation

### Core Components

#### SSHScanner Class
```python
class SSHScanner(BaseScannerModule):
    def __init__(self, timeout: int = 30):
        # Initialize with common credentials and vulnerability patterns
        
    async def scan(self, target: str, **kwargs) -> Dict[str, Any]:
        # Main scan orchestration method
        
    async def _check_ssh_service(self, target: str) -> Dict[str, Any]:
        # SSH service detection and banner grabbing
        
    async def _analyze_ssh_protocol(self, target: str) -> Dict[str, Any]:
        # Protocol analysis using paramiko
        
    async def _check_ssh_vulnerabilities(self, target: str, ssh_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        # Vulnerability assessment
        
    async def _perform_brute_force_test(self, target: str, kwargs: Dict[str, Any]) -> Dict[str, Any]:
        # Brute force testing implementation
        
    async def _audit_ssh_configuration(self, target: str, kwargs: Dict[str, Any]) -> Dict[str, Any]:
        # Configuration audit (requires credentials)
```

#### Vulnerability Patterns
```python
self.vulnerability_patterns = {
    'weak_encryption': [
        'arcfour', 'arcfour128', 'arcfour256', 'des', '3des-cbc',
        'blowfish-cbc', 'cast128-cbc', 'aes128-cbc', 'aes192-cbc',
        'aes256-cbc', 'rijndael-cbc@lysator.liu.se'
    ],
    'weak_mac': [
        'hmac-md5', 'hmac-md5-96', 'hmac-sha1-96', 'hmac-ripemd160',
        'hmac-ripemd160@openssh.com', 'umac-64@openssh.com'
    ],
    'weak_kex': [
        'diffie-hellman-group1-sha1', 'diffie-hellman-group14-sha1',
        'diffie-hellman-group-exchange-sha1', 'rsa1024-sha1',
        'gss-group1-sha1-*', 'gss-group14-sha1-*', 'gss-gex-sha1-*'
    ]
}
```

## CLI Integration

### New Command Line Options

```bash
# SSH-specific options added to enhanced_cli.py
--ssh-brute-force          # Enable SSH brute force testing
--ssh-usernames TEXT       # Custom username list
--ssh-passwords TEXT       # Custom password list
--ssh-max-attempts INT     # Maximum brute force attempts
--ssh-delay FLOAT          # Delay between attempts
--ssh-config-audit         # Enable configuration audit
--ssh-credentials TEXT     # Credentials for config audit
```

### Usage Examples

#### Basic SSH Security Scan
```bash
linuxscan 192.168.1.1 --modules ssh_scanner
```

#### SSH Brute Force Testing
```bash
linuxscan 192.168.1.1 --modules ssh_scanner --ssh-brute-force
```

#### Custom Credentials
```bash
linuxscan 192.168.1.1 --ssh-brute-force \
  --ssh-usernames admin,root,oracle \
  --ssh-passwords password,123456,admin
```

#### Configuration Audit
```bash
linuxscan 192.168.1.1 --ssh-config-audit \
  --ssh-credentials admin:password
```

#### Rate-Limited Testing
```bash
linuxscan 192.168.1.1 --ssh-brute-force \
  --ssh-max-attempts 50 \
  --ssh-delay 2.0
```

## Security Recommendations Generated

The SSH scanner generates comprehensive security recommendations:

1. **Critical Issues**:
   - Weak SSH credentials detected
   - Outdated SSH versions
   - Dangerous configuration settings

2. **High Priority**:
   - Weak encryption algorithms
   - Weak key exchange methods
   - Root login enabled

3. **Medium Priority**:
   - Weak MAC algorithms
   - Compression enabled
   - Default port usage

4. **Best Practices**:
   - Key-based authentication
   - Connection rate limiting
   - Log monitoring
   - Two-factor authentication

## Integration with LinuxScan Framework

### Module Registration
```python
# In enhanced_scanner.py
from .modules.ssh_scanner import SSHScanner
self.ssh_scanner = SSHScanner(timeout=timeout)
scanner_registry.register('ssh_scanner', SSHScanner)
```

### Scan Integration
```python
# SSH scanning integrated into scan_host method
if 'ssh_scanner' in scan_modules and 22 in open_ports:
    ssh_results = await self.ssh_scanner.scan(host, **kwargs)
    host_results['scan_results']['ssh_scan'] = ssh_results
```

## Testing Implementation

### Test Coverage
- **Unit tests** for all SSH scanner methods
- **Mock testing** for paramiko interactions
- **Integration tests** with the scanner framework
- **CLI option testing**

### Test Files
- `tests/test_ssh_scanner.py` - Comprehensive SSH scanner tests
- `tests/test_modules.py` - Updated with SSH scanner registration tests

## Security Considerations

### Ethical Usage
This SSH scanner is designed for:
- **Authorized security assessments**
- **Red team exercises**
- **Compliance auditing**
- **Security research**

### Rate Limiting
- Built-in delays between attempts
- Configurable attempt limits
- Timing analysis to detect countermeasures

### Stealth Features
- Customizable timing patterns
- Connection rate limiting
- Error handling to avoid detection

## Dependencies

### Required Libraries
- `paramiko>=3.4.0` - SSH protocol implementation
- `socket` - Network connectivity
- `asyncio` - Asynchronous operations
- `datetime` - Timestamp handling

### Optional Dependencies
- `nmap` - Enhanced port scanning
- `scapy` - Network packet analysis

## Performance Characteristics

### Scalability
- **Concurrent scanning** support
- **Async/await** implementation
- **Configurable worker limits**
- **Memory-efficient** credential testing

### Timing
- **Average scan time**: 10-30 seconds per host
- **Brute force time**: Depends on credentials and delay settings
- **Protocol analysis**: 1-3 seconds per host

## Output Formats

### JSON Output
```json
{
  "target": "192.168.1.1",
  "ssh_service": {
    "available": true,
    "version": "OpenSSH_7.4",
    "port": 22
  },
  "vulnerabilities": [
    {
      "type": "version",
      "severity": "high",
      "description": "OpenSSH version 7.4 is outdated",
      "cve": "CVE-2016-6515",
      "recommendation": "Update OpenSSH to version 7.4 or newer"
    }
  ],
  "brute_force": {
    "enabled": true,
    "attempts": 25,
    "successful_logins": [
      {
        "username": "admin",
        "password": "admin",
        "response_time": 0.15
      }
    ]
  },
  "recommendations": [
    "Use SSH key-based authentication",
    "Disable SSH root login",
    "Change default SSH port"
  ]
}
```

## Future Enhancements

### Planned Features
1. **SSH key strength analysis**
2. **Certificate-based authentication testing**
3. **SSH tunnel enumeration**
4. **Advanced timing attack detection**
5. **Machine learning for credential prediction**

### Integration Opportunities
1. **SIEM integration** for log correlation
2. **Vulnerability scanner integration**
3. **Compliance framework mapping**
4. **Automated remediation suggestions**

## Red Team Assessment Capabilities

The SSH scanner provides comprehensive red team assessment capabilities:

### Reconnaissance
- Service version identification
- Protocol capability enumeration
- Configuration weakness detection

### Credential Testing
- Dictionary-based attacks
- Common credential testing
- Timing-based analysis

### Vulnerability Exploitation
- Known vulnerability identification
- Weak algorithm detection
- Configuration misassessment

### Post-Exploitation
- SSH key enumeration
- Configuration file analysis
- Privilege escalation identification

This implementation transforms LinuxScan into a professional-grade SSH security assessment tool suitable for red team operations, security auditing, and compliance verification.