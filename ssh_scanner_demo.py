#!/usr/bin/env python3
"""
SSH Scanner Demo - Demonstrates SSH security testing capabilities
"""

import json
import sys
from datetime import datetime

# Mock SSH scanner for demonstration
class MockSSHScanner:
    """Mock SSH Scanner for demonstration purposes"""
    
    def __init__(self):
        self.name = "ssh_scanner"
        self.common_usernames = [
            'root', 'admin', 'administrator', 'user', 'guest', 'oracle',
            'postgres', 'mysql', 'www-data', 'ubuntu', 'debian', 'centos',
            'pi', 'vagrant', 'docker', 'test', 'demo'
        ]
        self.common_passwords = [
            'password', '123456', 'admin', 'root', 'toor', 'pass', 'test',
            'guest', 'password123', 'admin123', 'root123', 'qwerty',
            'abc123', 'password1', 'admin1', 'root1', '12345678',
            'welcome', 'login', 'passw0rd', 'p@ssw0rd', 'changeme', 'default'
        ]
        
    def demo_ssh_scan(self, target):
        """Demonstrate SSH security scan results"""
        return {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'ssh_service': {
                'available': True,
                'version': 'OpenSSH_7.4',
                'port': 22,
                'banner': 'SSH-2.0-OpenSSH_7.4'
            },
            'vulnerabilities': [
                {
                    'type': 'version',
                    'severity': 'high',
                    'description': 'OpenSSH version 7.4 is outdated and may contain security vulnerabilities',
                    'cve': 'CVE-2016-6515, CVE-2016-8858',
                    'recommendation': 'Update OpenSSH to version 7.4 or newer'
                },
                {
                    'type': 'weak_encryption',
                    'severity': 'medium',
                    'description': 'Weak encryption algorithms supported: aes128-cbc, aes192-cbc',
                    'recommendation': 'Disable weak encryption algorithms in SSH configuration'
                }
            ],
            'protocol_analysis': {
                'kex_algorithms': [
                    'diffie-hellman-group1-sha1',
                    'diffie-hellman-group14-sha1',
                    'diffie-hellman-group14-sha256'
                ],
                'encryption_algorithms_c2s': [
                    'aes128-ctr',
                    'aes192-ctr', 
                    'aes256-ctr',
                    'aes128-cbc',
                    'aes192-cbc',
                    'aes256-cbc'
                ],
                'mac_algorithms_c2s': [
                    'hmac-sha1',
                    'hmac-sha2-256',
                    'hmac-sha2-512'
                ]
            },
            'recommendations': [
                "SSH service is running - ensure it's necessary for your use case",
                "Address high-severity SSH vulnerabilities immediately",
                "Use SSH key-based authentication instead of passwords",
                "Disable SSH root login (PermitRootLogin no)",
                "Change default SSH port from 22 to a non-standard port",
                "Implement SSH connection rate limiting",
                "Use SSH protocol version 2 only",
                "Configure SSH idle timeout settings",
                "Regularly update SSH software to latest version",
                "Monitor SSH logs for suspicious activity",
                "Use SSH connection whitelisting where possible",
                "Implement two-factor authentication for SSH access"
            ]
        }
    
    def demo_brute_force_results(self, target):
        """Demonstrate SSH brute force test results"""
        return {
            'target': target,
            'brute_force': {
                'enabled': True,
                'attempts': 25,
                'successful_logins': [
                    {
                        'username': 'admin',
                        'password': 'admin',
                        'timestamp': datetime.now().isoformat(),
                        'response_time': 0.15
                    }
                ],
                'failed_logins': [
                    {
                        'username': 'root',
                        'password': 'password',
                        'error': 'Authentication failed',
                        'response_time': 0.12
                    },
                    {
                        'username': 'admin',
                        'password': 'password',
                        'error': 'Authentication failed',
                        'response_time': 0.13
                    }
                ],
                'timing_analysis': {
                    'avg_response_time': 0.125,
                    'min_response_time': 0.12,
                    'max_response_time': 0.13,
                    'timing_variation': 0.01
                }
            },
            'recommendations': [
                "CRITICAL: Weak SSH credentials found - change passwords immediately",
                "Implement strong password policies and consider key-based authentication",
                "Consider implementing fail2ban or similar brute force protection"
            ]
        }

def main():
    print("=" * 80)
    print("SSH Security Scanner Demo - Red Team Assessment Tool")
    print("=" * 80)
    
    scanner = MockSSHScanner()
    
    print(f"\n[*] SSH Scanner initialized: {scanner.name}")
    print(f"[*] Common usernames loaded: {len(scanner.common_usernames)}")
    print(f"[*] Common passwords loaded: {len(scanner.common_passwords)}")
    
    # Demo basic SSH scan
    print("\n[+] Demonstrating SSH Security Scan")
    print("-" * 40)
    
    target = "192.168.1.100"
    results = scanner.demo_ssh_scan(target)
    
    print(f"Target: {results['target']}")
    print(f"SSH Service: {results['ssh_service']['available']}")
    print(f"Version: {results['ssh_service']['version']}")
    print(f"Vulnerabilities found: {len(results['vulnerabilities'])}")
    
    for vuln in results['vulnerabilities']:
        print(f"  - {vuln['type']} ({vuln['severity']}): {vuln['description']}")
    
    print(f"\nProtocol Analysis:")
    print(f"  - Key Exchange: {len(results['protocol_analysis']['kex_algorithms'])} algorithms")
    print(f"  - Encryption: {len(results['protocol_analysis']['encryption_algorithms_c2s'])} algorithms")
    print(f"  - MAC: {len(results['protocol_analysis']['mac_algorithms_c2s'])} algorithms")
    
    # Demo brute force results
    print("\n[+] Demonstrating SSH Brute Force Results")
    print("-" * 40)
    
    brute_results = scanner.demo_brute_force_results(target)
    bf_data = brute_results['brute_force']
    
    print(f"Brute Force Test: {'Enabled' if bf_data['enabled'] else 'Disabled'}")
    print(f"Total attempts: {bf_data['attempts']}")
    print(f"Successful logins: {len(bf_data['successful_logins'])}")
    print(f"Failed logins: {len(bf_data['failed_logins'])}")
    
    if bf_data['successful_logins']:
        print("\n[!] CRITICAL: Weak credentials found!")
        for login in bf_data['successful_logins']:
            print(f"  - {login['username']}:{login['password']} (response time: {login['response_time']}s)")
    
    print(f"\nTiming Analysis:")
    timing = bf_data['timing_analysis']
    print(f"  - Average response time: {timing['avg_response_time']}s")
    print(f"  - Min/Max response time: {timing['min_response_time']}s / {timing['max_response_time']}s")
    print(f"  - Timing variation: {timing['timing_variation']}s")
    
    # Show recommendations
    print("\n[+] Security Recommendations")
    print("-" * 40)
    
    all_recommendations = results['recommendations'] + brute_results['recommendations']
    for i, rec in enumerate(all_recommendations[:10], 1):
        print(f"{i:2d}. {rec}")
    
    if len(all_recommendations) > 10:
        print(f"    ... and {len(all_recommendations) - 10} more recommendations")
    
    print("\n[+] SSH Scanner Features")
    print("-" * 40)
    print("✓ SSH service detection and banner grabbing")
    print("✓ SSH protocol analysis and algorithm enumeration")
    print("✓ Vulnerability scanning with CVE mapping")
    print("✓ Brute force testing with common credentials")
    print("✓ Timing analysis for account lockout detection")
    print("✓ Configuration audit capabilities")
    print("✓ SSH key enumeration and analysis")
    print("✓ Comprehensive security recommendations")
    
    print("\n[+] Usage Examples")
    print("-" * 40)
    print("# Basic SSH scan")
    print("linuxscan 192.168.1.1 --modules ssh_scanner")
    print()
    print("# SSH scan with brute force testing")
    print("linuxscan 192.168.1.1 --modules ssh_scanner --ssh-brute-force")
    print()
    print("# Custom SSH credentials for brute force")
    print("linuxscan 192.168.1.1 --ssh-brute-force --ssh-usernames admin,root --ssh-passwords password,123456")
    print()
    print("# SSH configuration audit")
    print("linuxscan 192.168.1.1 --ssh-config-audit --ssh-credentials admin:password")
    print()
    print("# Export SSH scan results")
    print("linuxscan 192.168.1.1 --modules ssh_scanner --output ssh_results.json --format json")
    
    print("\n" + "=" * 80)
    print("SSH Security Scanner Demo Complete")
    print("=" * 80)

if __name__ == "__main__":
    main()