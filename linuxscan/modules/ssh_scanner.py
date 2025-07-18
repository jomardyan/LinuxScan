#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Author: Hayk Jomardyan
#
"""
SSH Security Scanner for red team testing and security assessment
"""

import asyncio
import socket
import ssl
import re
# Removed unused import: random
import time
from typing import Dict, List, Any, Tuple, Optional
from datetime import datetime
import paramiko
from .base_scanner import BaseScannerModule


class SSHScanner(BaseScannerModule):
    """SSH Security Scanner for red team testing and security assessment"""
    
    def __init__(self, timeout: int = 30):
        super().__init__("ssh_scanner", timeout)
        
        # Common SSH usernames for brute force testing
        self.common_usernames = [
            'root', 'admin', 'administrator', 'user', 'guest', 'oracle',
            'postgres', 'mysql', 'www-data', 'nobody', 'daemon', 'bin',
            'sys', 'sync', 'games', 'man', 'lp', 'mail', 'news', 'uucp',
            'proxy', 'www', 'backup', 'list', 'irc', 'gnats', 'ubuntu',
            'debian', 'centos', 'redhat', 'fedora', 'suse', 'kali',
            'pi', 'vagrant', 'docker', 'test', 'demo', 'service'
        ]
        
        # Common SSH passwords for brute force testing
        self.common_passwords = [
            'password', '123456', 'admin', 'root', 'toor', 'pass', 'test',
            'guest', 'password123', 'admin123', 'root123', 'qwerty',
            'abc123', 'password1', 'admin1', 'root1', '12345678', '1234567890',
            'welcome', 'login', 'passw0rd', 'p@ssw0rd', 'p@ssword',
            'changeme', 'default', 'letmein', 'secret', 'manager',
            # Default passwords for specific services
            'oracle', 'postgres', 'mysql', 'redis', 'mongodb',
            # Weak passwords commonly found
            'a', 'aa', 'aaa', '1', '11', '111', 'password!', 'Password1',
            # Service-specific defaults
            'raspberry', 'ubnt', 'vagrant', 'docker', 'kali'
        ]
        
        # SSH vulnerability patterns
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
        
        # SSH configuration audit checks
        self.config_checks = {
            'permit_root_login': ['yes', 'without-password'],
            'password_authentication': ['yes'],
            'permit_empty_passwords': ['yes'],
            'challenge_response_authentication': ['yes'],
            'x11_forwarding': ['yes'],
            'allow_tcp_forwarding': ['yes'],
            'gateway_ports': ['yes'],
            'permit_tunnel': ['yes'],
            'max_auth_tries': [str(i) for i in range(10, 100)],  # High values
            'client_alive_interval': ['0'],
            'compression': ['yes'],
            'use_pam': ['yes'],
            'kbd_interactive_authentication': ['yes']
        }
    
    async def scan(self, target: str, **kwargs) -> Dict[str, Any]:
        """Perform comprehensive SSH security scan"""
        self.log_scan_start(target)
        
        results = {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'ssh_service': {},
            'vulnerabilities': [],
            'brute_force': {},
            'configuration_audit': {},
            'protocol_analysis': {},
            'recommendations': []
        }
        
        try:
            # Check if SSH service is running
            ssh_info = await self._check_ssh_service(target)
            results['ssh_service'] = ssh_info
            
            if not ssh_info.get('available', False):
                results['status'] = 'SSH service not available'
                return results
            
            # Perform SSH protocol analysis
            protocol_results = await self._analyze_ssh_protocol(target)
            results['protocol_analysis'] = protocol_results
            
            # Check for SSH vulnerabilities
            vuln_results = await self._check_ssh_vulnerabilities(target, ssh_info)
            results['vulnerabilities'] = vuln_results
            
            # Perform brute force testing (if enabled)
            if kwargs.get('brute_force', False):
                brute_results = await self._perform_brute_force_test(target, kwargs)
                results['brute_force'] = brute_results
            
            # Configuration audit (if accessible)
            if kwargs.get('config_audit', False):
                config_results = await self._audit_ssh_configuration(target, kwargs)
                results['configuration_audit'] = config_results
            
            # Generate security recommendations
            recommendations = self._generate_recommendations(results)
            results['recommendations'] = recommendations
            
        except Exception as e:
            self.logger.error(f"SSH scan error for {target}: {str(e)}")
            results['error'] = str(e)
        
        self.log_scan_end(target)
        return results
    
    async def _check_ssh_service(self, target: str) -> Dict[str, Any]:
        """Check if SSH service is available and gather basic info"""
        try:
            # Try to connect to SSH port
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((target, 22))
            sock.close()
            
            if result != 0:
                return {'available': False, 'reason': 'Port 22 not open'}
            
            # Get SSH banner
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            try:
                # Just get the banner without authentication
                transport = paramiko.Transport((target, 22))
                transport.start_client(timeout=self.timeout)
                server_version = transport.remote_version
                transport.close()
                
                return {
                    'available': True,
                    'version': server_version,
                    'port': 22,
                    'banner': server_version
                }
            except Exception as e:
                return {
                    'available': True,
                    'version': 'Unknown',
                    'port': 22,
                    'error': str(e)
                }
                
        except Exception as e:
            return {'available': False, 'error': str(e)}
    
    async def _analyze_ssh_protocol(self, target: str) -> Dict[str, Any]:
        """Analyze SSH protocol configuration and supported algorithms"""
        try:
            transport = paramiko.Transport((target, 22))
            transport.start_client(timeout=self.timeout)
            
            # Get supported algorithms
            kex_algorithms = transport.kex_info.get('kex_algorithms', [])
            server_host_key_algorithms = transport.kex_info.get('server_host_key_algorithms', [])
            encryption_algorithms_client_to_server = transport.kex_info.get('encryption_algorithms_client_to_server', [])
            encryption_algorithms_server_to_client = transport.kex_info.get('encryption_algorithms_server_to_client', [])
            mac_algorithms_client_to_server = transport.kex_info.get('mac_algorithms_client_to_server', [])
            mac_algorithms_server_to_client = transport.kex_info.get('mac_algorithms_server_to_client', [])
            compression_algorithms_client_to_server = transport.kex_info.get('compression_algorithms_client_to_server', [])
            compression_algorithms_server_to_client = transport.kex_info.get('compression_algorithms_server_to_client', [])
            
            transport.close()
            
            return {
                'kex_algorithms': kex_algorithms,
                'host_key_algorithms': server_host_key_algorithms,
                'encryption_algorithms_c2s': encryption_algorithms_client_to_server,
                'encryption_algorithms_s2c': encryption_algorithms_server_to_client,
                'mac_algorithms_c2s': mac_algorithms_client_to_server,
                'mac_algorithms_s2c': mac_algorithms_server_to_client,
                'compression_algorithms_c2s': compression_algorithms_client_to_server,
                'compression_algorithms_s2c': compression_algorithms_server_to_client
            }
            
        except Exception as e:
            return {'error': str(e)}
    
    async def _check_ssh_vulnerabilities(self, target: str, ssh_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for SSH vulnerabilities"""
        vulnerabilities = []
        
        try:
            # Check SSH version for known vulnerabilities
            version = ssh_info.get('version', '').lower()
            
            # Check for old SSH versions
            if 'openssh' in version:
                version_match = re.search(r'openssh[_-](\d+)\.(\d+)', version)
                if version_match:
                    major, minor = int(version_match.group(1)), int(version_match.group(2))
                    
                    if major < 7 or (major == 7 and minor < 4):
                        vulnerabilities.append({
                            'type': 'version',
                            'severity': 'high',
                            'description': f'OpenSSH version {major}.{minor} is outdated and may contain security vulnerabilities',
                            'cve': 'CVE-2016-6515, CVE-2016-8858',
                            'recommendation': 'Update OpenSSH to version 7.4 or newer'
                        })
            
            # Check protocol analysis for weak algorithms
            protocol_info = await self._analyze_ssh_protocol(target)
            
            # Check for weak encryption algorithms
            for direction in ['encryption_algorithms_c2s', 'encryption_algorithms_s2c']:
                algorithms = protocol_info.get(direction, [])
                weak_algos = [algo for algo in algorithms if algo in self.vulnerability_patterns['weak_encryption']]
                if weak_algos:
                    vulnerabilities.append({
                        'type': 'weak_encryption',
                        'severity': 'medium',
                        'description': f'Weak encryption algorithms supported: {", ".join(weak_algos)}',
                        'recommendation': 'Disable weak encryption algorithms in SSH configuration'
                    })
            
            # Check for weak MAC algorithms
            for direction in ['mac_algorithms_c2s', 'mac_algorithms_s2c']:
                algorithms = protocol_info.get(direction, [])
                weak_algos = [algo for algo in algorithms if algo in self.vulnerability_patterns['weak_mac']]
                if weak_algos:
                    vulnerabilities.append({
                        'type': 'weak_mac',
                        'severity': 'medium',
                        'description': f'Weak MAC algorithms supported: {", ".join(weak_algos)}',
                        'recommendation': 'Disable weak MAC algorithms in SSH configuration'
                    })
            
            # Check for weak key exchange algorithms
            kex_algorithms = protocol_info.get('kex_algorithms', [])
            weak_kex = [algo for algo in kex_algorithms if algo in self.vulnerability_patterns['weak_kex']]
            if weak_kex:
                vulnerabilities.append({
                    'type': 'weak_kex',
                    'severity': 'high',
                    'description': f'Weak key exchange algorithms supported: {", ".join(weak_kex)}',
                    'recommendation': 'Disable weak key exchange algorithms in SSH configuration'
                })
            
            # Check for compression vulnerability
            compression_algos = protocol_info.get('compression_algorithms_c2s', [])
            if 'zlib' in compression_algos or 'zlib@openssh.com' in compression_algos:
                vulnerabilities.append({
                    'type': 'compression',
                    'severity': 'low',
                    'description': 'SSH compression is enabled which may allow information disclosure',
                    'recommendation': 'Disable SSH compression or use zlib@openssh.com with delayed compression'
                })
            
        except Exception as e:
            vulnerabilities.append({
                'type': 'scan_error',
                'severity': 'info',
                'description': f'Error during vulnerability scan: {str(e)}'
            })
        
        return vulnerabilities
    
    async def _perform_brute_force_test(self, target: str, kwargs: Dict[str, Any]) -> Dict[str, Any]:
        """Perform SSH brute force testing"""
        results = {
            'enabled': True,
            'attempts': 0,
            'successful_logins': [],
            'failed_logins': [],
            'locked_accounts': [],
            'timing_analysis': {}
        }
        
        max_attempts = kwargs.get('max_attempts', 100)
        usernames = kwargs.get('usernames', self.common_usernames[:10])  # Limit to first 10
        passwords = kwargs.get('passwords', self.common_passwords[:10])  # Limit to first 10
        
        # Rate limiting to avoid detection
        delay_between_attempts = kwargs.get('delay', 1)
        
        try:
            for username in usernames:
                for password in passwords:
                    if results['attempts'] >= max_attempts:
                        break
                    
                    results['attempts'] += 1
                    
                    # Attempt SSH login
                    login_result = await self._attempt_ssh_login(target, username, password)
                    
                    if login_result['success']:
                        results['successful_logins'].append({
                            'username': username,
                            'password': password,
                            'timestamp': datetime.now().isoformat(),
                            'response_time': login_result['response_time']
                        })
                        self.logger.warning(f"Successful SSH login: {username}:{password}")
                    else:
                        results['failed_logins'].append({
                            'username': username,
                            'password': password,
                            'error': login_result['error'],
                            'response_time': login_result['response_time']
                        })
                    
                    # Rate limiting
                    if delay_between_attempts > 0:
                        await asyncio.sleep(delay_between_attempts)
                
                if results['attempts'] >= max_attempts:
                    break
            
            # Analyze timing patterns
            if results['failed_logins']:
                response_times = [login['response_time'] for login in results['failed_logins']]
                results['timing_analysis'] = {
                    'avg_response_time': sum(response_times) / len(response_times),
                    'min_response_time': min(response_times),
                    'max_response_time': max(response_times),
                    'timing_variation': max(response_times) - min(response_times)
                }
            
        except Exception as e:
            results['error'] = str(e)
        
        return results
    
    async def _attempt_ssh_login(self, target: str, username: str, password: str) -> Dict[str, Any]:
        """Attempt SSH login with given credentials"""
        start_time = time.time()
        
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            client.connect(
                target,
                username=username,
                password=password,
                timeout=self.timeout,
                allow_agent=False,
                look_for_keys=False
            )
            
            # If we get here, login was successful
            client.close()
            response_time = time.time() - start_time
            
            return {
                'success': True,
                'response_time': response_time,
                'error': None
            }
            
        except paramiko.AuthenticationException:
            response_time = time.time() - start_time
            return {
                'success': False,
                'response_time': response_time,
                'error': 'Authentication failed'
            }
        except paramiko.SSHException as e:
            response_time = time.time() - start_time
            return {
                'success': False,
                'response_time': response_time,
                'error': f'SSH error: {str(e)}'
            }
        except Exception as e:
            response_time = time.time() - start_time
            return {
                'success': False,
                'response_time': response_time,
                'error': f'Connection error: {str(e)}'
            }
    
    async def _audit_ssh_configuration(self, target: str, kwargs: Dict[str, Any]) -> Dict[str, Any]:
        """Audit SSH configuration for security issues"""
        results = {
            'enabled': True,
            'accessible': False,
            'config_issues': [],
            'secure_settings': [],
            'recommendations': []
        }
        
        # This would require authentication to access the SSH config
        # For now, we'll provide general recommendations based on common misconfigurations
        
        try:
            # Check if we have credentials to access the system
            credentials = kwargs.get('credentials', {})
            if not credentials:
                results['accessible'] = False
                results['message'] = 'SSH configuration audit requires valid credentials'
                return results
            
            # Attempt to connect and check configuration
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            client.connect(
                target,
                username=credentials.get('username'),
                password=credentials.get('password'),
                timeout=self.timeout
            )
            
            # Check SSH daemon configuration
            stdin, stdout, stderr = client.exec_command('cat /etc/ssh/sshd_config')
            config_content = stdout.read().decode()
            
            # Parse configuration and check for security issues
            config_lines = config_content.split('\n')
            for line in config_lines:
                line = line.strip()
                if line.startswith('#') or not line:
                    continue
                
                parts = line.split()
                if len(parts) >= 2:
                    setting = parts[0].lower()
                    value = parts[1].lower()
                    
                    if setting in self.config_checks:
                        if value in self.config_checks[setting]:
                            results['config_issues'].append({
                                'setting': setting,
                                'current_value': value,
                                'severity': 'medium',
                                'description': f'Insecure SSH configuration: {setting} = {value}',
                                'recommendation': f'Consider changing {setting} to a more secure value'
                            })
                        else:
                            results['secure_settings'].append({
                                'setting': setting,
                                'value': value
                            })
            
            client.close()
            results['accessible'] = True
            
        except Exception as e:
            results['error'] = str(e)
        
        return results
    
    def _generate_recommendations(self, results: Dict[str, Any]) -> List[str]:
        """Generate security recommendations based on scan results"""
        recommendations = []
        
        # Check SSH service availability
        if results['ssh_service'].get('available', False):
            recommendations.append("SSH service is running - ensure it's necessary for your use case")
        
        # Check vulnerabilities
        vulnerabilities = results.get('vulnerabilities', [])
        if vulnerabilities:
            high_severity = [v for v in vulnerabilities if v.get('severity') == 'high']
            if high_severity:
                recommendations.append("Address high-severity SSH vulnerabilities immediately")
            
            medium_severity = [v for v in vulnerabilities if v.get('severity') == 'medium']
            if medium_severity:
                recommendations.append("Address medium-severity SSH vulnerabilities")
        
        # Check brute force results
        brute_force = results.get('brute_force', {})
        if brute_force.get('successful_logins'):
            recommendations.append("CRITICAL: Weak SSH credentials found - change passwords immediately")
            recommendations.append("Implement strong password policies and consider key-based authentication")
        
        if brute_force.get('failed_logins'):
            attempts = len(brute_force['failed_logins'])
            if attempts > 50:
                recommendations.append("Consider implementing fail2ban or similar brute force protection")
        
        # General SSH security recommendations
        recommendations.extend([
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
        ])
        
        return recommendations
    
    async def scan_ssh_keys(self, target: str, **kwargs) -> Dict[str, Any]:
        """Scan for SSH keys and key-based vulnerabilities"""
        results = {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'key_enumeration': {},
            'key_vulnerabilities': [],
            'recommendations': []
        }
        
        try:
            # Check for common SSH key locations
            key_locations = [
                '/root/.ssh/id_rsa',
                '/root/.ssh/id_dsa',
                '/root/.ssh/id_ecdsa',
                '/root/.ssh/id_ed25519',
                '/home/*/.ssh/id_rsa',
                '/home/*/.ssh/id_dsa',
                '/home/*/.ssh/id_ecdsa',
                '/home/*/.ssh/id_ed25519'
            ]
            
            # Check authorized_keys files
            authorized_keys_locations = [
                '/root/.ssh/authorized_keys',
                '/home/*/.ssh/authorized_keys'
            ]
            
            # This would require authenticated access to check key files
            credentials = kwargs.get('credentials', {})
            if credentials:
                # Implementation would go here for authenticated key scanning
                pass
            
            results['key_enumeration'] = {
                'accessible': False,
                'message': 'SSH key enumeration requires authenticated access'
            }
            
        except Exception as e:
            results['error'] = str(e)
        
        return results