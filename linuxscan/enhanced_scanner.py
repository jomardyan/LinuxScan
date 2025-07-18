#!/usr/bin/env python3
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
Professional Linux Security Scanner
A high-performance security scanning tool for remote Linux servers
Author: Security Scanner Team
Version: 1.0.0
"""

import asyncio
import aiohttp
import socket
import ssl
import json
import csv
import ipaddress
import time
import sys
import os
from datetime import datetime
# Removed unused imports: ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Optional, Tuple
import subprocess
import platform
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeRemainingColumn
from rich.panel import Panel
from rich.layout import Layout
from rich.live import Live
from rich.text import Text
from rich import box
from rich.prompt import Prompt, Confirm
import click
import nmap
import paramiko
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import warnings
warnings.filterwarnings("ignore")

# Import enhanced components
try:
    from .logging_config import get_logger, LoggedOperation
    from .performance_monitor import get_performance_monitor, monitor_async_performance
    from .dependency_injection import get_container, inject_decorator
    from .config import get_config_manager, ConfigError
except ImportError:
    # Fallback for standalone usage
    import logging
    def get_logger(name: str) -> logging.Logger:
        return logging.getLogger(name)
    
    class LoggedOperation:
        def __init__(self, operation_name: str, target: str, logger=None):
            self.operation_name = operation_name
            self.target = target
            self.logger = logger or logging.getLogger()
        
        def __enter__(self):
            return self
        
        def __exit__(self, exc_type, exc_val, exc_tb):
            return False
    
    def monitor_async_performance(func):
        return func
    
    def inject_decorator(func):
        return func
    
    def get_performance_monitor():
        return None
    
    def get_config_manager():
        return None

# Import security scanning modules
try:
    from .modules.port_scanner import PortScanner
    from .modules.vulnerability_scanner import VulnerabilityScanner
    from .modules.network_scanner import NetworkScanner
    from .modules.web_scanner import WebScanner
    from .modules.forensics_scanner import ForensicsScanner
    from .modules.config_scanner import ConfigScanner
    from .modules.malware_scanner import MalwareScanner
    from .modules.database_scanner import DatabaseScanner
    from .modules.ssh_scanner import SSHScanner
    from .modules.system_check import SystemCheckModule
    from .modules.crypto_scanner import CryptoSecurityScanner
    from .modules.memory_scanner import MemoryAnalysisScanner
    from .modules.steganography_scanner import SteganographyScanner
    from .modules.iot_scanner import IoTDeviceScanner
    from .modules.traffic_scanner import TrafficAnalysisScanner
    from .modules.base_scanner import scanner_registry
except ImportError:
    # Fallback for direct execution
    import sys
    sys.path.append(os.path.dirname(os.path.abspath(__file__)))
    from modules.port_scanner import PortScanner
    from modules.vulnerability_scanner import VulnerabilityScanner
    from modules.network_scanner import NetworkScanner
    from modules.web_scanner import WebScanner
    from modules.forensics_scanner import ForensicsScanner
    from modules.config_scanner import ConfigScanner
    from modules.malware_scanner import MalwareScanner
    from modules.database_scanner import DatabaseScanner
    from modules.ssh_scanner import SSHScanner
    from modules.system_check import SystemCheckModule
    from modules.crypto_scanner import CryptoSecurityScanner
    from modules.memory_scanner import MemoryAnalysisScanner
    from modules.steganography_scanner import SteganographyScanner
    from modules.iot_scanner import IoTDeviceScanner
    from modules.traffic_scanner import TrafficAnalysisScanner
    from modules.base_scanner import scanner_registry

# Console instance for rich output
console = Console()


class ScanError(Exception):
    """Base exception for scan-related errors"""
    pass


class SecurityScanner:
    """Enhanced high-performance comprehensive security scanner for Linux servers"""
    
    COMMON_PORTS = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        111: "RPC",
        135: "MSRPC",
        139: "NetBIOS",
        143: "IMAP",
        443: "HTTPS",
        445: "SMB",
        993: "IMAPS",
        995: "POP3S",
        1723: "PPTP",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        5900: "VNC",
        8080: "HTTP-Proxy",
        8443: "HTTPS-Alt",
        27017: "MongoDB",
        6379: "Redis",
        9200: "Elasticsearch"
    }
    
    def __init__(self, timeout: int = 5, max_workers: int = 50):
        self.timeout = timeout
        self.max_workers = max_workers
        self.results = {}
        self.scan_start_time = None
        self.scan_end_time = None
        self.total_hosts = 0
        self.scanned_hosts = 0
        self.vulnerable_hosts = 0
        
        # Initialize enhanced components
        self.logger = get_logger("security_scanner")
        self.performance_monitor = get_performance_monitor()
        self.config_manager = get_config_manager()
        
        # Error tracking
        self.errors = []
        self.warnings = []
        
        # Start performance monitoring if enabled
        if self.performance_monitor:
            try:
                self.performance_monitor.start_monitoring()
            except Exception as e:
                self.logger.warning(f"Could not start performance monitoring: {e}")
        
        # Initialize scanner modules with error handling
        self.scanners = {}
        self._initialize_scanners()
        
        # Register scanners
        self._register_scanners()
        
        self.logger.info(f"SecurityScanner initialized with {len(self.scanners)} modules")
    
    def _initialize_scanners(self):
        """Initialize scanner modules with proper error handling"""
        scanner_classes = {
            'port_scanner': PortScanner,
            'vulnerability_scanner': VulnerabilityScanner,
            'network_scanner': NetworkScanner,
            'web_scanner': WebScanner,
            'forensics_scanner': ForensicsScanner,
            'config_scanner': ConfigScanner,
            'malware_scanner': MalwareScanner,
            'database_scanner': DatabaseScanner,
            'ssh_scanner': SSHScanner,
            'crypto_scanner': CryptoSecurityScanner,
            'memory_scanner': MemoryAnalysisScanner,
            'steganography_scanner': SteganographyScanner,
            'iot_scanner': IoTDeviceScanner,
            'traffic_scanner': TrafficAnalysisScanner,
            'system_check': SystemCheckModule
        }
        
        for scanner_name, scanner_class in scanner_classes.items():
            try:
                if scanner_name == 'system_check':
                    # SystemCheckModule doesn't take timeout parameter
                    scanner_instance = scanner_class()
                else:
                    scanner_instance = scanner_class(timeout=self.timeout)
                
                self.scanners[scanner_name] = scanner_instance
                self.logger.debug(f"Initialized {scanner_name}")
                
            except Exception as e:
                self.logger.error(f"Failed to initialize {scanner_name}: {e}")
                self.errors.append(f"Failed to initialize {scanner_name}: {e}")
        
        # Backward compatibility - set individual attributes
        self.port_scanner = self.scanners.get('port_scanner')
        self.vulnerability_scanner = self.scanners.get('vulnerability_scanner')
        self.network_scanner = self.scanners.get('network_scanner')
        self.web_scanner = self.scanners.get('web_scanner')
        self.forensics_scanner = self.scanners.get('forensics_scanner')
        self.config_scanner = self.scanners.get('config_scanner')
        self.malware_scanner = self.scanners.get('malware_scanner')
        self.database_scanner = self.scanners.get('database_scanner')
        self.ssh_scanner = self.scanners.get('ssh_scanner')
        self.crypto_scanner = self.scanners.get('crypto_scanner')
        self.memory_scanner = self.scanners.get('memory_scanner')
        self.steganography_scanner = self.scanners.get('steganography_scanner')
        self.iot_scanner = self.scanners.get('iot_scanner')
        self.traffic_scanner = self.scanners.get('traffic_scanner')
        self.system_check = self.scanners.get('system_check')
    
    def _register_scanners(self):
        """Register scanners with the registry"""
        scanner_classes = {
            'port_scanner': PortScanner,
            'vulnerability_scanner': VulnerabilityScanner,
            'network_scanner': NetworkScanner,
            'web_scanner': WebScanner,
            'forensics_scanner': ForensicsScanner,
            'config_scanner': ConfigScanner,
            'malware_scanner': MalwareScanner,
            'database_scanner': DatabaseScanner,
            'ssh_scanner': SSHScanner,
            'crypto_scanner': CryptoSecurityScanner,
            'memory_scanner': MemoryAnalysisScanner,
            'steganography_scanner': SteganographyScanner,
            'iot_scanner': IoTDeviceScanner,
            'traffic_scanner': TrafficAnalysisScanner,
            'system_check': SystemCheckModule
        }
        
        for scanner_name, scanner_class in scanner_classes.items():
            try:
                scanner_registry.register(scanner_name, scanner_class)
            except Exception as e:
                self.logger.warning(f"Failed to register {scanner_name}: {e}")
    
    def get_scanner(self, scanner_name: str):
        """Get a scanner instance by name"""
        return self.scanners.get(scanner_name)
    
    def get_available_scanners(self) -> List[str]:
        """Get list of available scanner names"""
        return list(self.scanners.keys())
    
    def get_scanner_status(self) -> Dict[str, bool]:
        """Get status of all scanners"""
        return {name: scanner is not None for name, scanner in self.scanners.items()}
    
    def get_errors(self) -> List[str]:
        """Get list of initialization errors"""
        return self.errors.copy()
    
    def get_warnings(self) -> List[str]:
        """Get list of warnings"""
        return self.warnings.copy()
        scanner_registry.register('network_scanner', NetworkScanner)
        scanner_registry.register('web_scanner', WebScanner)
        scanner_registry.register('forensics_scanner', ForensicsScanner)
        scanner_registry.register('config_scanner', ConfigScanner)
        scanner_registry.register('malware_scanner', MalwareScanner)
        scanner_registry.register('database_scanner', DatabaseScanner)
        scanner_registry.register('ssh_scanner', SSHScanner)
        scanner_registry.register('crypto_scanner', CryptoSecurityScanner)
        scanner_registry.register('memory_scanner', MemoryAnalysisScanner)
        scanner_registry.register('steganography_scanner', SteganographyScanner)
        scanner_registry.register('iot_scanner', IoTDeviceScanner)
        scanner_registry.register('traffic_scanner', TrafficAnalysisScanner)
        scanner_registry.register('system_check', SystemCheckModule)
        
        # Create modules dictionary for easy access
        self.modules = {
            'port_scanner': self.port_scanner,
            'vulnerability_scanner': self.vulnerability_scanner,
            'network_scanner': self.network_scanner,
            'web_scanner': self.web_scanner,
            'forensics_scanner': self.forensics_scanner,
            'config_scanner': self.config_scanner,
            'malware_scanner': self.malware_scanner,
            'database_scanner': self.database_scanner,
            'ssh_scanner': self.ssh_scanner,
            'crypto_scanner': self.crypto_scanner,
            'memory_scanner': self.memory_scanner,
            'steganography_scanner': self.steganography_scanner,
            'iot_scanner': self.iot_scanner,
            'traffic_scanner': self.traffic_scanner,
            'system_check': self.system_check
        }
        
    def parse_targets(self, targets: List[str]) -> List[str]:
        """Parse and validate target list"""
        parsed_targets = []
        
        for target in targets:
            try:
                # Check if it's a CIDR notation
                if '/' in target:
                    network = ipaddress.ip_network(target, strict=False)
                    parsed_targets.extend([str(ip) for ip in network.hosts()])
                else:
                    # Single IP or hostname
                    # Validate IP address
                    try:
                        ipaddress.ip_address(target)
                        parsed_targets.append(target)
                    except ValueError:
                        # Try to resolve hostname
                        try:
                            socket.gethostbyname(target)
                            parsed_targets.append(target)
                        except socket.gaierror:
                            console.print(f"[red]Warning: Could not resolve {target}[/red]")
                            continue
            except ValueError as e:
                console.print(f"[red]Warning: Invalid target {target}: {e}[/red]")
                continue
        
        return parsed_targets
    
    async def scan_port(self, host: str, port: int) -> Tuple[int, bool, Optional[str]]:
        """Scan a single port"""
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.timeout
            )
            writer.close()
            await writer.wait_closed()
            return port, True, 'Unknown'
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return port, False, None
    
    def detect_service(self, port: int, banner: bytes) -> str:
        """Detect service from port and banner"""
        banner_str = banner.decode('utf-8', errors='ignore').lower()
        
        # Service detection based on banner
        if b'ssh' in banner:
            return f"SSH - {banner_str.strip()}"
        elif b'http' in banner:
            return f"HTTP - {banner_str.strip()}"
        elif b'ftp' in banner:
            return f"FTP - {banner_str.strip()}"
        elif b'smtp' in banner:
            return f"SMTP - {banner_str.strip()}"
        elif port in self.COMMON_PORTS:
            return self.COMMON_PORTS[port]
        else:
            return 'Unknown'
    
    async def check_ssl_certificate(self, host: str, port: int = 443) -> Optional[Dict[str, Any]]:
        """Check SSL certificate"""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=True),
                timeout=self.timeout
            )
            
            # Get SSL certificate information
            # Try multiple approaches to get the SSL object
            ssl_objects = []
            
            # First try to get SSL object from transport (production code)
            transport = writer.transport
            if hasattr(transport, 'get_extra_info'):
                ssl_object = transport.get_extra_info('ssl_object')
                # Handle async mock case
                if hasattr(ssl_object, '__await__'):
                    ssl_object = await ssl_object
                if ssl_object:
                    ssl_objects.append(ssl_object)
                    
            # Also try writer.get_extra_info for test compatibility
            if hasattr(writer, 'get_extra_info'):
                ssl_object = writer.get_extra_info('ssl_object')
                # Handle async mock case
                if hasattr(ssl_object, '__await__'):
                    ssl_object = await ssl_object
                if ssl_object:
                    ssl_objects.append(ssl_object)
            
            # Try each SSL object until we find one that works
            for ssl_object in ssl_objects:
                if ssl_object:
                    try:
                        cert_der = ssl_object.getpeercert_binary()
                        cert = x509.load_der_x509_certificate(cert_der, default_backend())
                        
                        return {
                            'subject': cert.subject.rfc4514_string(),
                            'issuer': cert.issuer.rfc4514_string(),
                            'not_before': cert.not_valid_before.isoformat(),
                            'not_after': cert.not_valid_after.isoformat(),
                            'serial_number': str(cert.serial_number),
                            'version': cert.version.name
                        }
                    except Exception:
                        # Fallback to simple getpeercert() for compatibility
                        try:
                            cert = ssl_object.getpeercert()
                            # Handle async mock case
                            if hasattr(cert, '__await__'):
                                cert = await cert
                            if cert:
                                return {
                                    'subject': cert.get('subject', ''),
                                    'issuer': cert.get('issuer', ''),
                                    'not_before': cert.get('notBefore', ''),
                                    'not_after': cert.get('notAfter', ''),
                                    'serial_number': cert.get('serialNumber', ''),
                                    'version': cert.get('version', '')
                                }
                        except Exception:
                            continue
            
            writer.close()
            await writer.wait_closed()
            
        except Exception as e:
            return None
        
        return None
    
    async def check_ssh_security(self, host: str, port: int = 22) -> Optional[Dict[str, Any]]:
        """Check SSH security configuration"""
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(host, port, timeout=self.timeout)
            
            # Get SSH transport for security options
            transport = client.get_transport()
            if transport:
                security_options = transport.get_security_options()
                
                result = {
                    'kex_algorithms': security_options.kex,
                    'server_host_key_algorithms': security_options.key_types,
                    'encryption_algorithms': security_options.ciphers,
                    'mac_algorithms': security_options.digests,
                    'compression_algorithms': security_options.compression
                }
                
                client.close()
                return result
            else:
                client.close()
                return None
            
        except Exception as e:
            return None
    
    @monitor_async_performance
    async def scan_host(self, host: str, scan_modules: List[str] = None, **kwargs) -> Dict[str, Any]:
        """Comprehensive scan of a single host with enhanced error handling"""
        if scan_modules is None:
            scan_modules = ['port_scanner', 'vulnerability_scanner', 'network_scanner', 'web_scanner', 'ssh_scanner']
        
        host_results = {
            'host': host,
            'timestamp': datetime.now().isoformat(),
            'scan_modules': scan_modules,
            'scan_results': {},
            'vulnerabilities': [],
            'security_score': 0,
            'recommendations': [],
            'errors': [],
            'warnings': []
        }
        
        # Start performance monitoring for this scan
        if self.performance_monitor:
            await self.performance_monitor.start_async_monitoring()
        
        try:
            with LoggedOperation("host_scan", host, self.logger):
                # Validate target
                if not self._validate_target(host):
                    error_msg = f"Invalid target: {host}"
                    host_results['errors'].append(error_msg)
                    self.logger.error(error_msg)
                    return host_results
                
                # Port scanning with error handling
                if 'port_scanner' in scan_modules and self.port_scanner:
                    try:
                        port_scanner_kwargs = {
                            'enable_service_detection': kwargs.get('enable_service_detection', False),
                            'enable_os_detection': kwargs.get('enable_os_detection', False),
                            'enable_banner_grabbing': kwargs.get('enable_banner_grabbing', False)
                        }
                        
                        self.logger.info(f"Starting port scan on {host}")
                        port_results = await self.port_scanner.scan(host, **port_scanner_kwargs)
                        host_results['scan_results']['port_scan'] = port_results
                        
                        # Use port scan results for other scanners
                        open_ports = port_results.get('open_ports', {})
                        service_detection = port_results.get('service_detection', {})
                        
                        self.logger.info(f"Port scan completed for {host}: {len(open_ports)} open ports found")
                        
                    except Exception as e:
                        error_msg = f"Port scan failed for {host}: {e}"
                        host_results['errors'].append(error_msg)
                        self.logger.error(error_msg, exc_info=True)
                        open_ports = {}
                        service_detection = {}
                
                # SSH scanning for SSH services
                if ('ssh_scanner' in scan_modules and self.ssh_scanner and 
                    'open_ports' in host_results.get('scan_results', {}).get('port_scan', {}) and
                    22 in host_results['scan_results']['port_scan']['open_ports']):
                    try:
                        self.logger.info(f"Starting SSH scan on {host}")
                        ssh_results = await self.ssh_scanner.scan(host, **kwargs)
                        host_results['scan_results']['ssh_scan'] = ssh_results
                        self.logger.info(f"SSH scan completed for {host}")
                    except Exception as e:
                        error_msg = f"SSH scan failed for {host}: {e}"
                        host_results['errors'].append(error_msg)
                        self.logger.error(error_msg, exc_info=True)
                
                # Vulnerability scanning
                if 'vulnerability_scanner' in scan_modules and self.vulnerability_scanner:
                    try:
                        self.logger.info(f"Starting vulnerability scan on {host}")
                        vuln_results = await self.vulnerability_scanner.scan(
                            host, services=service_detection
                        )
                        host_results['scan_results']['vulnerability_scan'] = vuln_results
                        
                        # Extract vulnerabilities
                        if 'vulnerabilities' in vuln_results:
                            host_results['vulnerabilities'].extend(vuln_results['vulnerabilities'])
                        
                        self.logger.info(f"Vulnerability scan completed for {host}")
                    except Exception as e:
                        error_msg = f"Vulnerability scan failed for {host}: {e}"
                        host_results['errors'].append(error_msg)
                        self.logger.error(error_msg, exc_info=True)
                
                # Web scanning for web services
                if 'web_scanner' in scan_modules and self.web_scanner:
                    try:
                        web_ports = [80, 443, 8080, 8443]
                        for port in web_ports:
                            if ('open_ports' in host_results.get('scan_results', {}).get('port_scan', {}) and
                                port in host_results['scan_results']['port_scan']['open_ports']):
                                try:
                                    protocol = 'https' if port in [443, 8443] else 'http'
                                    web_url = f"{protocol}://{host}:{port}"
                                    
                                    self.logger.info(f"Starting web scan on {web_url}")
                                    web_results = await self.web_scanner.scan(web_url)
                                    host_results['scan_results'][f'web_scan_{port}'] = web_results
                                    self.logger.info(f"Web scan completed for {web_url}")
                                except Exception as e:
                                    error_msg = f"Web scan failed for {host}:{port}: {e}"
                                    host_results['errors'].append(error_msg)
                                    self.logger.error(error_msg, exc_info=True)
                    except Exception as e:
                        error_msg = f"Web scanner setup failed for {host}: {e}"
                        host_results['errors'].append(error_msg)
                        self.logger.error(error_msg, exc_info=True)
                
                # Additional scanner modules
                additional_scanners = [
                    ('network_scanner', 'network_scan'),
                    ('config_scanner', 'config_scan'),
                    ('malware_scanner', 'malware_scan'),
                    ('database_scanner', 'database_scan'),
                    ('crypto_scanner', 'crypto_scan'),
                    ('memory_scanner', 'memory_scan'),
                    ('steganography_scanner', 'steganography_scan'),
                    ('iot_scanner', 'iot_scan'),
                    ('traffic_scanner', 'traffic_scan'),
                    ('system_check', 'system_check')
                ]
                
                for scanner_name, result_key in additional_scanners:
                    if scanner_name in scan_modules and self.get_scanner(scanner_name):
                        try:
                            scanner = self.get_scanner(scanner_name)
                            self.logger.info(f"Starting {scanner_name} on {host}")
                            
                            if scanner_name == 'system_check':
                                # System check doesn't need host parameter
                                scan_results = await scanner.scan(**kwargs)
                            else:
                                scan_results = await scanner.scan(host, **kwargs)
                            
                            host_results['scan_results'][result_key] = scan_results
                            self.logger.info(f"{scanner_name} completed for {host}")
                        except Exception as e:
                            error_msg = f"{scanner_name} failed for {host}: {e}"
                            host_results['errors'].append(error_msg)
                            self.logger.error(error_msg, exc_info=True)
                
                # Calculate security score
                try:
                    host_results['security_score'] = self._calculate_security_score(host_results)
                except Exception as e:
                    warning_msg = f"Could not calculate security score for {host}: {e}"
                    host_results['warnings'].append(warning_msg)
                    self.logger.warning(warning_msg)
                
                # Generate recommendations
                try:
                    host_results['recommendations'] = self._generate_recommendations(host_results)
                except Exception as e:
                    warning_msg = f"Could not generate recommendations for {host}: {e}"
                    host_results['warnings'].append(warning_msg)
                    self.logger.warning(warning_msg)
                
        except Exception as e:
            error_msg = f"Scan failed for {host}: {e}"
            host_results['errors'].append(error_msg)
            self.logger.error(error_msg, exc_info=True)
        
        finally:
            # Stop performance monitoring for this scan
            if self.performance_monitor:
                await self.performance_monitor.stop_async_monitoring()
        
        return host_results
    
    def _validate_target(self, host: str) -> bool:
        """Validate scan target"""
        try:
            # Check if it's a valid IP address
            ipaddress.ip_address(host)
            return True
        except ValueError:
            # Check if it's a valid hostname
            try:
                socket.gethostbyname(host)
                return True
            except socket.gaierror:
                return False
    
    def _calculate_security_score(self, host_results: Dict[str, Any]) -> int:
        """Calculate security score based on scan results"""
        score = 100  # Start with perfect score
        
        # Deduct points for vulnerabilities
        vulnerabilities = host_results.get('vulnerabilities', [])
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'low').lower()
            if severity == 'critical':
                score -= 20
            elif severity == 'high':
                score -= 15
            elif severity == 'medium':
                score -= 10
            elif severity == 'low':
                score -= 5
        
        # Deduct points for open ports
        port_scan = host_results.get('scan_results', {}).get('port_scan', {})
        open_ports = port_scan.get('open_ports', {})
        
        # Deduct points for high-risk ports
        high_risk_ports = [21, 23, 135, 139, 445, 1433, 3306, 5432]
        for port in high_risk_ports:
            if port in open_ports:
                score -= 5
        
        # Deduct points for too many open ports
        if len(open_ports) > 10:
            score -= 10
        elif len(open_ports) > 5:
            score -= 5
        
        # Bonus points for security measures
        ssh_scan = host_results.get('scan_results', {}).get('ssh_scan', {})
        if ssh_scan.get('key_auth_enabled', False):
            score += 5
        
        return max(0, min(100, score))
    
    def _generate_recommendations(self, host_results: Dict[str, Any]) -> List[str]:
        """Generate security recommendations based on scan results"""
        recommendations = []
        
        # Port-based recommendations
        port_scan = host_results.get('scan_results', {}).get('port_scan', {})
        open_ports = port_scan.get('open_ports', {})
        
        high_risk_ports = {
            21: "FTP - Consider using SFTP instead",
            23: "Telnet - Use SSH instead",
            135: "MS-RPC - Ensure proper firewall configuration",
            139: "NetBIOS - Consider disabling if not needed",
            445: "SMB - Ensure latest patches are applied",
            1433: "SQL Server - Restrict access and use encryption",
            3306: "MySQL - Secure with strong passwords and restrict access",
            5432: "PostgreSQL - Use SSL connections and restrict access"
        }
        
        for port, message in high_risk_ports.items():
            if port in open_ports:
                recommendations.append(f"Port {port} is open: {message}")
        
        # Vulnerability-based recommendations
        vulnerabilities = host_results.get('vulnerabilities', [])
        critical_vulns = [v for v in vulnerabilities if v.get('severity', '').lower() == 'critical']
        high_vulns = [v for v in vulnerabilities if v.get('severity', '').lower() == 'high']
        
        if critical_vulns:
            recommendations.append(f"URGENT: {len(critical_vulns)} critical vulnerabilities found - apply patches immediately")
        
        if high_vulns:
            recommendations.append(f"HIGH PRIORITY: {len(high_vulns)} high-severity vulnerabilities found")
        
        # SSH-based recommendations
        ssh_scan = host_results.get('scan_results', {}).get('ssh_scan', {})
        if ssh_scan:
            if not ssh_scan.get('key_auth_enabled', False):
                recommendations.append("SSH: Enable key-based authentication")
            
            if ssh_scan.get('password_auth_enabled', False):
                recommendations.append("SSH: Consider disabling password authentication")
        
        # General security recommendations
        if len(open_ports) > 10:
            recommendations.append("Consider closing unnecessary ports to reduce attack surface")
        
        if not recommendations:
            recommendations.append("No critical security issues found")
        
        return recommendations
                
                # Database scanning
                if 'database_scanner' in scan_modules:
                    db_ports = [3306, 5432, 27017, 6379, 9200]
                    for port in db_ports:
                        if port in open_ports:
                            db_results = await self.database_scanner.scan(host, port=port)
                            host_results['scan_results'][f'database_scan_{port}'] = db_results
            
            # SSH scanning (standalone if SSH port scanning is not enabled)
            if 'ssh_scanner' in scan_modules and 'port_scanner' not in scan_modules:
                ssh_results = await self.ssh_scanner.scan(host, **kwargs)
                host_results['scan_results']['ssh_scan'] = ssh_results
            
            # Network scanning
            if 'network_scanner' in scan_modules:
                network_results = await self.network_scanner.scan(host)
                host_results['scan_results']['network_scan'] = network_results
            
            # Configuration scanning
            if 'config_scanner' in scan_modules:
                config_results = await self.config_scanner.scan(host)
                host_results['scan_results']['config_scan'] = config_results
            
            # Malware scanning
            if 'malware_scanner' in scan_modules:
                malware_results = await self.malware_scanner.scan(host)
                host_results['scan_results']['malware_scan'] = malware_results
            
            # Forensics scanning
            if 'forensics_scanner' in scan_modules:
                forensics_results = await self.forensics_scanner.scan(host)
                host_results['scan_results']['forensics_scan'] = forensics_results
            
            # Compile vulnerabilities from all modules
            host_results['vulnerabilities'] = self._compile_host_vulnerabilities(host_results['scan_results'])
            
            # Calculate security score
            host_results['security_score'] = self._calculate_host_security_score(host_results)
            
            # Generate recommendations
            host_results['recommendations'] = self._generate_host_recommendations(host_results)
            
        except Exception as e:
            host_results['error'] = str(e)
        
        return host_results
    
    async def scan_network(self, targets: List[str], scan_modules: List[str] = None, **kwargs) -> Dict[str, Any]:
        """Scan multiple targets"""
        self.scan_start_time = datetime.now()
        
        # Parse targets
        parsed_targets = self.parse_targets(targets)
        self.total_hosts = len(parsed_targets)
        
        console.print(f"[green]Starting comprehensive security scan of {self.total_hosts} hosts[/green]")
        console.print(f"[blue]Scan modules: {scan_modules or 'default'}[/blue]")
        
        # Progress tracking
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeRemainingColumn(),
            console=console
        ) as progress:
            
            scan_task = progress.add_task("Scanning hosts...", total=self.total_hosts)
            
            # Scan hosts concurrently
            semaphore = asyncio.Semaphore(self.max_workers)
            
            async def scan_with_progress(host):
                async with semaphore:
                    if scan_modules is not None:
                        result = await self.scan_host(host, scan_modules, **kwargs)
                    else:
                        result = await self.scan_host(host, **kwargs)
                    progress.advance(scan_task)
                    self.scanned_hosts += 1
                    
                    # Count vulnerable hosts
                    if result.get('vulnerabilities'):
                        self.vulnerable_hosts += 1
                    
                    return host, result
            
            # Execute scans
            tasks = [scan_with_progress(host) for host in parsed_targets]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Process results
            for result in results:
                if isinstance(result, Exception):
                    console.print(f"[red]Error during scan: {result}[/red]")
                    continue
                
                host, host_result = result
                self.results[host] = host_result
        
        self.scan_end_time = datetime.now()
        
        # Generate summary
        summary = self._generate_scan_summary()
        
        return {
            'summary': summary,
            'results': self.results,
            'scan_duration': (self.scan_end_time - self.scan_start_time).total_seconds(),
            'total_hosts': self.total_hosts,
            'scanned_hosts': self.scanned_hosts,
            'vulnerable_hosts': self.vulnerable_hosts
        }
    
    def _compile_host_vulnerabilities(self, scan_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Compile vulnerabilities from all scan modules"""
        vulnerabilities = []
        
        for module_name, module_results in scan_results.items():
            if isinstance(module_results, dict) and 'vulnerabilities' in module_results:
                for vuln in module_results['vulnerabilities']:
                    vuln['source_module'] = module_name
                    vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _calculate_host_security_score(self, host_results: Dict[str, Any]) -> int:
        """Calculate security score for a host"""
        base_score = 100
        vulnerabilities = host_results.get('vulnerabilities', [])
        
        # Deduct points based on vulnerability severity
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'Low').lower()
            if severity == 'critical':
                base_score -= 20
            elif severity == 'high':
                base_score -= 10
            elif severity == 'medium':
                base_score -= 5
            elif severity == 'low':
                base_score -= 2
        
        return max(0, base_score)
    
    def _generate_host_recommendations(self, host_results: Dict[str, Any]) -> List[str]:
        """Generate recommendations for a host"""
        recommendations = []
        
        # Compile recommendations from all modules
        for module_name, module_results in host_results.get('scan_results', {}).items():
            if isinstance(module_results, dict) and 'recommendations' in module_results:
                recommendations.extend(module_results['recommendations'])
        
        # Remove duplicates while preserving order
        unique_recommendations = []
        seen = set()
        for rec in recommendations:
            if rec not in seen:
                unique_recommendations.append(rec)
                seen.add(rec)
        
        return unique_recommendations
    
    def _generate_scan_summary(self) -> Dict[str, Any]:
        """Generate scan summary"""
        # Calculate scan duration safely
        if self.scan_end_time and self.scan_start_time:
            scan_duration = (self.scan_end_time - self.scan_start_time).total_seconds()
        else:
            scan_duration = 0.0
            
        summary = {
            'total_hosts': self.total_hosts,
            'scanned_hosts': self.scanned_hosts,
            'vulnerable_hosts': self.vulnerable_hosts,
            'scan_duration': scan_duration,
            'vulnerability_summary': {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0
            },
            'top_vulnerabilities': [],
            'security_score_distribution': {}
        }
        
        # Analyze vulnerabilities
        all_vulnerabilities = []
        vulnerability_counts = {}
        
        for host, host_result in self.results.items():
            vulnerabilities = host_result.get('vulnerabilities', [])
            all_vulnerabilities.extend(vulnerabilities)
            
            # Count by severity
            for vuln in vulnerabilities:
                severity = vuln.get('severity', 'Low').lower()
                if severity in summary['vulnerability_summary']:
                    summary['vulnerability_summary'][severity] += 1
                
                # Count vulnerability types
                vuln_type = vuln.get('type', 'Unknown')
                vulnerability_counts[vuln_type] = vulnerability_counts.get(vuln_type, 0) + 1
        
        # Top vulnerabilities
        summary['top_vulnerabilities'] = sorted(
            vulnerability_counts.items(),
            key=lambda x: x[1],
            reverse=True
        )[:10]
        
        # Security score distribution
        scores = [host_result.get('security_score', 0) for host_result in self.results.values()]
        if scores:
            summary['security_score_distribution'] = {
                'average': sum(scores) / len(scores),
                'minimum': min(scores),
                'maximum': max(scores),
                'median': sorted(scores)[len(scores) // 2]
            }
        
        return summary
    
    def analyze_vulnerabilities(self, scan_data: Dict[str, Any]) -> List[str]:
        """Analyze scan data for vulnerabilities"""
        vulnerabilities = []
        
        # Check for open ports with known vulnerabilities
        open_ports = scan_data.get('open_ports', {})
        for port, info in open_ports.items():
            service = info.get('service', '').lower()
            
            # Check for insecure services
            if 'telnet' in service:
                vulnerabilities.append(f"Insecure Telnet service on port {port}")
            elif 'ftp' in service and port == 21:
                vulnerabilities.append(f"Unencrypted FTP service on port {port}")
            elif 'http' in service and port == 80:
                vulnerabilities.append(f"Unencrypted HTTP service on port {port}")
        
        # Check SSL/TLS vulnerabilities
        ssl_certs = scan_data.get('ssl_certificates', {})
        for port, cert_info in ssl_certs.items():
            if cert_info.get('expired', False):
                vulnerabilities.append(f"Expired SSL certificate on port {port}")
            if cert_info.get('expires_soon', False):
                vulnerabilities.append(f"SSL certificate expires soon on port {port}")
        
        # Check SSH security
        ssh_security = scan_data.get('ssh_security', {})
        if ssh_security:
            weak_algorithms = ssh_security.get('weak_algorithms', [])
            for algo in weak_algorithms:
                vulnerabilities.append(f"Weak SSH algorithm: {algo}")
        
        return vulnerabilities
    
    def calculate_security_score(self, scan_data: Dict[str, Any]) -> Tuple[int, str]:
        """Calculate security score and rating"""
        base_score = 100
        
        # Deduct points for vulnerabilities
        vulnerabilities = scan_data.get('vulnerabilities', [])
        base_score -= len(vulnerabilities) * 5
        
        # Deduct points for open ports
        open_ports = scan_data.get('open_ports', {})
        base_score -= len(open_ports) * 2
        
        # Deduct points for insecure services
        insecure_services = ['telnet', 'ftp', 'http']
        for port, info in open_ports.items():
            service = info.get('service', '').lower()
            if any(insecure in service for insecure in insecure_services):
                base_score -= 10
        
        # Ensure score is not negative
        score = max(0, base_score)
        
        # Determine rating
        if score >= 90:
            rating = "Excellent"
        elif score >= 80:
            rating = "Good"
        elif score >= 70:
            rating = "Fair"
        elif score >= 60:
            rating = "Poor"
        else:
            rating = "Critical"
        
        return score, rating
    
    def export_json(self, filename: str):
        """Export results to JSON"""
        try:
            with open(filename, 'w') as f:
                json.dump(self.results, f, indent=2, default=str)
            console.print(f"[green]Results exported to {filename}[/green]")
        except Exception as e:
            console.print(f"[red]Error exporting to JSON: {e}[/red]")
    
    def export_csv(self, filename: str):
        """Export results to CSV"""
        try:
            with open(filename, 'w', newline='') as f:
                writer = csv.writer(f)
                
                # Write header
                writer.writerow(['Host', 'Security Score', 'Vulnerabilities', 'Open Ports', 'Recommendations'])
                
                # Write data
                for host, result in self.results.items():
                    vulnerabilities = len(result.get('vulnerabilities', []))
                    open_ports = len(result.get('scan_results', {}).get('port_scan', {}).get('open_ports', {}))
                    recommendations = len(result.get('recommendations', []))
                    security_score = result.get('security_score', 0)
                    
                    writer.writerow([host, security_score, vulnerabilities, open_ports, recommendations])
                    
            console.print(f"[green]Results exported to {filename}[/green]")
        except Exception as e:
            console.print(f"[red]Error exporting to CSV: {e}[/red]")
    
    def export_html(self, filename: str):
        """Export results to HTML"""
        try:
            html_content = self._generate_html_report()
            with open(filename, 'w') as f:
                f.write(html_content)
            console.print(f"[green]Results exported to {filename}[/green]")
        except Exception as e:
            console.print(f"[red]Error exporting to HTML: {e}[/red]")
    
    def _generate_html_report(self) -> str:
        """Generate HTML report"""
        html = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>LinuxScan Security Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                .header { background-color: #2e3440; color: white; padding: 20px; text-align: center; }
                .summary { background-color: #f8f9fa; padding: 15px; margin: 20px 0; }
                .host { border: 1px solid #dee2e6; margin: 10px 0; padding: 15px; }
                .vulnerability { background-color: #fff3cd; padding: 8px; margin: 5px 0; border-left: 4px solid #ffc107; }
                .critical { border-left-color: #dc3545; background-color: #f8d7da; }
                .high { border-left-color: #fd7e14; background-color: #fff3cd; }
                .medium { border-left-color: #ffc107; background-color: #fff3cd; }
                .low { border-left-color: #28a745; background-color: #d1edff; }
                table { width: 100%; border-collapse: collapse; margin: 10px 0; }
                th, td { border: 1px solid #dee2e6; padding: 8px; text-align: left; }
                th { background-color: #e9ecef; }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>LinuxScan Comprehensive Security Report</h1>
                <p>Generated on """ + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + """</p>
            </div>
        """
        
        # Add summary
        summary = self._generate_scan_summary()
        html += f"""
            <div class="summary">
                <h2>Scan Summary</h2>
                <p><strong>Total Hosts:</strong> {summary['total_hosts']}</p>
                <p><strong>Scanned Hosts:</strong> {summary['scanned_hosts']}</p>
                <p><strong>Vulnerable Hosts:</strong> {summary['vulnerable_hosts']}</p>
                <p><strong>Scan Duration:</strong> {summary['scan_duration']:.2f} seconds</p>
            </div>
        """
        
        # Add vulnerability summary
        html += """
            <div class="summary">
                <h2>Vulnerability Summary</h2>
                <table>
                    <tr><th>Severity</th><th>Count</th></tr>
        """
        
        for severity, count in summary['vulnerability_summary'].items():
            html += f"<tr><td>{severity.capitalize()}</td><td>{count}</td></tr>"
        
        html += """
                </table>
            </div>
        """
        
        # Add individual host results
        for host, result in self.results.items():
            html += f"""
                <div class="host">
                    <h3>Host: {host}</h3>
                    <p><strong>Security Score:</strong> {result.get('security_score', 0)}</p>
                    <p><strong>Vulnerabilities:</strong> {len(result.get('vulnerabilities', []))}</p>
                    
                    <h4>Vulnerabilities</h4>
            """
            
            for vuln in result.get('vulnerabilities', []):
                severity = vuln.get('severity', 'low').lower()
                html += f"""
                    <div class="vulnerability {severity}">
                        <strong>{vuln.get('type', 'Unknown')}</strong>: {vuln.get('description', 'No description')}
                    </div>
                """
            
            html += """
                </div>
            """
        
        html += """
        </body>
        </html>
        """
        
        return html
    
    def generate_summary_table(self) -> Table:
        """Generate summary table for display"""
        table = Table(title="Security Scan Summary")
        
        table.add_column("Host", style="cyan")
        table.add_column("Security Score", style="green")
        table.add_column("Vulnerabilities", style="red")
        table.add_column("Open Ports", style="yellow")
        table.add_column("Status", style="bold")
        
        for host, result in self.results.items():
            vulnerabilities = len(result.get('vulnerabilities', []))
            open_ports = len(result.get('scan_results', {}).get('port_scan', {}).get('open_ports', {}))
            security_score = result.get('security_score', 0)
            
            if security_score >= 80:
                status = "[green]Good[/green]"
            elif security_score >= 60:
                status = "[yellow]Fair[/yellow]"
            else:
                status = "[red]Poor[/red]"
            
            table.add_row(
                host,
                str(security_score),
                str(vulnerabilities),
                str(open_ports),
                status
            )
        
        return table


def display_banner():
    """Display application banner"""
    banner = """
    ╔══════════════════════════════════════════════════════════════════════════════════════╗
    ║                        LinuxScan - Comprehensive Security Scanner                    ║
    ║                             Professional Security Assessment Tool                     ║
    ║                                      Version 1.0.0                                  ║
    ╚══════════════════════════════════════════════════════════════════════════════════════╝
    """
    console.print(banner, style="bold blue")


def display_help():
    """Display help information"""
    help_text = """
    [bold]LinuxScan - Comprehensive Security Scanner[/bold]
    
    [yellow]USAGE:[/yellow]
        linuxscan [OPTIONS] TARGETS
    
    [yellow]TARGETS:[/yellow]
        Single IP:      192.168.1.1
        CIDR Range:     192.168.1.0/24
        Multiple IPs:   192.168.1.1,192.168.1.2,192.168.1.3
        Hostname:       example.com
    
    [yellow]OPTIONS:[/yellow]
        --modules, -m           Scan modules to use (comma-separated)
        --timeout, -t           Connection timeout in seconds (default: 5)
        --max-workers, -w       Maximum concurrent workers (default: 50)
        --output, -o            Output file name
        --format, -f            Output format (json, csv, html)
        --config, -c            Configuration file path
        --verbose, -v           Verbose output
        --help, -h              Show this help message
    
    [yellow]SCAN MODULES:[/yellow]
        port_scanner           Enhanced port scanning with service detection
        vulnerability_scanner  CVE-based vulnerability assessment
        network_scanner       Network analysis and traffic inspection
        web_scanner           Web application security testing
        config_scanner        Configuration and compliance auditing
        malware_scanner       Malware detection and analysis
        database_scanner      Database security assessment
        forensics_scanner     Digital forensics and analysis
    
    [yellow]EXAMPLES:[/yellow]
        # Basic scan
        linuxscan 192.168.1.1
        
        # Comprehensive scan with all modules
        linuxscan 192.168.1.0/24 --modules all
        
        # Specific modules
        linuxscan 192.168.1.1 --modules port_scanner,vulnerability_scanner
        
        # Export results
        linuxscan 192.168.1.1 --output results.json --format json
        
        # Custom configuration
        linuxscan 192.168.1.1 --config custom_config.json
    
    [yellow]FEATURES:[/yellow]
        ✓ 50+ Security Scanning Tools and Techniques
        ✓ CVE-based Vulnerability Assessment
        ✓ Network Traffic Analysis
        ✓ Web Application Security Testing
        ✓ Database Security Assessment
        ✓ Malware Detection and Analysis
        ✓ Digital Forensics Capabilities
        ✓ Configuration Compliance Auditing
        ✓ Comprehensive Reporting (JSON, CSV, HTML)
        ✓ Multi-threaded High-Performance Scanning
        ✓ Professional Security Assessment
    """
    console.print(help_text)