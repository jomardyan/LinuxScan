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
    
    async def scan_network(self, targets: List[str], scan_modules: List[str] = None, **kwargs) -> Dict[str, Any]:
        """Scan multiple targets concurrently with enhanced error handling"""
        if scan_modules is None:
            scan_modules = ['port_scanner', 'vulnerability_scanner', 'network_scanner', 'web_scanner', 'ssh_scanner']
        
        self.scan_start_time = time.time()
        self.total_hosts = len(targets)
        self.scanned_hosts = 0
        self.vulnerable_hosts = 0
        
        network_results = {
            'targets': targets,
            'scan_modules': scan_modules,
            'timestamp': datetime.now().isoformat(),
            'scan_duration': 0,
            'total_hosts': self.total_hosts,
            'scanned_hosts': 0,
            'vulnerable_hosts': 0,
            'results': {},
            'summary': {},
            'errors': []
        }
        
        try:
            with LoggedOperation("network_scan", f"{len(targets)} targets", self.logger):
                
                # Create semaphore to limit concurrent scans
                semaphore = asyncio.Semaphore(min(self.max_workers, len(targets)))
                
                async def scan_with_progress(host):
                    async with semaphore:
                        try:
                            result = await self.scan_host(host, scan_modules, **kwargs)
                            self.scanned_hosts += 1
                            
                            # Count vulnerable hosts
                            if result.get('vulnerabilities') or result.get('errors'):
                                self.vulnerable_hosts += 1
                            
                            return host, result
                        except Exception as e:
                            self.logger.error(f"Error scanning {host}: {e}")
                            network_results['errors'].append(f"Error scanning {host}: {e}")
                            return host, {'error': str(e), 'host': host}
                
                # Execute scans concurrently
                tasks = [scan_with_progress(host) for host in targets]
                completed_scans = await asyncio.gather(*tasks, return_exceptions=True)
                
                # Process results
                for result in completed_scans:
                    if isinstance(result, Exception):
                        network_results['errors'].append(f"Scan task failed: {result}")
                    else:
                        host, scan_result = result
                        network_results['results'][host] = scan_result
                
                # Calculate summary
                network_results['scanned_hosts'] = self.scanned_hosts
                network_results['vulnerable_hosts'] = self.vulnerable_hosts
                network_results['scan_duration'] = time.time() - self.scan_start_time
                
                # Generate summary statistics
                network_results['summary'] = self._generate_network_summary(network_results)
                
        except Exception as e:
            error_msg = f"Network scan failed: {e}"
            network_results['errors'].append(error_msg)
            self.logger.error(error_msg, exc_info=True)
        
        return network_results
    
    def _generate_network_summary(self, network_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate network scan summary"""
        summary = {
            'total_hosts': network_results['total_hosts'],
            'scanned_hosts': network_results['scanned_hosts'],
            'vulnerable_hosts': network_results['vulnerable_hosts'],
            'scan_duration': network_results['scan_duration'],
            'average_scan_time': network_results['scan_duration'] / max(network_results['scanned_hosts'], 1),
            'error_count': len(network_results['errors']),
            'total_vulnerabilities': 0,
            'critical_vulnerabilities': 0,
            'high_vulnerabilities': 0,
            'medium_vulnerabilities': 0,
            'low_vulnerabilities': 0,
            'total_open_ports': 0,
            'unique_services': set(),
            'security_score_average': 0
        }
        
        security_scores = []
        
        for host, result in network_results['results'].items():
            if 'error' in result:
                continue
                
            # Count vulnerabilities
            vulnerabilities = result.get('vulnerabilities', [])
            summary['total_vulnerabilities'] += len(vulnerabilities)
            
            for vuln in vulnerabilities:
                severity = vuln.get('severity', 'low').lower()
                if severity == 'critical':
                    summary['critical_vulnerabilities'] += 1
                elif severity == 'high':
                    summary['high_vulnerabilities'] += 1
                elif severity == 'medium':
                    summary['medium_vulnerabilities'] += 1
                elif severity == 'low':
                    summary['low_vulnerabilities'] += 1
            
            # Count open ports
            port_scan = result.get('scan_results', {}).get('port_scan', {})
            open_ports = port_scan.get('open_ports', {})
            summary['total_open_ports'] += len(open_ports)
            
            # Collect unique services
            service_detection = port_scan.get('service_detection', {})
            for service in service_detection.values():
                if service:
                    summary['unique_services'].add(service)
            
            # Collect security scores
            security_score = result.get('security_score', 0)
            if security_score > 0:
                security_scores.append(security_score)
        
        # Calculate average security score
        if security_scores:
            summary['security_score_average'] = sum(security_scores) / len(security_scores)
        
        summary['unique_services'] = list(summary['unique_services'])
        
        return summary


def display_banner():
    """Display the LinuxScan banner"""
    banner = """
    ╔═══════════════════════════════════════════════════════════════════════════════════╗
    ║                        🛡️  LinuxScan Security Scanner 🛡️                        ║
    ║                                                                                   ║
    ║                   Professional Linux Security Assessment Tool                     ║
    ║                              Version 1.0.0                                       ║
    ║                                                                                   ║
    ║                        Author: Security Scanner Team                             ║
    ║                         License: Apache 2.0                                      ║
    ╚═══════════════════════════════════════════════════════════════════════════════════╝
    """
    console.print(banner, style="bold cyan")


def display_help():
    """Display enhanced help information"""
    help_text = """
    [bold cyan]LinuxScan - Professional Linux Security Scanner[/bold cyan]
    
    [yellow]USAGE:[/yellow]
        linuxscan [targets] [options]
        
    [yellow]TARGETS:[/yellow]
        Single IP:     192.168.1.1
        IP Range:      192.168.1.1-192.168.1.100
        CIDR Range:    192.168.1.0/24
        Hostname:      example.com
        Multiple:      192.168.1.1,192.168.1.2,example.com
        
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
