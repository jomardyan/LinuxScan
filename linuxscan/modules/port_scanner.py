"""
Enhanced port scanner with service enumeration and banner grabbing
"""

import asyncio
import socket
import struct
import ssl
import re
from typing import Dict, List, Any, Tuple, Optional
from datetime import datetime
import nmap
from .base_scanner import BaseScannerModule


class PortScanner(BaseScannerModule):
    """Enhanced port scanner with service enumeration and banner grabbing"""
    
    WELL_KNOWN_PORTS = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
        80: "HTTP", 110: "POP3", 111: "RPC", 135: "MSRPC", 139: "NetBIOS",
        143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
        1433: "MSSQL", 1521: "Oracle", 1723: "PPTP", 3306: "MySQL",
        3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
        8080: "HTTP-Alt", 8443: "HTTPS-Alt", 9200: "Elasticsearch",
        27017: "MongoDB", 11211: "Memcached", 50000: "DB2"
    }
    
    # Service fingerprinting patterns
    SERVICE_PATTERNS = {
        'ssh': [
            (re.compile(b'SSH-([0-9.]+)-(.+)'), 'SSH {0} ({1})'),
            (re.compile(b'SSH-([0-9.]+)'), 'SSH {0}')
        ],
        'http': [
            (re.compile(b'HTTP/([0-9.]+) ([0-9]+) (.+)'), 'HTTP/{0} Status {1} ({2})'),
            (re.compile(b'Server: (.+)'), 'HTTP Server: {0}')
        ],
        'ftp': [
            (re.compile(b'220 (.+) FTP'), 'FTP Server: {0}'),
            (re.compile(b'220-(.+)'), 'FTP: {0}')
        ],
        'smtp': [
            (re.compile(b'220 (.+) SMTP'), 'SMTP Server: {0}'),
            (re.compile(b'220-(.+)'), 'SMTP: {0}')
        ],
        'pop3': [
            (re.compile(b'\\+OK (.+)'), 'POP3: {0}')
        ],
        'imap': [
            (re.compile(b'\\* OK (.+)'), 'IMAP: {0}')
        ],
        'mysql': [
            (re.compile(b'\\x05\\x00\\x00\\x00\\x0a(.+)\\x00'), 'MySQL: {0}')
        ],
        'postgres': [
            (re.compile(b'R\\x00\\x00\\x00\\x08\\x00\\x00\\x00\\x00'), 'PostgreSQL')
        ]
    }
    
    def __init__(self, timeout: int = 5, max_concurrent: int = 100):
        super().__init__("port_scanner", timeout)
        self.max_concurrent = max_concurrent
        self.nm = nmap.PortScanner()
        
    async def scan(self, target: str, ports: Optional[List[int]] = None,
                   scan_type: str = 'tcp', **kwargs) -> Dict[str, Any]:
        """
        Comprehensive port scan with service enumeration and banner grabbing
        """
        self.log_scan_start(target)
        
        if not self.validate_target(target):
            return {"error": f"Target {target} is unreachable"}
        
        # Default port ranges
        if ports is None:
            ports = list(range(1, 1025))  # Standard well-known ports
            ports.extend([1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017])
        
        results = {
            'target': target,
            'scan_type': scan_type,
            'timestamp': datetime.now().isoformat(),
            'open_ports': {},
            'closed_ports': [],
            'filtered_ports': [],
            'os_detection': {},
            'service_detection': {},
            'vulnerabilities': []
        }
        
        try:
            # Perform asynchronous port scanning
            if scan_type == 'tcp':
                scan_results = await self._tcp_scan(target, ports)
            elif scan_type == 'udp':
                scan_results = await self._udp_scan(target, ports)
            else:
                scan_results = await self._tcp_scan(target, ports)
            
            results.update(scan_results)
            
            # Enhanced service detection for open ports
            for port in results['open_ports']:
                service_info = await self._detect_service(target, port)
                results['service_detection'][port] = service_info
                
                # Banner grabbing
                banner = await self._grab_banner(target, port)
                if banner:
                    results['open_ports'][port]['banner'] = banner
                    results['open_ports'][port]['service_version'] = self._parse_service_version(banner, port)
            
            # OS detection using nmap
            os_info = await self._detect_os(target)
            results['os_detection'] = os_info
            
            # Check for common vulnerabilities
            vulns = await self._check_vulnerabilities(target, results['open_ports'])
            results['vulnerabilities'] = vulns
            
        except Exception as e:
            self.logger.error(f"Error scanning {target}: {str(e)}")
            results['error'] = str(e)
        
        self.log_scan_end(target)
        return results
    
    async def _tcp_scan(self, target: str, ports: List[int]) -> Dict[str, Any]:
        """Perform TCP port scan"""
        semaphore = asyncio.Semaphore(self.max_concurrent)
        tasks = []
        
        for port in ports:
            task = self._scan_tcp_port(target, port, semaphore)
            tasks.append(task)
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        open_ports = {}
        closed_ports = []
        
        for result in results:
            if isinstance(result, Exception):
                continue
                
            port, status, service = result
            if status == 'open':
                open_ports[port] = {
                    'protocol': 'tcp',
                    'service': service,
                    'state': 'open'
                }
            else:
                closed_ports.append(port)
        
        return {
            'open_ports': open_ports,
            'closed_ports': closed_ports,
            'filtered_ports': []
        }
    
    async def _scan_tcp_port(self, target: str, port: int, semaphore: asyncio.Semaphore) -> Tuple[int, str, str]:
        """Scan a single TCP port"""
        async with semaphore:
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(target, port),
                    timeout=self.timeout
                )
                writer.close()
                await writer.wait_closed()
                
                service = self.WELL_KNOWN_PORTS.get(port, "Unknown")
                return port, 'open', service
                
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                return port, 'closed', ''
    
    async def _udp_scan(self, target: str, ports: List[int]) -> Dict[str, Any]:
        """Perform UDP port scan"""
        # UDP scanning is more complex and requires different approach
        open_ports = {}
        closed_ports = []
        
        # Use nmap for UDP scanning as it's more reliable
        try:
            self.nm.scan(target, f"{ports[0]}-{ports[-1]}", arguments='-sU')
            
            if target in self.nm.all_hosts():
                for port in self.nm[target]['udp']:
                    state = self.nm[target]['udp'][port]['state']
                    if state == 'open':
                        open_ports[port] = {
                            'protocol': 'udp',
                            'service': self.nm[target]['udp'][port]['name'],
                            'state': 'open'
                        }
                    else:
                        closed_ports.append(port)
        except Exception as e:
            self.logger.error(f"UDP scan failed: {str(e)}")
        
        return {
            'open_ports': open_ports,
            'closed_ports': closed_ports,
            'filtered_ports': []
        }
    
    async def _detect_service(self, target: str, port: int) -> Dict[str, Any]:
        """Enhanced service detection"""
        service_info = {
            'name': self.WELL_KNOWN_PORTS.get(port, "Unknown"),
            'version': None,
            'product': None,
            'cpe': None,
            'scripts': {}
        }
        
        try:
            # Use nmap for detailed service detection
            self.nm.scan(target, str(port), arguments='-sV -sC')
            
            if target in self.nm.all_hosts() and 'tcp' in self.nm[target]:
                if port in self.nm[target]['tcp']:
                    port_info = self.nm[target]['tcp'][port]
                    service_info.update({
                        'name': port_info.get('name', 'Unknown'),
                        'version': port_info.get('version', None),
                        'product': port_info.get('product', None),
                        'cpe': port_info.get('cpe', None),
                        'scripts': port_info.get('script', {})
                    })
        except Exception as e:
            self.logger.error(f"Service detection failed for {target}:{port}: {str(e)}")
        
        return service_info
    
    async def _grab_banner(self, target: str, port: int) -> Optional[str]:
        """Grab service banner"""
        try:
            if port == 443 or port == 8443:
                # SSL/TLS banner grabbing
                return await self._grab_ssl_banner(target, port)
            else:
                # Regular banner grabbing
                return await self._grab_tcp_banner(target, port)
        except Exception as e:
            self.logger.debug(f"Banner grabbing failed for {target}:{port}: {str(e)}")
            return None
    
    async def _grab_tcp_banner(self, target: str, port: int) -> Optional[str]:
        """Grab TCP banner"""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, port),
                timeout=self.timeout
            )
            
            # Send appropriate probe based on port
            probe = self._get_service_probe(port)
            if probe:
                writer.write(probe)
                await writer.drain()
            
            # Read response
            banner = await asyncio.wait_for(reader.read(1024), timeout=3)
            
            writer.close()
            await writer.wait_closed()
            
            return banner.decode('utf-8', errors='ignore').strip()
            
        except Exception:
            return None
    
    async def _grab_ssl_banner(self, target: str, port: int) -> Optional[str]:
        """Grab SSL/TLS banner"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, port, ssl=context),
                timeout=self.timeout
            )
            
            # Send HTTP request for web servers
            writer.write(b'GET / HTTP/1.1\\r\\nHost: ' + target.encode() + b'\\r\\n\\r\\n')
            await writer.drain()
            
            banner = await asyncio.wait_for(reader.read(1024), timeout=3)
            
            writer.close()
            await writer.wait_closed()
            
            return banner.decode('utf-8', errors='ignore').strip()
            
        except Exception:
            return None
    
    def _get_service_probe(self, port: int) -> Optional[bytes]:
        """Get appropriate service probe"""
        probes = {
            80: b'GET / HTTP/1.1\\r\\nHost: localhost\\r\\n\\r\\n',
            25: b'HELO localhost\\r\\n',
            110: b'USER test\\r\\n',
            143: b'A001 CAPABILITY\\r\\n',
            21: b'USER anonymous\\r\\n',
            23: b'\\r\\n',
            3306: b'\\x00\\x00\\x00\\x01',  # MySQL handshake
        }
        return probes.get(port)
    
    def _parse_service_version(self, banner: str, port: int) -> Optional[str]:
        """Parse service version from banner"""
        if not banner:
            return None
        
        # Get service type
        service_type = None
        for service, patterns in self.SERVICE_PATTERNS.items():
            for pattern, format_str in patterns:
                match = pattern.search(banner.encode())
                if match:
                    try:
                        groups = [g.decode('utf-8', errors='ignore') for g in match.groups()]
                        return format_str.format(*groups)
                    except:
                        pass
        
        # Return first line of banner if no pattern matches
        return banner.split('\\n')[0][:100]
    
    async def _detect_os(self, target: str) -> Dict[str, Any]:
        """OS detection using nmap"""
        os_info = {
            'os_match': None,
            'accuracy': 0,
            'os_classes': [],
            'fingerprint': None
        }
        
        try:
            self.nm.scan(target, arguments='-O')
            
            if target in self.nm.all_hosts():
                host_info = self.nm[target]
                
                if 'osmatch' in host_info:
                    os_matches = host_info['osmatch']
                    if os_matches:
                        best_match = os_matches[0]
                        os_info.update({
                            'os_match': best_match.get('name', 'Unknown'),
                            'accuracy': int(best_match.get('accuracy', 0)),
                            'os_classes': [osclass.get('osfamily', 'Unknown') 
                                         for osclass in best_match.get('osclass', [])],
                            'fingerprint': host_info.get('fingerprint', None)
                        })
        except Exception as e:
            self.logger.error(f"OS detection failed: {str(e)}")
        
        return os_info
    
    async def _check_vulnerabilities(self, target: str, open_ports: Dict[int, Dict]) -> List[str]:
        """Check for common port-based vulnerabilities"""
        vulnerabilities = []
        
        for port, info in open_ports.items():
            service = info.get('service', '').lower()
            
            # Check for insecure services
            if port == 21:  # FTP
                vulnerabilities.append(f"FTP service on port {port} - Consider using SFTP/FTPS")
            elif port == 23:  # Telnet
                vulnerabilities.append(f"Telnet service on port {port} - Unencrypted protocol, use SSH instead")
            elif port == 80 and 443 not in open_ports:  # HTTP without HTTPS
                vulnerabilities.append(f"HTTP service on port {port} without HTTPS - Consider enabling SSL/TLS")
            elif port == 139 or port == 445:  # SMB
                vulnerabilities.append(f"SMB service on port {port} - Ensure proper authentication and encryption")
            elif port == 3389:  # RDP
                vulnerabilities.append(f"RDP service on port {port} - Ensure strong authentication and consider VPN")
            elif port == 5900:  # VNC
                vulnerabilities.append(f"VNC service on port {port} - Ensure strong authentication")
            
            # Check for database services exposed to network
            if port in [1433, 1521, 3306, 5432, 6379, 9200, 27017]:
                vulnerabilities.append(f"Database service on port {port} - Ensure proper access controls")
        
        return vulnerabilities