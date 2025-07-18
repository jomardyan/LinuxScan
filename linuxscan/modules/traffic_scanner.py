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
Traffic Analysis Scanner
Advanced network traffic analysis and monitoring module
"""

import asyncio
import subprocess
import json
import tempfile
import os
from typing import Dict, List, Any, Optional
from datetime import datetime
from .base_scanner import BaseScannerModule


class TrafficAnalysisScanner(BaseScannerModule):
    """Advanced network traffic analysis and monitoring scanner"""
    
    def __init__(self, timeout: int = 300):
        super().__init__("traffic_analysis_scanner", timeout)
        self.pcap_tools = ['tcpdump', 'tshark', 'dumpcap']
        self.analysis_tools = ['wireshark', 'tcpflow', 'ngrep']
        self.suspicious_patterns = [
            r'password', r'passwd', r'login', r'admin', r'secret',
            r'key', r'token', r'auth', r'credential', r'session'
        ]
        self.malicious_domains = [
            'evil.com', 'malware.com', 'phishing.com', 'botnet.com'
        ]
        self.suspicious_ports = [4444, 4445, 31337, 12345, 54321, 6666, 1337]
    
    async def scan(self, target: str, **kwargs) -> Dict[str, Any]:
        """Perform traffic analysis scan"""
        self.log_scan_start(target)
        
        # Enhanced target info with reverse DNS
        target_info = self.enhance_target_info(target)
        
        results = {
            'target_info': target_info,
            'scan_type': 'traffic_analysis',
            'timestamp': datetime.now().isoformat(),
            'capture_info': {},
            'protocol_analysis': {},
            'security_analysis': {},
            'anomaly_detection': {},
            'suspicious_activities': [],
            'network_flows': [],
            'dns_analysis': {},
            'http_analysis': {}
        }
        
        try:
            # Check if traffic capture tools are available
            available_tools = await self._check_capture_tools()
            if not available_tools:
                results['error'] = 'No traffic capture tools available'
                return results
            
            # Capture network traffic
            capture_duration = kwargs.get('capture_duration', 60)  # Default 60 seconds
            interface = kwargs.get('interface', 'any')
            
            pcap_file = await self._capture_traffic(target, interface, capture_duration, available_tools[0])
            
            if pcap_file:
                results['capture_info'] = {
                    'file_path': pcap_file,
                    'duration': capture_duration,
                    'interface': interface,
                    'tool_used': available_tools[0]
                }
                
                # Analyze captured traffic
                await self._analyze_traffic(pcap_file, results)
                
                # Clean up pcap file
                try:
                    os.unlink(pcap_file)
                except Exception:
                    pass
            
        except Exception as e:
            results['error'] = str(e)
            self.logger.error(f"Error in traffic analysis scan: {e}")
        
        self.log_scan_end(target)
        return results
    
    async def _check_capture_tools(self) -> List[str]:
        """Check which traffic capture tools are available"""
        available_tools = []
        
        for tool in self.pcap_tools:
            try:
                process = await asyncio.create_subprocess_exec(
                    'which', tool,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                await asyncio.wait_for(process.communicate(), timeout=5)
                
                if process.returncode == 0:
                    available_tools.append(tool)
            except Exception:
                continue
        
        return available_tools
    
    async def _capture_traffic(self, target: str, interface: str, duration: int, tool: str) -> Optional[str]:
        """Capture network traffic using specified tool"""
        try:
            # Create temporary pcap file
            temp_fd, pcap_file = tempfile.mkstemp(suffix='.pcap')
            os.close(temp_fd)
            
            # Build capture command
            if tool == 'tcpdump':
                cmd = [
                    'tcpdump', '-i', interface, '-w', pcap_file,
                    '-s', '0', '-n', '-q',
                    f'host {target}',
                    '-G', str(duration), '-W', '1'
                ]
            elif tool == 'tshark':
                cmd = [
                    'tshark', '-i', interface, '-w', pcap_file,
                    '-s', '0', '-n', '-q',
                    '-f', f'host {target}',
                    '-a', f'duration:{duration}'
                ]
            elif tool == 'dumpcap':
                cmd = [
                    'dumpcap', '-i', interface, '-w', pcap_file,
                    '-s', '0', '-n', '-q',
                    '-f', f'host {target}',
                    '-a', f'duration:{duration}'
                ]
            else:
                return None
            
            # Start capture process
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            # Wait for capture to complete
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=duration + 30
            )
            
            if process.returncode == 0 and os.path.exists(pcap_file):
                return pcap_file
            else:
                # Clean up on failure
                try:
                    os.unlink(pcap_file)
                except Exception:
                    pass
                return None
        
        except Exception as e:
            self.logger.error(f"Traffic capture error: {e}")
            return None
    
    async def _analyze_traffic(self, pcap_file: str, results: Dict[str, Any]):
        """Analyze captured traffic file"""
        try:
            # Protocol analysis
            await self._analyze_protocols(pcap_file, results)
            
            # Security analysis
            await self._analyze_security(pcap_file, results)
            
            # Anomaly detection
            await self._detect_anomalies(pcap_file, results)
            
            # DNS analysis
            await self._analyze_dns_traffic(pcap_file, results)
            
            # HTTP analysis
            await self._analyze_http_traffic(pcap_file, results)
            
        except Exception as e:
            self.logger.error(f"Traffic analysis error: {e}")
    
    async def _analyze_protocols(self, pcap_file: str, results: Dict[str, Any]):
        """Analyze network protocols in captured traffic"""
        protocol_stats = {
            'total_packets': 0,
            'protocols': {},
            'top_talkers': [],
            'port_statistics': {}
        }
        
        try:
            # Use tshark for protocol analysis
            cmd = [
                'tshark', '-r', pcap_file, '-T', 'fields',
                '-e', 'frame.number', '-e', 'ip.src', '-e', 'ip.dst',
                '-e', 'ip.proto', '-e', 'tcp.srcport', '-e', 'tcp.dstport',
                '-e', 'udp.srcport', '-e', 'udp.dstport',
                '-E', 'header=y', '-E', 'separator=,'
            ]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=60)
            
            if process.returncode == 0:
                lines = stdout.decode('utf-8').strip().split('\n')
                protocol_stats['total_packets'] = len(lines) - 1  # Exclude header
                
                # Parse protocol statistics
                protocol_counts = {}
                src_ip_counts = {}
                dst_ip_counts = {}
                port_counts = {}
                
                for line in lines[1:]:  # Skip header
                    fields = line.split(',')
                    if len(fields) >= 7:
                        src_ip = fields[1]
                        dst_ip = fields[2]
                        protocol = fields[3]
                        src_port = fields[4] or fields[6]  # TCP or UDP
                        dst_port = fields[5] or fields[7]  # TCP or UDP
                        
                        # Count protocols
                        if protocol:
                            protocol_counts[protocol] = protocol_counts.get(protocol, 0) + 1
                        
                        # Count source IPs
                        if src_ip:
                            src_ip_counts[src_ip] = src_ip_counts.get(src_ip, 0) + 1
                        
                        # Count destination IPs
                        if dst_ip:
                            dst_ip_counts[dst_ip] = dst_ip_counts.get(dst_ip, 0) + 1
                        
                        # Count ports
                        if src_port:
                            port_counts[src_port] = port_counts.get(src_port, 0) + 1
                        if dst_port:
                            port_counts[dst_port] = port_counts.get(dst_port, 0) + 1
                
                # Sort and limit results
                protocol_stats['protocols'] = dict(sorted(protocol_counts.items(), key=lambda x: x[1], reverse=True)[:10])
                
                # Top talkers (source IPs)
                protocol_stats['top_talkers'] = [
                    {'ip': ip, 'packets': count}
                    for ip, count in sorted(src_ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]
                ]
                
                # Port statistics
                protocol_stats['port_statistics'] = dict(sorted(port_counts.items(), key=lambda x: x[1], reverse=True)[:20])
        
        except Exception as e:
            protocol_stats['error'] = str(e)
        
        results['protocol_analysis'] = protocol_stats
    
    async def _analyze_security(self, pcap_file: str, results: Dict[str, Any]):
        """Analyze traffic for security issues"""
        security_analysis = {
            'suspicious_connections': [],
            'malicious_domains': [],
            'port_scans': [],
            'credential_exposure': [],
            'data_exfiltration': []
        }
        
        try:
            # Check for suspicious ports
            await self._check_suspicious_ports(pcap_file, security_analysis)
            
            # Check for credential exposure
            await self._check_credential_exposure(pcap_file, security_analysis)
            
            # Check for data exfiltration patterns
            await self._check_data_exfiltration(pcap_file, security_analysis)
            
        except Exception as e:
            security_analysis['error'] = str(e)
        
        results['security_analysis'] = security_analysis
    
    async def _check_suspicious_ports(self, pcap_file: str, security_analysis: Dict[str, Any]):
        """Check for connections to suspicious ports"""
        try:
            cmd = [
                'tshark', '-r', pcap_file, '-T', 'fields',
                '-e', 'ip.src', '-e', 'ip.dst', '-e', 'tcp.dstport',
                '-E', 'separator=,'
            ]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=30)
            
            if process.returncode == 0:
                lines = stdout.decode('utf-8').strip().split('\n')
                
                for line in lines:
                    fields = line.split(',')
                    if len(fields) >= 3:
                        src_ip = fields[0]
                        dst_ip = fields[1]
                        dst_port = fields[2]
                        
                        if dst_port and dst_port.isdigit():
                            port = int(dst_port)
                            if port in self.suspicious_ports:
                                security_analysis['suspicious_connections'].append({
                                    'src_ip': src_ip,
                                    'dst_ip': dst_ip,
                                    'dst_port': port,
                                    'reason': 'Suspicious port'
                                })
        
        except Exception as e:
            self.logger.debug(f"Suspicious port check error: {e}")
    
    async def _check_credential_exposure(self, pcap_file: str, security_analysis: Dict[str, Any]):
        """Check for exposed credentials in traffic"""
        try:
            # Use tshark to extract HTTP data
            cmd = [
                'tshark', '-r', pcap_file, '-T', 'fields',
                '-e', 'http.request.method', '-e', 'http.request.uri',
                '-e', 'http.request.full_uri', '-e', 'http.request.line',
                '-Y', 'http.request',
                '-E', 'separator=,'
            ]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=30)
            
            if process.returncode == 0:
                lines = stdout.decode('utf-8').strip().split('\n')
                
                for line in lines:
                    line_lower = line.lower()
                    for pattern in self.suspicious_patterns:
                        if pattern in line_lower:
                            security_analysis['credential_exposure'].append({
                                'data': line[:200],  # Truncate for safety
                                'pattern': pattern,
                                'protocol': 'HTTP'
                            })
        
        except Exception as e:
            self.logger.debug(f"Credential exposure check error: {e}")
    
    async def _check_data_exfiltration(self, pcap_file: str, security_analysis: Dict[str, Any]):
        """Check for data exfiltration patterns"""
        try:
            # Look for large uploads or unusual data patterns
            cmd = [
                'tshark', '-r', pcap_file, '-T', 'fields',
                '-e', 'ip.src', '-e', 'ip.dst', '-e', 'tcp.len',
                '-e', 'udp.length', '-e', 'frame.time',
                '-E', 'separator=,'
            ]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=30)
            
            if process.returncode == 0:
                lines = stdout.decode('utf-8').strip().split('\n')
                
                # Analyze data volumes
                src_volumes = {}
                
                for line in lines:
                    fields = line.split(',')
                    if len(fields) >= 5:
                        src_ip = fields[0]
                        tcp_len = fields[2]
                        udp_len = fields[3]
                        
                        data_len = 0
                        if tcp_len and tcp_len.isdigit():
                            data_len = int(tcp_len)
                        elif udp_len and udp_len.isdigit():
                            data_len = int(udp_len)
                        
                        if src_ip and data_len > 0:
                            src_volumes[src_ip] = src_volumes.get(src_ip, 0) + data_len
                
                # Flag high volume sources
                for src_ip, volume in src_volumes.items():
                    if volume > 1024 * 1024:  # > 1MB
                        security_analysis['data_exfiltration'].append({
                            'src_ip': src_ip,
                            'volume_bytes': volume,
                            'reason': 'High data volume'
                        })
        
        except Exception as e:
            self.logger.debug(f"Data exfiltration check error: {e}")
    
    async def _detect_anomalies(self, pcap_file: str, results: Dict[str, Any]):
        """Detect network anomalies"""
        anomalies = {
            'high_connection_rate': [],
            'unusual_protocols': [],
            'time_based_anomalies': [],
            'size_anomalies': []
        }
        
        try:
            # Analyze connection patterns
            await self._analyze_connection_patterns(pcap_file, anomalies)
            
        except Exception as e:
            anomalies['error'] = str(e)
        
        results['anomaly_detection'] = anomalies
    
    async def _analyze_connection_patterns(self, pcap_file: str, anomalies: Dict[str, Any]):
        """Analyze connection patterns for anomalies"""
        try:
            cmd = [
                'tshark', '-r', pcap_file, '-T', 'fields',
                '-e', 'frame.time_relative', '-e', 'ip.src', '-e', 'ip.dst',
                '-e', 'tcp.flags', '-e', 'tcp.dstport',
                '-E', 'separator=,'
            ]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=30)
            
            if process.returncode == 0:
                lines = stdout.decode('utf-8').strip().split('\n')
                
                # Analyze connection rates
                connection_times = {}
                
                for line in lines:
                    fields = line.split(',')
                    if len(fields) >= 5:
                        time_str = fields[0]
                        src_ip = fields[1]
                        dst_ip = fields[2]
                        tcp_flags = fields[3]
                        dst_port = fields[4]
                        
                        # Look for SYN packets (new connections)
                        if tcp_flags and '2' in tcp_flags:  # SYN flag
                            if src_ip not in connection_times:
                                connection_times[src_ip] = []
                            
                            try:
                                time_val = float(time_str)
                                connection_times[src_ip].append(time_val)
                            except ValueError:
                                continue
                
                # Check for high connection rates
                for src_ip, times in connection_times.items():
                    if len(times) > 50:  # > 50 connections
                        # Calculate rate
                        if len(times) > 1:
                            duration = max(times) - min(times)
                            if duration > 0:
                                rate = len(times) / duration
                                if rate > 5:  # > 5 connections per second
                                    anomalies['high_connection_rate'].append({
                                        'src_ip': src_ip,
                                        'connection_count': len(times),
                                        'rate_per_second': round(rate, 2),
                                        'duration': round(duration, 2)
                                    })
        
        except Exception as e:
            self.logger.debug(f"Connection pattern analysis error: {e}")
    
    async def _analyze_dns_traffic(self, pcap_file: str, results: Dict[str, Any]):
        """Analyze DNS traffic"""
        dns_analysis = {
            'queries': [],
            'responses': [],
            'suspicious_domains': [],
            'query_statistics': {}
        }
        
        try:
            cmd = [
                'tshark', '-r', pcap_file, '-T', 'fields',
                '-e', 'dns.qry.name', '-e', 'dns.resp.name',
                '-e', 'dns.a', '-e', 'dns.qry.type',
                '-Y', 'dns',
                '-E', 'separator=,'
            ]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=30)
            
            if process.returncode == 0:
                lines = stdout.decode('utf-8').strip().split('\n')
                
                query_counts = {}
                
                for line in lines:
                    fields = line.split(',')
                    if len(fields) >= 4:
                        query_name = fields[0]
                        response_name = fields[1]
                        ip_address = fields[2]
                        query_type = fields[3]
                        
                        if query_name:
                            dns_analysis['queries'].append({
                                'domain': query_name,
                                'type': query_type,
                                'response_ip': ip_address
                            })
                            
                            query_counts[query_name] = query_counts.get(query_name, 0) + 1
                            
                            # Check for suspicious domains
                            if any(malicious in query_name.lower() for malicious in self.malicious_domains):
                                dns_analysis['suspicious_domains'].append({
                                    'domain': query_name,
                                    'reason': 'Matched malicious domain pattern'
                                })
                
                # Top queried domains
                dns_analysis['query_statistics'] = dict(
                    sorted(query_counts.items(), key=lambda x: x[1], reverse=True)[:20]
                )
        
        except Exception as e:
            dns_analysis['error'] = str(e)
        
        results['dns_analysis'] = dns_analysis
    
    async def _analyze_http_traffic(self, pcap_file: str, results: Dict[str, Any]):
        """Analyze HTTP traffic"""
        http_analysis = {
            'requests': [],
            'responses': [],
            'user_agents': [],
            'hosts': [],
            'suspicious_requests': []
        }
        
        try:
            cmd = [
                'tshark', '-r', pcap_file, '-T', 'fields',
                '-e', 'http.request.method', '-e', 'http.request.uri',
                '-e', 'http.host', '-e', 'http.user_agent',
                '-e', 'http.response.code',
                '-Y', 'http',
                '-E', 'separator=,'
            ]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=30)
            
            if process.returncode == 0:
                lines = stdout.decode('utf-8').strip().split('\n')
                
                user_agent_counts = {}
                host_counts = {}
                
                for line in lines:
                    fields = line.split(',')
                    if len(fields) >= 5:
                        method = fields[0]
                        uri = fields[1]
                        host = fields[2]
                        user_agent = fields[3]
                        response_code = fields[4]
                        
                        if method and uri:
                            request_info = {
                                'method': method,
                                'uri': uri,
                                'host': host,
                                'user_agent': user_agent,
                                'response_code': response_code
                            }
                            
                            http_analysis['requests'].append(request_info)
                            
                            # Count user agents
                            if user_agent:
                                user_agent_counts[user_agent] = user_agent_counts.get(user_agent, 0) + 1
                            
                            # Count hosts
                            if host:
                                host_counts[host] = host_counts.get(host, 0) + 1
                            
                            # Check for suspicious requests
                            if any(pattern in uri.lower() for pattern in self.suspicious_patterns):
                                http_analysis['suspicious_requests'].append({
                                    'request': request_info,
                                    'reason': 'Suspicious URI pattern'
                                })
                
                # Top user agents and hosts
                http_analysis['user_agents'] = dict(
                    sorted(user_agent_counts.items(), key=lambda x: x[1], reverse=True)[:10]
                )
                
                http_analysis['hosts'] = dict(
                    sorted(host_counts.items(), key=lambda x: x[1], reverse=True)[:10]
                )
        
        except Exception as e:
            http_analysis['error'] = str(e)
        
        results['http_analysis'] = http_analysis