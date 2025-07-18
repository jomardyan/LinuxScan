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
Network scanner for traffic analysis and network security
"""

import asyncio
import socket
import struct
import time
import ipaddress
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
from collections import defaultdict
import subprocess
import threading
import json
from .base_scanner import BaseScannerModule

try:
    import scapy.all as scapy
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    scapy = None

try:
    import netaddr
    NETADDR_AVAILABLE = True
except ImportError:
    NETADDR_AVAILABLE = False
    netaddr = None


class NetworkScanner(BaseScannerModule):
    """Network scanner for traffic analysis and network security"""
    
    def __init__(self, timeout: int = 30, capture_duration: int = 60):
        super().__init__("network_scanner", timeout)
        self.capture_duration = capture_duration
        self.packet_count = 0
        self.traffic_data = defaultdict(dict)
        self.suspicious_patterns = []
        
    async def scan(self, target: str, scan_type: str = 'discovery',
                   interface: Optional[str] = None, **kwargs) -> Dict[str, Any]:
        """
        Comprehensive network scan
        """
        self.log_scan_start(target)
        
        results = {
            'target': target,
            'scan_type': scan_type,
            'timestamp': datetime.now().isoformat(),
            'network_discovery': {},
            'traffic_analysis': {},
            'protocol_analysis': {},
            'anomaly_detection': {},
            'dns_enumeration': {},
            'wireless_analysis': {},
            'bluetooth_analysis': {},
            'vulnerabilities': []
        }
        
        try:
            if scan_type == 'discovery':
                results['network_discovery'] = await self._network_discovery(target)
            elif scan_type == 'traffic':
                results['traffic_analysis'] = await self._traffic_analysis(target, interface)
            elif scan_type == 'protocol':
                results['protocol_analysis'] = await self._protocol_analysis(target)
            elif scan_type == 'dns':
                results['dns_enumeration'] = await self._dns_enumeration(target)
            elif scan_type == 'wireless':
                results['wireless_analysis'] = await self._wireless_analysis(interface)
            elif scan_type == 'bluetooth':
                results['bluetooth_analysis'] = await self._bluetooth_analysis()
            elif scan_type == 'comprehensive':
                # Run all scans
                results['network_discovery'] = await self._network_discovery(target)
                results['traffic_analysis'] = await self._traffic_analysis(target, interface)
                results['protocol_analysis'] = await self._protocol_analysis(target)
                results['dns_enumeration'] = await self._dns_enumeration(target)
                results['anomaly_detection'] = await self._anomaly_detection(target)
            
            # Check for network vulnerabilities
            results['vulnerabilities'] = await self._check_network_vulnerabilities(results)
            
        except Exception as e:
            self.logger.error(f"Error during network scan of {target}: {str(e)}")
            results['error'] = str(e)
        
        self.log_scan_end(target)
        return results
    
    async def _network_discovery(self, target: str) -> Dict[str, Any]:
        """Network discovery and host enumeration"""
        discovery_results = {
            'live_hosts': [],
            'host_details': {},
            'network_topology': {},
            'arp_table': {},
            'routing_table': {},
            'network_services': {}
        }
        
        try:
            # Parse network range
            if '/' in target:
                network = ipaddress.ip_network(target, strict=False)
                hosts = list(network.hosts())
            else:
                hosts = [ipaddress.ip_address(target)]
            
            # Ping sweep to find live hosts
            live_hosts = await self._ping_sweep(hosts)
            discovery_results['live_hosts'] = [str(host) for host in live_hosts]
            
            # ARP discovery for local network
            if SCAPY_AVAILABLE:
                arp_results = await self._arp_discovery(target)
                discovery_results['arp_table'] = arp_results
            
            # OS fingerprinting for live hosts
            for host in live_hosts:
                host_info = await self._os_fingerprint(str(host))
                discovery_results['host_details'][str(host)] = host_info
            
            # Network topology discovery
            topology = await self._discover_topology(live_hosts)
            discovery_results['network_topology'] = topology
            
        except Exception as e:
            self.logger.error(f"Network discovery failed: {str(e)}")
            discovery_results['error'] = str(e)
        
        return discovery_results
    
    async def _traffic_analysis(self, target: str, interface: Optional[str] = None) -> Dict[str, Any]:
        """Network traffic analysis"""
        traffic_results = {
            'packet_count': 0,
            'protocols': {},
            'top_talkers': {},
            'connections': {},
            'suspicious_traffic': [],
            'bandwidth_usage': {},
            'flow_analysis': {}
        }
        
        if not SCAPY_AVAILABLE:
            traffic_results['error'] = "Scapy not available for traffic analysis"
            return traffic_results
        
        try:
            # Start packet capture
            packets = await self._capture_packets(target, interface, self.capture_duration)
            traffic_results['packet_count'] = len(packets)
            
            # Analyze protocols
            protocols = self._analyze_protocols(packets)
            traffic_results['protocols'] = protocols
            
            # Find top talkers
            top_talkers = self._find_top_talkers(packets)
            traffic_results['top_talkers'] = top_talkers
            
            # Analyze connections
            connections = self._analyze_connections(packets)
            traffic_results['connections'] = connections
            
            # Detect suspicious traffic
            suspicious = self._detect_suspicious_traffic(packets)
            traffic_results['suspicious_traffic'] = suspicious
            
            # Calculate bandwidth usage
            bandwidth = self._calculate_bandwidth(packets)
            traffic_results['bandwidth_usage'] = bandwidth
            
        except Exception as e:
            self.logger.error(f"Traffic analysis failed: {str(e)}")
            traffic_results['error'] = str(e)
        
        return traffic_results
    
    async def _protocol_analysis(self, target: str) -> Dict[str, Any]:
        """Protocol-specific analysis"""
        protocol_results = {
            'tcp_analysis': {},
            'udp_analysis': {},
            'icmp_analysis': {},
            'http_analysis': {},
            'dns_analysis': {},
            'ssl_analysis': {},
            'smtp_analysis': {},
            'ftp_analysis': {}
        }
        
        try:
            # TCP analysis
            protocol_results['tcp_analysis'] = await self._analyze_tcp(target)
            
            # UDP analysis
            protocol_results['udp_analysis'] = await self._analyze_udp(target)
            
            # ICMP analysis
            protocol_results['icmp_analysis'] = await self._analyze_icmp(target)
            
            # Application layer analysis
            protocol_results['http_analysis'] = await self._analyze_http(target)
            protocol_results['dns_analysis'] = await self._analyze_dns(target)
            protocol_results['ssl_analysis'] = await self._analyze_ssl(target)
            
        except Exception as e:
            self.logger.error(f"Protocol analysis failed: {str(e)}")
            protocol_results['error'] = str(e)
        
        return protocol_results
    
    async def _dns_enumeration(self, target: str) -> Dict[str, Any]:
        """DNS enumeration and reconnaissance"""
        dns_results = {
            'a_records': [],
            'aaaa_records': [],
            'mx_records': [],
            'ns_records': [],
            'txt_records': [],
            'cname_records': [],
            'ptr_records': [],
            'srv_records': [],
            'zone_transfer': {},
            'dns_bruteforce': {},
            'dns_vulnerabilities': []
        }
        
        try:
            # DNS record enumeration
            record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'PTR', 'SRV']
            
            for record_type in record_types:
                records = await self._query_dns_records(target, record_type)
                dns_results[f'{record_type.lower()}_records'] = records
            
            # Zone transfer attempt
            zone_transfer = await self._attempt_zone_transfer(target)
            dns_results['zone_transfer'] = zone_transfer
            
            # DNS bruteforce
            bruteforce = await self._dns_bruteforce(target)
            dns_results['dns_bruteforce'] = bruteforce
            
            # DNS security checks
            dns_vulns = await self._check_dns_vulnerabilities(target)
            dns_results['dns_vulnerabilities'] = dns_vulns
            
        except Exception as e:
            self.logger.error(f"DNS enumeration failed: {str(e)}")
            dns_results['error'] = str(e)
        
        return dns_results
    
    async def _wireless_analysis(self, interface: Optional[str] = None) -> Dict[str, Any]:
        """Wireless network analysis"""
        wireless_results = {
            'access_points': [],
            'stations': [],
            'security_analysis': {},
            'wps_analysis': {},
            'rogue_ap_detection': {},
            'wireless_vulnerabilities': []
        }
        
        try:
            # Wireless scanning requires specific tools
            if not interface:
                wireless_results['error'] = "No wireless interface specified"
                return wireless_results
            
            # Scan for access points
            access_points = await self._scan_access_points(interface)
            wireless_results['access_points'] = access_points
            
            # Scan for stations
            stations = await self._scan_stations(interface)
            wireless_results['stations'] = stations
            
            # Security analysis
            security_analysis = await self._analyze_wireless_security(access_points)
            wireless_results['security_analysis'] = security_analysis
            
            # WPS analysis
            wps_analysis = await self._analyze_wps(access_points)
            wireless_results['wps_analysis'] = wps_analysis
            
            # Rogue AP detection
            rogue_detection = await self._detect_rogue_aps(access_points)
            wireless_results['rogue_ap_detection'] = rogue_detection
            
        except Exception as e:
            self.logger.error(f"Wireless analysis failed: {str(e)}")
            wireless_results['error'] = str(e)
        
        return wireless_results
    
    async def _bluetooth_analysis(self) -> Dict[str, Any]:
        """Bluetooth analysis"""
        bluetooth_results = {
            'discoverable_devices': [],
            'device_info': {},
            'service_discovery': {},
            'security_analysis': {},
            'bluetooth_vulnerabilities': []
        }
        
        try:
            # Bluetooth scanning requires specific tools
            devices = await self._scan_bluetooth_devices()
            bluetooth_results['discoverable_devices'] = devices
            
            # Device information gathering
            for device in devices:
                device_info = await self._get_bluetooth_device_info(device)
                bluetooth_results['device_info'][device] = device_info
            
            # Service discovery
            services = await self._discover_bluetooth_services(devices)
            bluetooth_results['service_discovery'] = services
            
            # Security analysis
            security_analysis = await self._analyze_bluetooth_security(devices)
            bluetooth_results['security_analysis'] = security_analysis
            
        except Exception as e:
            self.logger.error(f"Bluetooth analysis failed: {str(e)}")
            bluetooth_results['error'] = str(e)
        
        return bluetooth_results
    
    async def _anomaly_detection(self, target: str) -> Dict[str, Any]:
        """Network anomaly detection"""
        anomaly_results = {
            'traffic_anomalies': [],
            'protocol_anomalies': [],
            'behavioral_anomalies': [],
            'security_anomalies': [],
            'recommendations': []
        }
        
        try:
            # Traffic pattern analysis
            traffic_anomalies = await self._detect_traffic_anomalies(target)
            anomaly_results['traffic_anomalies'] = traffic_anomalies
            
            # Protocol anomaly detection
            protocol_anomalies = await self._detect_protocol_anomalies(target)
            anomaly_results['protocol_anomalies'] = protocol_anomalies
            
            # Behavioral analysis
            behavioral_anomalies = await self._detect_behavioral_anomalies(target)
            anomaly_results['behavioral_anomalies'] = behavioral_anomalies
            
            # Security anomaly detection
            security_anomalies = await self._detect_security_anomalies(target)
            anomaly_results['security_anomalies'] = security_anomalies
            
            # Generate recommendations
            recommendations = self._generate_anomaly_recommendations(anomaly_results)
            anomaly_results['recommendations'] = recommendations
            
        except Exception as e:
            self.logger.error(f"Anomaly detection failed: {str(e)}")
            anomaly_results['error'] = str(e)
        
        return anomaly_results
    
    async def _ping_sweep(self, hosts: List[ipaddress.IPv4Address]) -> List[ipaddress.IPv4Address]:
        """Ping sweep to find live hosts"""
        live_hosts = []
        
        # Limit concurrent pings
        semaphore = asyncio.Semaphore(50)
        
        async def ping_host(host):
            async with semaphore:
                try:
                    proc = await asyncio.create_subprocess_exec(
                        'ping', '-c', '1', '-W', '1', str(host),
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                    await proc.communicate()
                    if proc.returncode == 0:
                        return host
                except:
                    pass
                return None
        
        tasks = [ping_host(host) for host in hosts[:254]]  # Limit to /24
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if result and not isinstance(result, Exception):
                live_hosts.append(result)
        
        return live_hosts
    
    async def _arp_discovery(self, target: str) -> Dict[str, Any]:
        """ARP discovery for local network"""
        arp_results = {}
        
        if not SCAPY_AVAILABLE:
            return {'error': 'Scapy not available'}
        
        try:
            # ARP request to discover local hosts
            arp_request = scapy.ARP(pdst=target)
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request
            
            answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]
            
            for element in answered_list:
                client_dict = {
                    'ip': element[1].psrc,
                    'mac': element[1].hwsrc
                }
                arp_results[client_dict['ip']] = client_dict['mac']
                
        except Exception as e:
            arp_results['error'] = str(e)
        
        return arp_results
    
    async def _os_fingerprint(self, host: str) -> Dict[str, Any]:
        """OS fingerprinting"""
        os_info = {
            'os_guess': 'Unknown',
            'confidence': 0,
            'fingerprint_method': 'TCP'
        }
        
        try:
            # Use nmap for OS detection
            import nmap
            nm = nmap.PortScanner()
            nm.scan(host, arguments='-O')
            
            if host in nm.all_hosts():
                if 'osmatch' in nm[host]:
                    os_matches = nm[host]['osmatch']
                    if os_matches:
                        best_match = os_matches[0]
                        os_info.update({
                            'os_guess': best_match.get('name', 'Unknown'),
                            'confidence': int(best_match.get('accuracy', 0)),
                            'fingerprint_method': 'nmap'
                        })
        except Exception as e:
            os_info['error'] = str(e)
        
        return os_info
    
    async def _discover_topology(self, hosts: List[ipaddress.IPv4Address]) -> Dict[str, Any]:
        """Discover network topology"""
        topology = {
            'subnets': [],
            'gateways': [],
            'routers': [],
            'switches': []
        }
        
        try:
            # Analyze IP ranges to determine subnets
            ip_strings = [str(host) for host in hosts]
            
            # Group by subnet
            subnets = {}
            for ip_str in ip_strings:
                ip = ipaddress.ip_address(ip_str)
                # Assume /24 subnet
                subnet = str(ipaddress.ip_network(f"{ip}/24", strict=False))
                if subnet not in subnets:
                    subnets[subnet] = []
                subnets[subnet].append(ip_str)
            
            topology['subnets'] = list(subnets.keys())
            
            # Try to identify gateways (first IP in range)
            for subnet in subnets:
                network = ipaddress.ip_network(subnet)
                gateway = str(network.network_address + 1)
                topology['gateways'].append(gateway)
                
        except Exception as e:
            topology['error'] = str(e)
        
        return topology
    
    async def _capture_packets(self, target: str, interface: Optional[str], duration: int) -> List:
        """Capture network packets"""
        packets = []
        
        if not SCAPY_AVAILABLE:
            return packets
        
        try:
            # Capture packets for specified duration
            filter_str = f"host {target}" if target else None
            packets = scapy.sniff(
                iface=interface,
                timeout=duration,
                filter=filter_str,
                count=1000  # Limit packet count
            )
        except Exception as e:
            self.logger.error(f"Packet capture failed: {str(e)}")
        
        return packets
    
    def _analyze_protocols(self, packets: List) -> Dict[str, int]:
        """Analyze network protocols"""
        protocols = defaultdict(int)
        
        for packet in packets:
            if hasattr(packet, 'proto'):
                if packet.proto == 1:  # ICMP
                    protocols['ICMP'] += 1
                elif packet.proto == 6:  # TCP
                    protocols['TCP'] += 1
                elif packet.proto == 17:  # UDP
                    protocols['UDP'] += 1
                else:
                    protocols['Other'] += 1
        
        return dict(protocols)
    
    def _find_top_talkers(self, packets: List) -> Dict[str, int]:
        """Find top talking hosts"""
        talkers = defaultdict(int)
        
        for packet in packets:
            if hasattr(packet, 'src'):
                talkers[packet.src] += 1
            if hasattr(packet, 'dst'):
                talkers[packet.dst] += 1
        
        # Return top 10 talkers
        return dict(sorted(talkers.items(), key=lambda x: x[1], reverse=True)[:10])
    
    def _analyze_connections(self, packets: List) -> Dict[str, Any]:
        """Analyze network connections"""
        connections = {
            'tcp_connections': 0,
            'udp_connections': 0,
            'unique_connections': set(),
            'connection_details': []
        }
        
        for packet in packets:
            if hasattr(packet, 'src') and hasattr(packet, 'dst'):
                if hasattr(packet, 'sport') and hasattr(packet, 'dport'):
                    connection = f"{packet.src}:{packet.sport} -> {packet.dst}:{packet.dport}"
                    connections['unique_connections'].add(connection)
                    
                    if packet.proto == 6:  # TCP
                        connections['tcp_connections'] += 1
                    elif packet.proto == 17:  # UDP
                        connections['udp_connections'] += 1
        
        connections['unique_connections'] = len(connections['unique_connections'])
        return connections
    
    def _detect_suspicious_traffic(self, packets: List) -> List[str]:
        """Detect suspicious network traffic"""
        suspicious = []
        
        # Track port scan attempts
        port_scan_threshold = 10
        src_ports = defaultdict(set)
        
        for packet in packets:
            if hasattr(packet, 'src') and hasattr(packet, 'dport'):
                src_ports[packet.src].add(packet.dport)
        
        for src, ports in src_ports.items():
            if len(ports) > port_scan_threshold:
                suspicious.append(f"Potential port scan from {src} ({len(ports)} ports)")
        
        return suspicious
    
    def _calculate_bandwidth(self, packets: List) -> Dict[str, int]:
        """Calculate bandwidth usage"""
        bandwidth = {
            'total_bytes': 0,
            'average_packet_size': 0,
            'packets_per_second': 0
        }
        
        total_bytes = sum(len(packet) for packet in packets)
        bandwidth['total_bytes'] = total_bytes
        
        if packets:
            bandwidth['average_packet_size'] = total_bytes // len(packets)
            bandwidth['packets_per_second'] = len(packets) // self.capture_duration
        
        return bandwidth
    
    # Placeholder methods for advanced analysis
    async def _analyze_tcp(self, target: str) -> Dict[str, Any]:
        """TCP-specific analysis"""
        return {'status': 'not_implemented'}
    
    async def _analyze_udp(self, target: str) -> Dict[str, Any]:
        """UDP-specific analysis"""
        return {'status': 'not_implemented'}
    
    async def _analyze_icmp(self, target: str) -> Dict[str, Any]:
        """ICMP-specific analysis"""
        return {'status': 'not_implemented'}
    
    async def _analyze_http(self, target: str) -> Dict[str, Any]:
        """HTTP-specific analysis"""
        return {'status': 'not_implemented'}
    
    async def _analyze_dns(self, target: str) -> Dict[str, Any]:
        """DNS-specific analysis"""
        return {'status': 'not_implemented'}
    
    async def _analyze_ssl(self, target: str) -> Dict[str, Any]:
        """SSL-specific analysis"""
        return {'status': 'not_implemented'}
    
    async def _query_dns_records(self, target: str, record_type: str) -> List[str]:
        """Query DNS records"""
        records = []
        
        try:
            import dns.resolver
            
            resolver = dns.resolver.Resolver()
            answers = resolver.resolve(target, record_type)
            
            for answer in answers:
                records.append(str(answer))
                
        except Exception as e:
            self.logger.debug(f"DNS query failed for {target} {record_type}: {str(e)}")
        
        return records
    
    async def _attempt_zone_transfer(self, target: str) -> Dict[str, Any]:
        """Attempt DNS zone transfer"""
        return {'status': 'not_implemented'}
    
    async def _dns_bruteforce(self, target: str) -> Dict[str, Any]:
        """DNS bruteforce"""
        return {'status': 'not_implemented'}
    
    async def _check_dns_vulnerabilities(self, target: str) -> List[str]:
        """Check DNS vulnerabilities"""
        return []
    
    async def _scan_access_points(self, interface: str) -> List[Dict[str, Any]]:
        """Scan for wireless access points"""
        return []
    
    async def _scan_stations(self, interface: str) -> List[Dict[str, Any]]:
        """Scan for wireless stations"""
        return []
    
    async def _analyze_wireless_security(self, access_points: List) -> Dict[str, Any]:
        """Analyze wireless security"""
        return {'status': 'not_implemented'}
    
    async def _analyze_wps(self, access_points: List) -> Dict[str, Any]:
        """Analyze WPS"""
        return {'status': 'not_implemented'}
    
    async def _detect_rogue_aps(self, access_points: List) -> Dict[str, Any]:
        """Detect rogue access points"""
        return {'status': 'not_implemented'}
    
    async def _scan_bluetooth_devices(self) -> List[str]:
        """Scan for Bluetooth devices"""
        return []
    
    async def _get_bluetooth_device_info(self, device: str) -> Dict[str, Any]:
        """Get Bluetooth device information"""
        return {'status': 'not_implemented'}
    
    async def _discover_bluetooth_services(self, devices: List) -> Dict[str, Any]:
        """Discover Bluetooth services"""
        return {'status': 'not_implemented'}
    
    async def _analyze_bluetooth_security(self, devices: List) -> Dict[str, Any]:
        """Analyze Bluetooth security"""
        return {'status': 'not_implemented'}
    
    async def _detect_traffic_anomalies(self, target: str) -> List[str]:
        """Detect traffic anomalies"""
        return []
    
    async def _detect_protocol_anomalies(self, target: str) -> List[str]:
        """Detect protocol anomalies"""
        return []
    
    async def _detect_behavioral_anomalies(self, target: str) -> List[str]:
        """Detect behavioral anomalies"""
        return []
    
    async def _detect_security_anomalies(self, target: str) -> List[str]:
        """Detect security anomalies"""
        return []
    
    def _generate_anomaly_recommendations(self, anomaly_results: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on anomalies"""
        recommendations = []
        
        if anomaly_results['traffic_anomalies']:
            recommendations.append("Monitor traffic patterns for unusual activity")
        
        if anomaly_results['protocol_anomalies']:
            recommendations.append("Investigate protocol violations")
        
        if anomaly_results['behavioral_anomalies']:
            recommendations.append("Review behavioral patterns for security threats")
        
        if anomaly_results['security_anomalies']:
            recommendations.append("Address security anomalies immediately")
        
        return recommendations
    
    async def _check_network_vulnerabilities(self, results: Dict[str, Any]) -> List[str]:
        """Check for network vulnerabilities"""
        vulnerabilities = []
        
        # Check for common network vulnerabilities
        if 'network_discovery' in results:
            discovery = results['network_discovery']
            
            if 'live_hosts' in discovery and len(discovery['live_hosts']) > 50:
                vulnerabilities.append("Large number of live hosts detected - potential for lateral movement")
            
            if 'arp_table' in discovery and discovery['arp_table']:
                vulnerabilities.append("ARP table accessible - potential for ARP spoofing attacks")
        
        if 'traffic_analysis' in results:
            traffic = results['traffic_analysis']
            
            if 'suspicious_traffic' in traffic and traffic['suspicious_traffic']:
                vulnerabilities.extend(traffic['suspicious_traffic'])
        
        return vulnerabilities