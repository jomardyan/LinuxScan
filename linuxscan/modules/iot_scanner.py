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
IoT Device Scanner
Comprehensive IoT device discovery and security assessment module
"""

import asyncio
import socket
import struct
import json
import re
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
from .base_scanner import BaseScannerModule


class IoTDeviceScanner(BaseScannerModule):
    """Comprehensive IoT device discovery and security assessment scanner"""
    
    def __init__(self, timeout: int = 180):
        super().__init__("iot_device_scanner", timeout)
        self.iot_ports = [
            23, 80, 443, 554, 1883, 5683, 8080, 8443, 8888, 9999,
            5000, 5001, 5555, 7547, 37777, 56789, 6789, 8000, 8090
        ]
        self.iot_signatures = {
            'camera': [
                b'<title>IPCam</title>',
                b'<title>Network Camera</title>',
                b'<title>Web Video Server</title>',
                b'DVR',
                b'IP Camera',
                b'Webcam',
                b'AXIS'
            ],
            'router': [
                b'<title>Router</title>',
                b'<title>Wireless Router</title>',
                b'TP-Link',
                b'Netgear',
                b'Linksys',
                b'D-Link',
                b'ASUS',
                b'Buffalo'
            ],
            'smart_home': [
                b'SmartHome',
                b'Home Automation',
                b'IoT Gateway',
                b'Smart Hub',
                b'Philips Hue',
                b'Nest',
                b'Ring'
            ],
            'industrial': [
                b'SCADA',
                b'HMI',
                b'PLC',
                b'Industrial',
                b'Schneider',
                b'Siemens',
                b'Allen Bradley'
            ],
            'printer': [
                b'HP LaserJet',
                b'Canon',
                b'Epson',
                b'Brother',
                b'Print Server',
                b'Printer'
            ]
        }
        self.upnp_services = [
            'upnp:rootdevice',
            'urn:schemas-upnp-org:device:MediaRenderer:1',
            'urn:schemas-upnp-org:device:MediaServer:1',
            'urn:schemas-upnp-org:device:WANDevice:1',
            'urn:schemas-upnp-org:service:WANIPConnection:1'
        ]
    
    async def scan(self, target: str, **kwargs) -> Dict[str, Any]:
        """Perform IoT device discovery and security scan"""
        self.log_scan_start(target)
        
        # Enhanced target info with reverse DNS
        target_info = self.enhance_target_info(target)
        
        results = {
            'target_info': target_info,
            'scan_type': 'iot_device_scan',
            'timestamp': datetime.now().isoformat(),
            'discovered_devices': [],
            'device_types': {},
            'security_issues': [],
            'upnp_devices': [],
            'mqtt_brokers': [],
            'coap_endpoints': [],
            'default_credentials': [],
            'open_services': []
        }
        
        try:
            # Discover IoT devices
            await self._discover_iot_devices(target, results)
            
            # Scan for UPnP devices
            await self._scan_upnp_devices(target, results)
            
            # Scan for MQTT brokers
            await self._scan_mqtt_brokers(target, results)
            
            # Scan for CoAP endpoints
            await self._scan_coap_endpoints(target, results)
            
            # Check for default credentials
            await self._check_default_credentials(target, results)
            
            # Analyze security issues
            await self._analyze_security_issues(results)
            
        except Exception as e:
            results['error'] = str(e)
            self.logger.error(f"Error in IoT device scan: {e}")
        
        self.log_scan_end(target)
        return results
    
    async def _discover_iot_devices(self, target: str, results: Dict[str, Any]):
        """Discover IoT devices through port scanning and banner grabbing"""
        discovered_devices = []
        
        for port in self.iot_ports:
            try:
                device_info = await self._probe_device(target, port)
                if device_info:
                    discovered_devices.append(device_info)
            except Exception as e:
                self.logger.debug(f"Error probing {target}:{port}: {e}")
        
        # Categorize devices by type
        device_types = {}
        for device in discovered_devices:
            device_type = device.get('type', 'unknown')
            if device_type not in device_types:
                device_types[device_type] = []
            device_types[device_type].append(device)
        
        results['discovered_devices'] = discovered_devices
        results['device_types'] = device_types
    
    async def _probe_device(self, target: str, port: int) -> Optional[Dict[str, Any]]:
        """Probe a device on a specific port"""
        try:
            # Try HTTP first
            if port in [80, 443, 8080, 8443, 8888]:
                return await self._probe_http_device(target, port)
            
            # Try raw socket connection
            return await self._probe_raw_device(target, port)
        
        except Exception as e:
            self.logger.debug(f"Error probing device {target}:{port}: {e}")
            return None
    
    async def _probe_http_device(self, target: str, port: int) -> Optional[Dict[str, Any]]:
        """Probe HTTP-based IoT device"""
        try:
            protocol = 'https' if port in [443, 8443] else 'http'
            
            # Simple HTTP request
            reader, writer = await asyncio.open_connection(target, port)
            
            request = f"GET / HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n"
            writer.write(request.encode())
            await writer.drain()
            
            response = await asyncio.wait_for(reader.read(4096), timeout=10)
            writer.close()
            await writer.wait_closed()
            
            if response:
                response_str = response.decode('utf-8', errors='ignore')
                device_info = {
                    'host': target,
                    'port': port,
                    'protocol': protocol,
                    'service': 'http',
                    'banner': response_str[:500],  # First 500 chars
                    'type': self._identify_device_type(response),
                    'headers': self._parse_http_headers(response_str),
                    'title': self._extract_html_title(response_str)
                }
                
                return device_info
        
        except Exception as e:
            self.logger.debug(f"HTTP probe failed for {target}:{port}: {e}")
        
        return None
    
    async def _probe_raw_device(self, target: str, port: int) -> Optional[Dict[str, Any]]:
        """Probe device using raw socket connection"""
        try:
            reader, writer = await asyncio.open_connection(target, port)
            
            # Send common IoT probe strings
            probes = [b'\r\n', b'GET / HTTP/1.0\r\n\r\n', b'help\r\n']
            
            for probe in probes:
                writer.write(probe)
                await writer.drain()
                
                try:
                    response = await asyncio.wait_for(reader.read(1024), timeout=5)
                    if response:
                        writer.close()
                        await writer.wait_closed()
                        
                        device_info = {
                            'host': target,
                            'port': port,
                            'protocol': 'tcp',
                            'service': self._identify_service(port),
                            'banner': response.decode('utf-8', errors='ignore')[:500],
                            'type': self._identify_device_type(response),
                            'probe_successful': True
                        }
                        
                        return device_info
                
                except asyncio.TimeoutError:
                    continue
            
            writer.close()
            await writer.wait_closed()
        
        except Exception as e:
            self.logger.debug(f"Raw probe failed for {target}:{port}: {e}")
        
        return None
    
    def _identify_device_type(self, response: bytes) -> str:
        """Identify device type based on response"""
        response_lower = response.lower()
        
        for device_type, signatures in self.iot_signatures.items():
            for signature in signatures:
                if signature.lower() in response_lower:
                    return device_type
        
        return 'unknown'
    
    def _identify_service(self, port: int) -> str:
        """Identify service type based on port"""
        service_map = {
            23: 'telnet',
            80: 'http',
            443: 'https',
            554: 'rtsp',
            1883: 'mqtt',
            5683: 'coap',
            8080: 'http-alt',
            8443: 'https-alt',
            37777: 'dahua-dvr',
            56789: 'ip-camera'
        }
        
        return service_map.get(port, 'unknown')
    
    def _parse_http_headers(self, response: str) -> Dict[str, str]:
        """Parse HTTP headers from response"""
        headers = {}
        lines = response.split('\r\n')
        
        for line in lines[1:]:  # Skip status line
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip().lower()] = value.strip()
            elif line.strip() == '':
                break
        
        return headers
    
    def _extract_html_title(self, response: str) -> str:
        """Extract HTML title from response"""
        title_match = re.search(r'<title[^>]*>([^<]+)</title>', response, re.IGNORECASE)
        if title_match:
            return title_match.group(1).strip()
        return ''
    
    async def _scan_upnp_devices(self, target: str, results: Dict[str, Any]):
        """Scan for UPnP devices"""
        upnp_devices = []
        
        try:
            # UPnP discovery via SSDP
            ssdp_request = (
                "M-SEARCH * HTTP/1.1\r\n"
                "HOST: 239.255.255.250:1900\r\n"
                "MAN: \"ssdp:discover\"\r\n"
                "ST: upnp:rootdevice\r\n"
                "MX: 3\r\n\r\n"
            )
            
            # Create UDP socket for multicast
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(10)
            
            try:
                sock.sendto(ssdp_request.encode(), ('239.255.255.250', 1900))
                
                # Collect responses
                responses = []
                start_time = asyncio.get_event_loop().time()
                
                while (asyncio.get_event_loop().time() - start_time) < 10:
                    try:
                        data, addr = sock.recvfrom(1024)
                        response = data.decode('utf-8', errors='ignore')
                        responses.append({'response': response, 'addr': addr})
                    except socket.timeout:
                        break
                
                sock.close()
                
                # Parse UPnP responses
                for resp in responses:
                    upnp_info = self._parse_upnp_response(resp['response'])
                    if upnp_info:
                        upnp_info['source_addr'] = resp['addr'][0]
                        upnp_devices.append(upnp_info)
            
            except Exception as e:
                self.logger.debug(f"UPnP scan error: {e}")
                sock.close()
        
        except Exception as e:
            self.logger.debug(f"UPnP setup error: {e}")
        
        results['upnp_devices'] = upnp_devices
    
    def _parse_upnp_response(self, response: str) -> Optional[Dict[str, Any]]:
        """Parse UPnP SSDP response"""
        try:
            lines = response.split('\r\n')
            upnp_info = {}
            
            for line in lines:
                if ':' in line:
                    key, value = line.split(':', 1)
                    upnp_info[key.strip().lower()] = value.strip()
            
            return upnp_info
        
        except Exception:
            return None
    
    async def _scan_mqtt_brokers(self, target: str, results: Dict[str, Any]):
        """Scan for MQTT brokers"""
        mqtt_brokers = []
        
        mqtt_ports = [1883, 8883, 1884, 8884]
        
        for port in mqtt_ports:
            try:
                # Try to connect to MQTT broker
                reader, writer = await asyncio.open_connection(target, port)
                
                # Send MQTT CONNECT packet
                connect_packet = self._create_mqtt_connect_packet()
                writer.write(connect_packet)
                await writer.drain()
                
                response = await asyncio.wait_for(reader.read(1024), timeout=5)
                writer.close()
                await writer.wait_closed()
                
                if response and len(response) >= 4:
                    # Parse MQTT CONNACK response
                    if response[0] == 0x20:  # CONNACK packet type
                        mqtt_info = {
                            'host': target,
                            'port': port,
                            'protocol': 'mqtt',
                            'connection_successful': True,
                            'return_code': response[3] if len(response) > 3 else 'unknown'
                        }
                        mqtt_brokers.append(mqtt_info)
            
            except Exception as e:
                self.logger.debug(f"MQTT scan error on {target}:{port}: {e}")
        
        results['mqtt_brokers'] = mqtt_brokers
    
    def _create_mqtt_connect_packet(self) -> bytes:
        """Create MQTT CONNECT packet"""
        # Simple MQTT CONNECT packet for testing
        protocol_name = b'MQTT'
        protocol_level = 4
        connect_flags = 0x02  # Clean session
        keep_alive = 60
        client_id = b'iot_scanner'
        
        variable_header = (
            struct.pack('!H', len(protocol_name)) + protocol_name +
            struct.pack('!BBH', protocol_level, connect_flags, keep_alive)
        )
        
        payload = struct.pack('!H', len(client_id)) + client_id
        
        remaining_length = len(variable_header) + len(payload)
        fixed_header = struct.pack('!BB', 0x10, remaining_length)
        
        return fixed_header + variable_header + payload
    
    async def _scan_coap_endpoints(self, target: str, results: Dict[str, Any]):
        """Scan for CoAP endpoints"""
        coap_endpoints = []
        
        try:
            # CoAP discovery
            coap_request = self._create_coap_request()
            
            # Send CoAP request
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(10)
            
            try:
                sock.sendto(coap_request, (target, 5683))
                response, addr = sock.recvfrom(1024)
                
                if response:
                    coap_info = {
                        'host': target,
                        'port': 5683,
                        'protocol': 'coap',
                        'response_length': len(response),
                        'response_data': response.hex()
                    }
                    coap_endpoints.append(coap_info)
            
            except Exception as e:
                self.logger.debug(f"CoAP scan error: {e}")
            
            finally:
                sock.close()
        
        except Exception as e:
            self.logger.debug(f"CoAP setup error: {e}")
        
        results['coap_endpoints'] = coap_endpoints
    
    def _create_coap_request(self) -> bytes:
        """Create CoAP GET request"""
        # Simple CoAP GET request for /.well-known/core
        version = 1
        type_con = 0  # Confirmable
        token_length = 0
        code = 1  # GET
        message_id = 0x1234
        
        header = struct.pack('!BBH', 
                           (version << 6) | (type_con << 4) | token_length,
                           code,
                           message_id)
        
        # Add URI path option for /.well-known/core
        uri_path = b'.well-known/core'
        option = struct.pack('!B', 0xB0 | len(uri_path)) + uri_path
        
        return header + option
    
    async def _check_default_credentials(self, target: str, results: Dict[str, Any]):
        """Check for default credentials on discovered devices"""
        default_creds = []
        
        common_credentials = [
            ('admin', 'admin'),
            ('admin', 'password'),
            ('admin', '123456'),
            ('admin', ''),
            ('root', 'root'),
            ('root', 'password'),
            ('root', ''),
            ('user', 'user'),
            ('guest', 'guest'),
            ('admin', 'changeme')
        ]
        
        for device in results.get('discovered_devices', []):
            if device.get('service') in ['http', 'https']:
                # Check HTTP basic auth
                for username, password in common_credentials:
                    try:
                        cred_result = await self._test_http_credentials(
                            target, device['port'], username, password
                        )
                        if cred_result:
                            default_creds.append({
                                'host': target,
                                'port': device['port'],
                                'username': username,
                                'password': password,
                                'service': device['service'],
                                'device_type': device.get('type', 'unknown')
                            })
                    except Exception as e:
                        self.logger.debug(f"Credential test error: {e}")
        
        results['default_credentials'] = default_creds
    
    async def _test_http_credentials(self, target: str, port: int, username: str, password: str) -> bool:
        """Test HTTP basic authentication credentials"""
        try:
            import base64
            
            # Create basic auth header
            credentials = f"{username}:{password}"
            encoded_credentials = base64.b64encode(credentials.encode()).decode()
            
            # Send HTTP request with auth
            reader, writer = await asyncio.open_connection(target, port)
            
            request = (
                f"GET / HTTP/1.1\r\n"
                f"Host: {target}\r\n"
                f"Authorization: Basic {encoded_credentials}\r\n"
                f"Connection: close\r\n\r\n"
            )
            
            writer.write(request.encode())
            await writer.drain()
            
            response = await asyncio.wait_for(reader.read(1024), timeout=10)
            writer.close()
            await writer.wait_closed()
            
            if response:
                response_str = response.decode('utf-8', errors='ignore')
                # Check if authentication succeeded (not 401)
                if '401 Unauthorized' not in response_str and '403 Forbidden' not in response_str:
                    return True
        
        except Exception as e:
            self.logger.debug(f"HTTP auth test error: {e}")
        
        return False
    
    async def _analyze_security_issues(self, results: Dict[str, Any]):
        """Analyze discovered devices for security issues"""
        security_issues = []
        
        # Check for devices with default credentials
        for cred in results.get('default_credentials', []):
            security_issues.append({
                'type': 'default_credentials',
                'severity': 'high',
                'description': f"Default credentials found on {cred['host']}:{cred['port']} ({cred['username']}:{cred['password']})",
                'device_type': cred.get('device_type', 'unknown')
            })
        
        # Check for unencrypted services
        for device in results.get('discovered_devices', []):
            if device.get('service') == 'http' and device.get('port') != 80:
                security_issues.append({
                    'type': 'unencrypted_service',
                    'severity': 'medium',
                    'description': f"Unencrypted HTTP service on {device['host']}:{device['port']}",
                    'device_type': device.get('type', 'unknown')
                })
        
        # Check for open MQTT brokers
        for mqtt in results.get('mqtt_brokers', []):
            if mqtt.get('return_code') == 0:  # Connection accepted
                security_issues.append({
                    'type': 'open_mqtt_broker',
                    'severity': 'medium',
                    'description': f"Open MQTT broker found on {mqtt['host']}:{mqtt['port']}",
                    'device_type': 'mqtt_broker'
                })
        
        results['security_issues'] = security_issues