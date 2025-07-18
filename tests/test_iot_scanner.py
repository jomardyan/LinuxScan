"""
Tests for IoT Scanner module
"""

import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime

from linuxscan.modules.iot_scanner import IoTDeviceScanner


class TestIoTDeviceScanner:
    """Test IoTDeviceScanner module"""
    
    def test_init(self):
        """Test IoTDeviceScanner initialization"""
        scanner = IoTDeviceScanner()
        assert scanner.name == "iot_scanner"
        assert scanner.timeout == 60
        assert len(scanner.iot_ports) > 0
        assert len(scanner.iot_signatures) > 0
        assert len(scanner.common_credentials) > 0
        
        # Check specific IoT ports
        assert 1883 in scanner.iot_ports  # MQTT
        assert 5683 in scanner.iot_ports  # CoAP
        assert 8080 in scanner.iot_ports  # HTTP alternate
    
    @pytest.mark.asyncio
    async def test_scan_basic(self):
        """Test basic IoT scanning"""
        scanner = IoTDeviceScanner()
        
        with patch.object(scanner, '_device_discovery') as mock_discovery:
            mock_discovery.return_value = {
                'detected_devices': [
                    {'ip': '192.168.1.100', 'type': 'camera', 'vendor': 'Hikvision'}
                ],
                'protocols': ['HTTP', 'RTSP']
            }
            
            with patch.object(scanner, '_protocol_analysis') as mock_protocol:
                mock_protocol.return_value = {
                    'mqtt': {'enabled': True, 'authentication': False},
                    'coap': {'enabled': False},
                    'http': {'enabled': True, 'security': 'weak'}
                }
                
                with patch.object(scanner, '_credential_testing') as mock_creds:
                    mock_creds.return_value = {
                        'default_credentials': [
                            {'username': 'admin', 'password': 'admin', 'access': 'full'}
                        ],
                        'brute_force_results': []
                    }
                    
                    result = await scanner.scan('192.168.1.0/24')
                    
                    assert result['target'] == '192.168.1.0/24'
                    assert 'device_discovery' in result
                    assert 'protocol_analysis' in result
                    assert 'credential_testing' in result
    
    @pytest.mark.asyncio
    async def test_device_discovery(self):
        """Test IoT device discovery"""
        scanner = IoTDeviceScanner()
        
        with patch.object(scanner, '_scan_iot_ports') as mock_ports:
            mock_ports.return_value = {
                '192.168.1.100': {
                    'open_ports': [80, 554, 1883],
                    'services': {
                        80: {'banner': 'Server: lighttpd/1.4.35', 'service': 'HTTP'},
                        554: {'banner': 'RTSP/1.0 200 OK', 'service': 'RTSP'},
                        1883: {'banner': '', 'service': 'MQTT'}
                    }
                }
            }
            
            with patch.object(scanner, '_fingerprint_device') as mock_fingerprint:
                mock_fingerprint.return_value = {
                    'device_type': 'IP Camera',
                    'vendor': 'Hikvision',
                    'model': 'DS-2CD2142FWD-I',
                    'firmware': '5.4.5'
                }
                
                result = await scanner._device_discovery('192.168.1.0/24')
                
                assert 'detected_devices' in result
                assert len(result['detected_devices']) > 0
                assert result['detected_devices'][0]['ip'] == '192.168.1.100'
    
    def test_fingerprint_device(self):
        """Test device fingerprinting"""
        scanner = IoTDeviceScanner()
        
        # Test IP camera fingerprinting
        services = {
            80: {'banner': 'Server: lighttpd/1.4.35', 'service': 'HTTP'},
            554: {'banner': 'RTSP/1.0 200 OK', 'service': 'RTSP'}
        }
        
        result = scanner._fingerprint_device('192.168.1.100', services)
        
        assert 'device_type' in result
        assert 'vendor' in result
        assert result['device_type'] in ['IP Camera', 'Security Camera', 'Unknown']
    
    @pytest.mark.asyncio
    async def test_mqtt_analysis(self):
        """Test MQTT protocol analysis"""
        scanner = IoTDeviceScanner()
        
        with patch('paho.mqtt.client.Client') as mock_client:
            mock_mqtt = MagicMock()
            mock_client.return_value = mock_mqtt
            
            # Mock successful connection without authentication
            mock_mqtt.connect.return_value = 0
            mock_mqtt.is_connected.return_value = True
            
            result = await scanner._mqtt_analysis('192.168.1.100')
            
            assert 'enabled' in result
            assert 'authentication' in result
            assert 'topics' in result
    
    @pytest.mark.asyncio
    async def test_coap_analysis(self):
        """Test CoAP protocol analysis"""
        scanner = IoTDeviceScanner()
        
        with patch('aiocoap.Context') as mock_context:
            mock_ctx = AsyncMock()
            mock_context.create_client_context.return_value = mock_ctx
            
            mock_response = MagicMock()
            mock_response.code = 200
            mock_response.payload = b'CoAP server response'
            mock_ctx.request.return_value = mock_response
            
            result = await scanner._coap_analysis('192.168.1.100')
            
            assert 'enabled' in result
            assert 'resources' in result
    
    def test_analyze_iot_vulnerabilities(self):
        """Test IoT vulnerability analysis"""
        scanner = IoTDeviceScanner()
        
        device_info = {
            'device_type': 'IP Camera',
            'vendor': 'Hikvision',
            'firmware': '5.4.5',
            'services': {
                80: {'service': 'HTTP', 'banner': 'Server: lighttpd/1.4.35'},
                554: {'service': 'RTSP'}
            }
        }
        
        protocols = {
            'mqtt': {'enabled': True, 'authentication': False},
            'http': {'enabled': True, 'security': 'weak'}
        }
        
        credentials = {
            'default_credentials': [
                {'username': 'admin', 'password': 'admin', 'access': 'full'}
            ]
        }
        
        vulnerabilities = scanner._analyze_iot_vulnerabilities(device_info, protocols, credentials)
        
        assert len(vulnerabilities) > 0
        assert any('default credentials' in vuln['description'].lower() for vuln in vulnerabilities)
    
    def test_check_firmware_vulnerabilities(self):
        """Test firmware vulnerability checking"""
        scanner = IoTDeviceScanner()
        
        # Test known vulnerable firmware
        device_info = {
            'vendor': 'Hikvision',
            'model': 'DS-2CD2142FWD-I',
            'firmware': '5.4.5'
        }
        
        vulnerabilities = scanner._check_firmware_vulnerabilities(device_info)
        
        assert isinstance(vulnerabilities, list)
        # Should find vulnerabilities for this older firmware
    
    def test_detect_iot_protocols(self):
        """Test IoT protocol detection"""
        scanner = IoTDeviceScanner()
        
        services = {
            1883: {'service': 'MQTT', 'banner': 'MQTT broker'},
            5683: {'service': 'CoAP', 'banner': 'CoAP server'},
            8080: {'service': 'HTTP', 'banner': 'HTTP server'}
        }
        
        protocols = scanner._detect_iot_protocols(services)
        
        assert 'mqtt' in protocols
        assert 'coap' in protocols
        assert 'http' in protocols
    
    def test_generate_iot_recommendations(self):
        """Test IoT security recommendations"""
        scanner = IoTDeviceScanner()
        
        results = {
            'device_discovery': {
                'detected_devices': [
                    {'device_type': 'IP Camera', 'vendor': 'Hikvision'}
                ]
            },
            'protocol_analysis': {
                'mqtt': {'enabled': True, 'authentication': False}
            },
            'credential_testing': {
                'default_credentials': [
                    {'username': 'admin', 'password': 'admin'}
                ]
            },
            'vulnerability_analysis': {
                'vulnerabilities': [
                    {'type': 'Default Credentials', 'severity': 'High'}
                ]
            }
        }
        
        recommendations = scanner._generate_iot_recommendations(results)
        
        assert len(recommendations) > 0
        assert any('password' in rec.lower() for rec in recommendations)
        assert any('authentication' in rec.lower() for rec in recommendations)
    
    def test_calculate_iot_risk_score(self):
        """Test IoT risk score calculation"""
        scanner = IoTDeviceScanner()
        
        # Test high risk scenario
        high_risk_results = {
            'vulnerability_analysis': {
                'vulnerabilities': [
                    {'severity': 'Critical'},
                    {'severity': 'High'},
                    {'severity': 'Medium'}
                ]
            },
            'credential_testing': {
                'default_credentials': [
                    {'username': 'admin', 'password': 'admin'}
                ]
            },
            'protocol_analysis': {
                'mqtt': {'enabled': True, 'authentication': False}
            }
        }
        
        score = scanner._calculate_iot_risk_score(high_risk_results)
        assert score >= 70  # High risk
        
        # Test low risk scenario
        low_risk_results = {
            'vulnerability_analysis': {
                'vulnerabilities': []
            },
            'credential_testing': {
                'default_credentials': []
            },
            'protocol_analysis': {
                'mqtt': {'enabled': True, 'authentication': True}
            }
        }
        
        score = scanner._calculate_iot_risk_score(low_risk_results)
        assert score <= 30  # Low risk
    
    @pytest.mark.asyncio
    async def test_scan_iot_ports(self):
        """Test IoT port scanning"""
        scanner = IoTDeviceScanner()
        
        with patch('asyncio.open_connection') as mock_connect:
            mock_reader = AsyncMock()
            mock_writer = AsyncMock()
            mock_reader.read.return_value = b'HTTP/1.1 200 OK\r\nServer: lighttpd/1.4.35\r\n\r\n'
            mock_connect.return_value = (mock_reader, mock_writer)
            
            result = await scanner._scan_iot_ports(['192.168.1.100'])
            
            assert '192.168.1.100' in result
            assert 'open_ports' in result['192.168.1.100']
            assert 'services' in result['192.168.1.100']
    
    def test_extract_device_info(self):
        """Test device information extraction"""
        scanner = IoTDeviceScanner()
        
        # Test HTTP banner extraction
        http_banner = 'HTTP/1.1 200 OK\r\nServer: lighttpd/1.4.35\r\nContent-Type: text/html\r\n\r\n<html><title>IP Camera</title></html>'
        
        info = scanner._extract_device_info(http_banner, 80)
        
        assert 'server' in info
        assert 'lighttpd' in info['server']
        
        # Test RTSP banner extraction
        rtsp_banner = 'RTSP/1.0 200 OK\r\nServer: Hikvision/5.4.5\r\n\r\n'
        
        info = scanner._extract_device_info(rtsp_banner, 554)
        
        assert 'server' in info
        assert 'Hikvision' in info['server']


if __name__ == "__main__":
    pytest.main([__file__, "-v"])