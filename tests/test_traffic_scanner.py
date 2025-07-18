"""
Tests for Traffic Scanner module
"""

import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime

from linuxscan.modules.traffic_scanner import TrafficAnalysisScanner


class TestTrafficAnalysisScanner:
    """Test TrafficAnalysisScanner module"""
    
    def test_init(self):
        """Test TrafficAnalysisScanner initialization"""
        scanner = TrafficAnalysisScanner()
        assert scanner.name == "traffic_scanner"
        assert scanner.timeout == 300
        assert scanner.capture_duration == 60
        assert len(scanner.suspicious_patterns) > 0
        assert len(scanner.protocol_analyzers) > 0
        
        # Check specific protocol analyzers
        assert 'http' in scanner.protocol_analyzers
        assert 'dns' in scanner.protocol_analyzers
        assert 'tcp' in scanner.protocol_analyzers
    
    @pytest.mark.asyncio
    async def test_scan_basic(self):
        """Test basic traffic scanning"""
        scanner = TrafficAnalysisScanner()
        
        with patch.object(scanner, '_packet_capture') as mock_capture:
            mock_capture.return_value = {
                'total_packets': 1000,
                'capture_duration': 60,
                'packets_per_second': 16.67,
                'raw_packets': []
            }
            
            with patch.object(scanner, '_protocol_analysis') as mock_protocol:
                mock_protocol.return_value = {
                    'http': {'requests': 100, 'responses': 95},
                    'dns': {'queries': 50, 'responses': 48},
                    'tcp': {'connections': 25, 'established': 20}
                }
                
                with patch.object(scanner, '_traffic_analysis') as mock_traffic:
                    mock_traffic.return_value = {
                        'bandwidth_usage': 1024000,
                        'top_talkers': [{'ip': '192.168.1.100', 'bytes': 500000}],
                        'suspicious_flows': []
                    }
                    
                    result = await scanner.scan('eth0')
                    
                    assert result['target'] == 'eth0'
                    assert 'packet_capture' in result
                    assert 'protocol_analysis' in result
                    assert 'traffic_analysis' in result
    
    @pytest.mark.asyncio
    async def test_packet_capture(self):
        """Test packet capture functionality"""
        scanner = TrafficAnalysisScanner()
        
        with patch('scapy.all.sniff') as mock_sniff:
            # Mock captured packets
            mock_packets = [
                MagicMock(src='192.168.1.100', dst='192.168.1.1', proto=6, len=64),
                MagicMock(src='192.168.1.1', dst='192.168.1.100', proto=6, len=1500),
                MagicMock(src='192.168.1.100', dst='8.8.8.8', proto=17, len=128)
            ]
            mock_sniff.return_value = mock_packets
            
            result = await scanner._packet_capture('eth0', duration=10)
            
            assert result['total_packets'] == 3
            assert result['capture_duration'] == 10
            assert 'packets_per_second' in result
            assert 'raw_packets' in result
    
    def test_analyze_http_traffic(self):
        """Test HTTP traffic analysis"""
        scanner = TrafficAnalysisScanner()
        
        # Mock HTTP packets
        http_packets = [
            MagicMock(
                src='192.168.1.100',
                dst='192.168.1.1',
                dport=80,
                payload='GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n'
            ),
            MagicMock(
                src='192.168.1.1',
                dst='192.168.1.100',
                sport=80,
                payload='HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html></html>'
            )
        ]
        
        result = scanner._analyze_http_traffic(http_packets)
        
        assert 'total_requests' in result
        assert 'total_responses' in result
        assert 'methods' in result
        assert 'status_codes' in result
        assert 'user_agents' in result
    
    def test_analyze_dns_traffic(self):
        """Test DNS traffic analysis"""
        scanner = TrafficAnalysisScanner()
        
        # Mock DNS packets
        dns_packets = [
            MagicMock(
                src='192.168.1.100',
                dst='8.8.8.8',
                dport=53,
                qd=MagicMock(qname='example.com', qtype=1)
            ),
            MagicMock(
                src='8.8.8.8',
                dst='192.168.1.100',
                sport=53,
                an=MagicMock(rdata='192.168.1.50')
            )
        ]
        
        result = scanner._analyze_dns_traffic(dns_packets)
        
        assert 'total_queries' in result
        assert 'total_responses' in result
        assert 'query_types' in result
        assert 'top_domains' in result
        assert 'suspicious_domains' in result
    
    def test_detect_suspicious_patterns(self):
        """Test suspicious pattern detection"""
        scanner = TrafficAnalysisScanner()
        
        # Mock packets with suspicious patterns
        suspicious_packets = [
            MagicMock(
                src='192.168.1.100',
                dst='10.0.0.1',
                payload='GET /../../etc/passwd HTTP/1.1'
            ),
            MagicMock(
                src='192.168.1.100',
                dst='192.168.1.1',
                payload='<script>alert("XSS")</script>'
            ),
            MagicMock(
                src='192.168.1.100',
                dst='8.8.8.8',
                dport=53,
                qd=MagicMock(qname='malware.com')
            )
        ]
        
        result = scanner._detect_suspicious_patterns(suspicious_packets)
        
        assert 'sql_injection' in result
        assert 'xss_attempts' in result
        assert 'directory_traversal' in result
        assert 'malicious_domains' in result
    
    def test_analyze_bandwidth_usage(self):
        """Test bandwidth usage analysis"""
        scanner = TrafficAnalysisScanner()
        
        # Mock packets with size information
        packets = [
            MagicMock(src='192.168.1.100', dst='192.168.1.1', len=1500),
            MagicMock(src='192.168.1.1', dst='192.168.1.100', len=64),
            MagicMock(src='192.168.1.100', dst='8.8.8.8', len=128),
            MagicMock(src='8.8.8.8', dst='192.168.1.100', len=512)
        ]
        
        result = scanner._analyze_bandwidth_usage(packets, duration=60)
        
        assert 'total_bytes' in result
        assert 'bytes_per_second' in result
        assert 'top_talkers' in result
        assert 'traffic_distribution' in result
    
    def test_detect_port_scans(self):
        """Test port scan detection"""
        scanner = TrafficAnalysisScanner()
        
        # Mock packets indicating port scan
        scan_packets = []
        for port in range(1, 1000, 10):  # Simulate scanning every 10th port
            scan_packets.append(MagicMock(
                src='192.168.1.200',
                dst='192.168.1.100',
                dport=port,
                flags=2  # SYN flag
            ))
        
        result = scanner._detect_port_scans(scan_packets)
        
        assert 'port_scans' in result
        assert len(result['port_scans']) > 0
        assert '192.168.1.200' in [scan['source'] for scan in result['port_scans']]
    
    def test_analyze_connection_patterns(self):
        """Test connection pattern analysis"""
        scanner = TrafficAnalysisScanner()
        
        # Mock connection packets
        connection_packets = [
            MagicMock(src='192.168.1.100', dst='192.168.1.1', sport=12345, dport=80, flags=2),  # SYN
            MagicMock(src='192.168.1.1', dst='192.168.1.100', sport=80, dport=12345, flags=18),  # SYN-ACK
            MagicMock(src='192.168.1.100', dst='192.168.1.1', sport=12345, dport=80, flags=16),  # ACK
            MagicMock(src='192.168.1.100', dst='192.168.1.1', sport=12345, dport=80, flags=1),   # FIN
        ]
        
        result = scanner._analyze_connection_patterns(connection_packets)
        
        assert 'total_connections' in result
        assert 'connection_states' in result
        assert 'average_duration' in result
        assert 'top_connections' in result
    
    def test_detect_ddos_patterns(self):
        """Test DDoS pattern detection"""
        scanner = TrafficAnalysisScanner()
        
        # Mock DDoS-like traffic
        ddos_packets = []
        for i in range(1000):
            ddos_packets.append(MagicMock(
                src=f'192.168.1.{i % 254 + 1}',
                dst='192.168.1.100',
                dport=80,
                flags=2
            ))
        
        result = scanner._detect_ddos_patterns(ddos_packets)
        
        assert 'ddos_detected' in result
        assert 'attack_type' in result
        assert 'source_ips' in result
        assert 'packets_per_second' in result
    
    def test_analyze_protocol_distribution(self):
        """Test protocol distribution analysis"""
        scanner = TrafficAnalysisScanner()
        
        # Mock packets with different protocols
        protocol_packets = [
            MagicMock(proto=6, len=1500),  # TCP
            MagicMock(proto=6, len=64),    # TCP
            MagicMock(proto=17, len=128),  # UDP
            MagicMock(proto=1, len=56),    # ICMP
        ]
        
        result = scanner._analyze_protocol_distribution(protocol_packets)
        
        assert 'protocol_counts' in result
        assert 'protocol_bytes' in result
        assert 'protocol_percentages' in result
        assert result['protocol_counts'][6] == 2  # TCP count
        assert result['protocol_counts'][17] == 1  # UDP count
    
    def test_extract_file_transfers(self):
        """Test file transfer extraction"""
        scanner = TrafficAnalysisScanner()
        
        # Mock HTTP file transfer packets
        file_packets = [
            MagicMock(
                src='192.168.1.100',
                dst='192.168.1.1',
                payload='GET /download/file.exe HTTP/1.1\r\nHost: example.com\r\n\r\n'
            ),
            MagicMock(
                src='192.168.1.1',
                dst='192.168.1.100',
                payload='HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: 1024000\r\n\r\nMZ...'
            )
        ]
        
        result = scanner._extract_file_transfers(file_packets)
        
        assert 'file_transfers' in result
        assert 'total_files' in result
        assert 'file_types' in result
        assert 'suspicious_files' in result
    
    def test_generate_traffic_report(self):
        """Test traffic analysis report generation"""
        scanner = TrafficAnalysisScanner()
        
        results = {
            'packet_capture': {
                'total_packets': 1000,
                'capture_duration': 60,
                'packets_per_second': 16.67
            },
            'protocol_analysis': {
                'http': {'requests': 100, 'responses': 95},
                'dns': {'queries': 50, 'responses': 48},
                'tcp': {'connections': 25, 'established': 20}
            },
            'traffic_analysis': {
                'bandwidth_usage': 1024000,
                'top_talkers': [{'ip': '192.168.1.100', 'bytes': 500000}],
                'suspicious_flows': []
            },
            'security_analysis': {
                'suspicious_patterns': {
                    'sql_injection': 2,
                    'xss_attempts': 1,
                    'port_scans': 3
                }
            }
        }
        
        report = scanner._generate_traffic_report(results)
        
        assert 'summary' in report
        assert 'security_findings' in report
        assert 'recommendations' in report
        assert 'traffic_statistics' in report
    
    def test_calculate_threat_score(self):
        """Test threat score calculation"""
        scanner = TrafficAnalysisScanner()
        
        # Test high threat scenario
        high_threat_analysis = {
            'suspicious_patterns': {
                'sql_injection': 10,
                'xss_attempts': 5,
                'directory_traversal': 8
            },
            'ddos_patterns': {
                'ddos_detected': True,
                'attack_type': 'SYN flood'
            },
            'port_scans': {
                'port_scans': [
                    {'source': '192.168.1.200', 'ports_scanned': 1000}
                ]
            }
        }
        
        score = scanner._calculate_threat_score(high_threat_analysis)
        assert score >= 70  # High threat
        
        # Test low threat scenario
        low_threat_analysis = {
            'suspicious_patterns': {
                'sql_injection': 0,
                'xss_attempts': 0,
                'directory_traversal': 0
            },
            'ddos_patterns': {
                'ddos_detected': False
            },
            'port_scans': {
                'port_scans': []
            }
        }
        
        score = scanner._calculate_threat_score(low_threat_analysis)
        assert score <= 30  # Low threat
    
    def test_analyze_encrypted_traffic(self):
        """Test encrypted traffic analysis"""
        scanner = TrafficAnalysisScanner()
        
        # Mock encrypted traffic packets
        encrypted_packets = [
            MagicMock(
                src='192.168.1.100',
                dst='192.168.1.1',
                dport=443,
                payload=b'\x16\x03\x01\x00\x1a...'  # TLS handshake
            ),
            MagicMock(
                src='192.168.1.100',
                dst='192.168.1.1',
                dport=22,
                payload=b'SSH-2.0-OpenSSH_7.4'
            )
        ]
        
        result = scanner._analyze_encrypted_traffic(encrypted_packets)
        
        assert 'tls_connections' in result
        assert 'ssh_connections' in result
        assert 'encryption_ratios' in result
        assert 'cipher_suites' in result


if __name__ == "__main__":
    pytest.main([__file__, "-v"])