"""
Test scanner functionality
"""

import pytest
import asyncio
import socket
import json
from unittest.mock import patch, AsyncMock, MagicMock, mock_open
from datetime import datetime

from linuxscan.scanner import SecurityScanner


class TestSecurityScanner:
    """Test SecurityScanner class"""
    
    def test_init(self):
        """Test scanner initialization"""
        scanner = SecurityScanner()
        assert scanner.timeout == 5
        assert scanner.max_workers == 50
        assert scanner.results == {}
        assert scanner.scan_start_time is None
        assert scanner.scan_end_time is None
    
    def test_parse_targets_single_ip(self):
        """Test parsing single IP target"""
        scanner = SecurityScanner()
        targets = scanner.parse_targets(['192.168.1.1'])
        assert targets == ['192.168.1.1']
    
    def test_parse_targets_cidr(self):
        """Test parsing CIDR target"""
        scanner = SecurityScanner()
        targets = scanner.parse_targets(['192.168.1.0/30'])
        # Should expand to 4 IPs (network includes network and broadcast)
        assert len(targets) >= 2  # At least 2 usable IPs
        assert '192.168.1.1' in targets
        assert '192.168.1.2' in targets
    
    def test_parse_targets_mixed(self):
        """Test parsing mixed targets"""
        scanner = SecurityScanner()
        targets = scanner.parse_targets(['192.168.1.1', '10.0.0.0/30'])
        assert '192.168.1.1' in targets
        assert len(targets) > 1  # Should include CIDR expansion
    
    def test_parse_targets_invalid(self):
        """Test parsing invalid targets"""
        scanner = SecurityScanner()
        targets = scanner.parse_targets(['invalid.ip', '999.999.999.999'])
        # Should filter out invalid targets
        assert len(targets) == 0 or 'invalid.ip' not in targets
    
    @pytest.mark.asyncio
    async def test_scan_port_open(self):
        """Test scanning open port"""
        scanner = SecurityScanner()
        
        with patch('asyncio.open_connection') as mock_connect:
            mock_reader = AsyncMock()
            mock_writer = AsyncMock()
            mock_connect.return_value = (mock_reader, mock_writer)
            
            result = await scanner.scan_port('127.0.0.1', 80)
            assert result == (80, True, 'Unknown')
            mock_connect.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_scan_port_closed(self):
        """Test scanning closed port"""
        scanner = SecurityScanner()
        
        with patch('asyncio.open_connection', side_effect=ConnectionRefusedError()):
            result = await scanner.scan_port('127.0.0.1', 80)
            assert result == (80, False, None)
    
    @pytest.mark.asyncio
    async def test_scan_port_timeout(self):
        """Test scanning port with timeout"""
        scanner = SecurityScanner()
        
        with patch('asyncio.open_connection', side_effect=asyncio.TimeoutError()):
            result = await scanner.scan_port('127.0.0.1', 80)
            assert result == (80, False, None)
    
    def test_detect_service_http(self):
        """Test HTTP service detection"""
        scanner = SecurityScanner()
        service = scanner.detect_service(80, b'HTTP/1.1 200 OK')
        assert 'HTTP' in service
    
    def test_detect_service_ssh(self):
        """Test SSH service detection"""
        scanner = SecurityScanner()
        service = scanner.detect_service(22, b'SSH-2.0-OpenSSH_8.0')
        assert 'SSH' in service
    
    def test_detect_service_unknown(self):
        """Test unknown service detection"""
        scanner = SecurityScanner()
        service = scanner.detect_service(9999, b'unknown response')
        assert service == 'Unknown'
    
    @pytest.mark.asyncio
    async def test_check_ssl_certificate_valid(self):
        """Test SSL certificate check for valid cert"""
        scanner = SecurityScanner()
        
        # Mock SSL context and connection
        with patch('ssl.create_default_context') as mock_context:
            with patch('asyncio.open_connection') as mock_connect:
                mock_reader = AsyncMock()
                mock_writer = AsyncMock()
                mock_writer.get_extra_info.return_value = MagicMock()
                mock_connect.return_value = (mock_reader, mock_writer)
                
                # Mock certificate data
                mock_cert = {
                    'subject': ((('commonName', 'example.com'),),),
                    'issuer': ((('organizationName', 'Test CA'),),),
                    'notAfter': 'Dec 31 23:59:59 2025 GMT',
                    'notBefore': 'Jan  1 00:00:00 2024 GMT'
                }
                mock_writer.get_extra_info.return_value.getpeercert.return_value = mock_cert
                
                result = await scanner.check_ssl_certificate('example.com', 443)
                assert result is not None
                assert 'subject' in result
    
    @pytest.mark.asyncio
    async def test_check_ssl_certificate_connection_error(self):
        """Test SSL certificate check with connection error"""
        scanner = SecurityScanner()
        
        with patch('asyncio.open_connection', side_effect=ConnectionRefusedError()):
            result = await scanner.check_ssl_certificate('example.com', 443)
            assert result is None
    
    @pytest.mark.asyncio
    async def test_check_ssh_security(self):
        """Test SSH security check"""
        scanner = SecurityScanner()
        
        with patch('paramiko.SSHClient') as mock_ssh_class:
            mock_ssh = MagicMock()
            mock_ssh_class.return_value = mock_ssh
            mock_ssh.connect.return_value = None
            mock_ssh.get_transport.return_value.get_security_options.return_value = MagicMock()
            
            result = await scanner.check_ssh_security('127.0.0.1', 22)
            assert result is not None
    
    @pytest.mark.asyncio
    async def test_check_ssh_security_connection_error(self):
        """Test SSH security check with connection error"""
        scanner = SecurityScanner()
        
        with patch('paramiko.SSHClient') as mock_ssh_class:
            mock_ssh = MagicMock()
            mock_ssh_class.return_value = mock_ssh
            mock_ssh.connect.side_effect = Exception("Connection failed")
            
            result = await scanner.check_ssh_security('127.0.0.1', 22)
            assert result is None
    
    def test_analyze_vulnerabilities_ssh(self):
        """Test vulnerability analysis for SSH"""
        scanner = SecurityScanner()
        
        scan_data = {
            'open_ports': {22: {'service': 'SSH-2.0-OpenSSH_7.4'}},
            'ssh_security': {
                'protocol_version': 'SSH-2.0',
                'weak_algorithms': ['aes128-cbc']
            }
        }
        
        vulnerabilities = scanner.analyze_vulnerabilities(scan_data)
        assert len(vulnerabilities) > 0
        assert any('SSH' in vuln for vuln in vulnerabilities)
    
    def test_analyze_vulnerabilities_ssl(self):
        """Test vulnerability analysis for SSL"""
        scanner = SecurityScanner()
        
        scan_data = {
            'open_ports': {443: {'service': 'HTTPS'}},
            'ssl_certificates': {
                443: {
                    'expired': True,
                    'subject': 'example.com'
                }
            }
        }
        
        vulnerabilities = scanner.analyze_vulnerabilities(scan_data)
        assert len(vulnerabilities) > 0
        assert any('certificate' in vuln.lower() for vuln in vulnerabilities)
    
    def test_calculate_security_score_high(self):
        """Test security score calculation for secure system"""
        scanner = SecurityScanner()
        
        scan_data = {
            'open_ports': {22: {'service': 'SSH-2.0-OpenSSH_8.0'}},
            'vulnerabilities': [],
            'ssl_certificates': {},
            'ssh_security': {'protocol_version': 'SSH-2.0'}
        }
        
        score, rating = scanner.calculate_security_score(scan_data)
        assert score >= 70
        assert rating in ['Good', 'Excellent']
    
    def test_calculate_security_score_low(self):
        """Test security score calculation for insecure system"""
        scanner = SecurityScanner()
        
        scan_data = {
            'open_ports': {
                21: {'service': 'FTP'},
                23: {'service': 'Telnet'},
                80: {'service': 'HTTP'}
            },
            'vulnerabilities': [
                'Weak SSH algorithms detected',
                'Expired SSL certificate',
                'Insecure FTP service'
            ],
            'ssl_certificates': {443: {'expired': True}},
            'ssh_security': None
        }
        
        score, rating = scanner.calculate_security_score(scan_data)
        assert score < 50
        assert rating in ['Poor', 'Critical']
    
    def test_export_json(self):
        """Test JSON export functionality"""
        scanner = SecurityScanner()
        scanner.results = {
            '192.168.1.1': {
                'open_ports': {22: {'service': 'SSH'}},
                'vulnerabilities': []
            }
        }
        
        with patch('builtins.open', mock_open()) as mock_file:
            scanner.export_json('test.json')
            mock_file.assert_called_once_with('test.json', 'w')
            # Verify JSON was written
            handle = mock_file()
            written_data = ''.join(call.args[0] for call in handle.write.call_args_list)
            assert 'open_ports' in written_data
    
    def test_export_csv(self):
        """Test CSV export functionality"""
        scanner = SecurityScanner()
        scanner.results = {
            '192.168.1.1': {
                'open_ports': {22: {'service': 'SSH'}},
                'vulnerabilities': [],
                'security_analysis': {'score': 80, 'rating': 'Good'}
            }
        }
        
        with patch('builtins.open', mock_open()) as mock_file:
            scanner.export_csv('test.csv')
            mock_file.assert_called_once_with('test.csv', 'w', newline='')
    
    def test_export_html(self):
        """Test HTML export functionality"""
        scanner = SecurityScanner()
        scanner.results = {
            '192.168.1.1': {
                'open_ports': {22: {'service': 'SSH'}},
                'vulnerabilities': [],
                'security_analysis': {'score': 80, 'rating': 'Good'}
            }
        }
        
        with patch('builtins.open', mock_open()) as mock_file:
            scanner.export_html('test.html')
            mock_file.assert_called_once_with('test.html', 'w')
            # Verify HTML was written
            handle = mock_file()
            written_data = ''.join(call.args[0] for call in handle.write.call_args_list)
            assert '<html>' in written_data
            assert '<table>' in written_data
    
    def test_generate_summary_table(self):
        """Test summary table generation"""
        scanner = SecurityScanner()
        scanner.results = {
            '192.168.1.1': {
                'open_ports': {22: {'service': 'SSH'}},
                'vulnerabilities': [],
                'security_analysis': {'score': 80, 'rating': 'Good'}
            }
        }
        
        table = scanner.generate_summary_table()
        # Should return a Rich table object
        assert hasattr(table, 'add_row')  # Rich table method
    
    @pytest.mark.asyncio
    async def test_scan_network_single_target(self):
        """Test scanning single network target"""
        scanner = SecurityScanner()
        
        # Mock the individual scan methods
        with patch.object(scanner, 'scan_host') as mock_scan_host:
            mock_scan_host.return_value = {
                'open_ports': {22: {'service': 'SSH'}},
                'vulnerabilities': [],
                'security_analysis': {'score': 80, 'rating': 'Good'}
            }
            
            await scanner.scan_network(['127.0.0.1'])
            
            mock_scan_host.assert_called_once_with('127.0.0.1')
            assert '127.0.0.1' in scanner.results
            assert scanner.scan_start_time is not None
            assert scanner.scan_end_time is not None


class TestUtilityFunctions:
    """Test utility functions"""
    
    def test_display_banner(self):
        """Test banner display"""
        from linuxscan.scanner import display_banner
        
        with patch('linuxscan.scanner.console') as mock_console:
            display_banner()
            mock_console.print.assert_called_once()
    
    def test_display_help(self):
        """Test help display"""
        from linuxscan.scanner import display_help
        
        with patch('linuxscan.scanner.console') as mock_console:
            display_help()
            mock_console.print.assert_called_once()


if __name__ == "__main__":
    pytest.main([__file__])