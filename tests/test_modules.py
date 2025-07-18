"""
Comprehensive tests for LinuxScan security modules
"""

import pytest
import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime

from linuxscan.modules.port_scanner import PortScanner
from linuxscan.modules.vulnerability_scanner import VulnerabilityScanner
from linuxscan.modules.network_scanner import NetworkScanner
from linuxscan.modules.web_scanner import WebScanner
from linuxscan.modules.forensics_scanner import ForensicsScanner
from linuxscan.modules.config_scanner import ConfigScanner
from linuxscan.modules.malware_scanner import MalwareScanner
from linuxscan.modules.database_scanner import DatabaseScanner
from linuxscan.modules.ssh_scanner import SSHScanner
from linuxscan.modules.base_scanner import BaseScannerModule, scanner_registry


class TestPortScanner:
    """Test PortScanner module"""
    
    def test_init(self):
        """Test PortScanner initialization"""
        scanner = PortScanner()
        assert scanner.name == "port_scanner"
        assert scanner.timeout == 5
        assert scanner.max_concurrent == 100
    
    @pytest.mark.asyncio
    async def test_scan_basic(self):
        """Test basic port scanning"""
        scanner = PortScanner()
        
        with patch.object(scanner, '_tcp_scan') as mock_tcp:
            mock_tcp.return_value = {
                'open_ports': {80: {'protocol': 'tcp', 'service': 'HTTP', 'state': 'open'}},
                'closed_ports': [443],
                'filtered_ports': []
            }
            
            with patch.object(scanner, '_detect_service') as mock_service:
                mock_service.return_value = {'name': 'HTTP', 'version': '1.1'}
                
                with patch.object(scanner, '_grab_banner') as mock_banner:
                    mock_banner.return_value = "HTTP/1.1 200 OK"
                    
                    with patch.object(scanner, '_detect_os') as mock_os:
                        mock_os.return_value = {'os_match': 'Linux'}
                        
                        with patch.object(scanner, '_check_vulnerabilities') as mock_vulns:
                            mock_vulns.return_value = []
                            
                            result = await scanner.scan('127.0.0.1')
                            
                            assert result['target'] == '127.0.0.1'
                            assert 'open_ports' in result
                            assert 80 in result['open_ports']
    
    @pytest.mark.asyncio
    async def test_scan_tcp_port(self):
        """Test TCP port scanning"""
        scanner = PortScanner()
        
        with patch('asyncio.open_connection') as mock_connect:
            mock_reader = AsyncMock()
            mock_writer = AsyncMock()
            mock_connect.return_value = (mock_reader, mock_writer)
            
            result = await scanner._scan_tcp_port('127.0.0.1', 80, asyncio.Semaphore(10))
            
            assert result == (80, 'open', 'HTTP')
            mock_connect.assert_called_once()
    
    def test_parse_service_version(self):
        """Test service version parsing"""
        scanner = PortScanner()
        
        # Test SSH banner
        banner = "SSH-2.0-OpenSSH_8.0"
        result = scanner._parse_service_version(banner, 22)
        assert "SSH" in result
        assert "2.0" in result
        
        # Test HTTP banner
        banner = "HTTP/1.1 200 OK"
        result = scanner._parse_service_version(banner, 80)
        assert "HTTP" in result or banner.split('\n')[0][:100] in result


class TestVulnerabilityScanner:
    """Test VulnerabilityScanner module"""
    
    def test_init(self):
        """Test VulnerabilityScanner initialization"""
        scanner = VulnerabilityScanner()
        assert scanner.name == "vulnerability_scanner"
        assert scanner.timeout == 30
        assert len(scanner.vuln_patterns) > 0
    
    @pytest.mark.asyncio
    async def test_scan_basic(self):
        """Test basic vulnerability scanning"""
        scanner = VulnerabilityScanner()
        
        services = {
            22: {'name': 'ssh', 'version': 'OpenSSH_7.4', 'banner': 'SSH-2.0-OpenSSH_7.4'}
        }
        
        result = await scanner.scan('127.0.0.1', services=services)
        
        assert result['target'] == '127.0.0.1'
        assert 'vulnerabilities' in result
        assert 'security_score' in result
        assert 'recommendations' in result
    
    @pytest.mark.asyncio
    async def test_check_service_vulnerabilities(self):
        """Test service vulnerability checking"""
        scanner = VulnerabilityScanner()
        
        service_info = {
            'name': 'ssh',
            'version': 'OpenSSH_7.4',
            'banner': 'SSH-2.0-OpenSSH_7.4'
        }
        
        vulns = await scanner._check_service_vulnerabilities('127.0.0.1', 22, service_info)
        
        assert isinstance(vulns, list)
        # Should find vulnerabilities for OpenSSH 7.4
        assert len(vulns) > 0
    
    def test_version_matches(self):
        """Test version matching"""
        scanner = VulnerabilityScanner()
        
        assert scanner._version_matches('OpenSSH_7.4', 'OpenSSH_7.4')
        assert scanner._version_matches('Apache/2.4.29', 'Apache/2.4.29')
        assert not scanner._version_matches('OpenSSH_8.0', 'OpenSSH_7.4')
    
    def test_get_cvss_score(self):
        """Test CVSS score calculation"""
        scanner = VulnerabilityScanner()
        
        assert scanner._get_cvss_score('Critical') == 9.0
        assert scanner._get_cvss_score('High') == 7.0
        assert scanner._get_cvss_score('Medium') == 5.0
        assert scanner._get_cvss_score('Low') == 3.0
        assert scanner._get_cvss_score('Info') == 1.0
    
    def test_calculate_security_score(self):
        """Test security score calculation"""
        scanner = VulnerabilityScanner()
        
        results = {
            'critical_vulns': [{'severity': 'Critical'}],
            'high_vulns': [{'severity': 'High'}],
            'medium_vulns': [],
            'low_vulns': [],
            'info_vulns': []
        }
        
        score = scanner._calculate_security_score(results)
        assert score == 70  # 100 - 20 (critical) - 10 (high)


class TestNetworkScanner:
    """Test NetworkScanner module"""
    
    def test_init(self):
        """Test NetworkScanner initialization"""
        scanner = NetworkScanner()
        assert scanner.name == "network_scanner"
        assert scanner.timeout == 30
        assert scanner.capture_duration == 60
    
    @pytest.mark.asyncio
    async def test_scan_discovery(self):
        """Test network discovery scanning"""
        scanner = NetworkScanner()
        
        with patch.object(scanner, '_network_discovery') as mock_discovery:
            mock_discovery.return_value = {
                'live_hosts': ['127.0.0.1'],
                'host_details': {},
                'network_topology': {}
            }
            
            result = await scanner.scan('127.0.0.1', scan_type='discovery')
            
            assert result['target'] == '127.0.0.1'
            assert result['scan_type'] == 'discovery'
            assert 'network_discovery' in result
    
    @pytest.mark.asyncio
    async def test_ping_sweep(self):
        """Test ping sweep functionality"""
        scanner = NetworkScanner()
        
        import ipaddress
        hosts = [ipaddress.IPv4Address('127.0.0.1')]
        
        with patch('asyncio.create_subprocess_exec') as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate.return_value = (b'', b'')
            mock_subprocess.return_value = mock_process
            
            result = await scanner._ping_sweep(hosts)
            
            assert len(result) == 1
            assert result[0] == ipaddress.IPv4Address('127.0.0.1')
    
    def test_analyze_protocols(self):
        """Test protocol analysis"""
        scanner = NetworkScanner()
        
        # Mock packets
        packets = []
        for i in range(10):
            packet = MagicMock()
            packet.proto = 6 if i % 2 == 0 else 17  # TCP or UDP
            packets.append(packet)
        
        protocols = scanner._analyze_protocols(packets)
        
        assert 'TCP' in protocols
        assert 'UDP' in protocols
        assert protocols['TCP'] == 5
        assert protocols['UDP'] == 5


class TestWebScanner:
    """Test WebScanner module"""
    
    def test_init(self):
        """Test WebScanner initialization"""
        scanner = WebScanner()
        assert scanner.name == "web_scanner"
        assert scanner.timeout == 30
        assert scanner.max_concurrent == 10
        assert len(scanner.sql_payloads) > 0
        assert len(scanner.xss_payloads) > 0
    
    @pytest.mark.asyncio
    async def test_scan_basic(self):
        """Test basic web scanning"""
        scanner = WebScanner()
        
        with patch('aiohttp.ClientSession') as mock_session:
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.headers = {'Server': 'Apache/2.4.41'}
            mock_response.text.return_value = "<html><body>Test</body></html>"
            mock_response.url.scheme = 'http'
            
            mock_session_instance = AsyncMock()
            mock_session_instance.get.return_value.__aenter__.return_value = mock_response
            mock_session.return_value = mock_session_instance
            
            result = await scanner.scan('http://example.com')
            
            assert result['target'] == 'http://example.com'
            assert 'information_gathering' in result
            assert 'security_headers' in result
    
    def test_detect_sql_error(self):
        """Test SQL error detection"""
        scanner = WebScanner()
        
        # Test positive cases
        assert scanner._detect_sql_error("mysql_fetch_array() error")
        assert scanner._detect_sql_error("ORA-00942: table or view does not exist")
        assert scanner._detect_sql_error("PostgreSQL query failed")
        
        # Test negative case
        assert not scanner._detect_sql_error("Normal response")
    
    def test_detect_technologies(self):
        """Test technology detection"""
        scanner = WebScanner()
        
        content = "<html><head><title>WordPress Site</title></head><body>wp-content</body></html>"
        headers = {'X-Powered-By': 'PHP/7.4.0'}
        
        technologies = scanner._detect_technologies(content, headers)
        
        assert technologies['programming_language'] == 'PHP'
        assert technologies['cms'] == 'WordPress'
    
    def test_detect_version_disclosure(self):
        """Test version disclosure detection"""
        scanner = WebScanner()
        
        content = "Server version: Apache/2.4.41"
        headers = {'Server': 'Apache/2.4.41 (Ubuntu)'}
        
        versions = scanner._detect_version_disclosure(content, headers)
        
        assert len(versions) > 0
        assert any('Apache' in version for version in versions)


class TestForensicsScanner:
    """Test ForensicsScanner module"""
    
    def test_init(self):
        """Test ForensicsScanner initialization"""
        scanner = ForensicsScanner()
        assert scanner.name == "forensics_scanner"
        assert scanner.timeout == 60
        assert scanner.evidence_dir.startswith('/tmp/linuxscan_forensics_')
    
    @pytest.mark.asyncio
    async def test_scan_comprehensive(self):
        """Test comprehensive forensics scanning"""
        scanner = ForensicsScanner()
        
        result = await scanner.scan('127.0.0.1', scan_type='comprehensive')
        
        assert result['target'] == '127.0.0.1'
        assert result['scan_type'] == 'comprehensive'
        assert 'memory_analysis' in result
        assert 'rootkit_detection' in result
        assert 'file_integrity' in result
        assert 'indicators_of_compromise' in result
    
    def test_generate_iocs(self):
        """Test IOC generation"""
        scanner = ForensicsScanner()
        
        results = {
            'rootkit_detection': {
                'suspicious_files': ['/tmp/malware.exe']
            },
            'process_analysis': {
                'suspicious_processes': ['malicious_process']
            }
        }
        
        iocs = scanner._generate_iocs(results)
        
        assert len(iocs) == 2
        assert any(ioc['type'] == 'file' for ioc in iocs)
        assert any(ioc['type'] == 'process' for ioc in iocs)


class TestConfigScanner:
    """Test ConfigScanner module"""
    
    def test_init(self):
        """Test ConfigScanner initialization"""
        scanner = ConfigScanner()
        assert scanner.name == "config_scanner"
        assert scanner.timeout == 30
        assert len(scanner.cis_benchmarks) > 0
        assert len(scanner.stig_checks) > 0
    
    @pytest.mark.asyncio
    async def test_scan_cis(self):
        """Test CIS compliance scanning"""
        scanner = ConfigScanner()
        
        result = await scanner.scan('127.0.0.1', compliance_framework='cis')
        
        assert result['target'] == '127.0.0.1'
        assert result['compliance_framework'] == 'cis'
        assert 'system_hardening' in result
        assert 'compliance_score' in result
    
    @pytest.mark.asyncio
    async def test_run_cis_checks(self):
        """Test CIS benchmark checks"""
        scanner = ConfigScanner()
        
        cis_results = await scanner._run_cis_checks('127.0.0.1')
        
        assert cis_results['framework'] == 'CIS'
        assert cis_results['total_checks'] > 0
        assert 'passed_checks' in cis_results
        assert 'failed_checks' in cis_results
    
    def test_calculate_compliance_score(self):
        """Test compliance score calculation"""
        scanner = ConfigScanner()
        
        results = {
            'passed_checks': [{'id': '1.1.1'}, {'id': '1.1.2'}],
            'failed_checks': [{'id': '1.1.3'}]
        }
        
        score = scanner._calculate_compliance_score(results)
        assert score == 66  # 2 passed out of 3 total = 66%


class TestMalwareScanner:
    """Test MalwareScanner module"""
    
    def test_init(self):
        """Test MalwareScanner initialization"""
        scanner = MalwareScanner()
        assert scanner.name == "malware_scanner"
        assert scanner.timeout == 60
        assert len(scanner.yara_rules) > 0
        assert len(scanner.malware_signatures) > 0
    
    @pytest.mark.asyncio
    async def test_scan_comprehensive(self):
        """Test comprehensive malware scanning"""
        scanner = MalwareScanner()
        
        result = await scanner.scan('127.0.0.1', scan_type='comprehensive')
        
        assert result['target'] == '127.0.0.1'
        assert result['scan_type'] == 'comprehensive'
        assert 'file_scan' in result
        assert 'signature_scan' in result
        assert 'yara_scan' in result
        assert 'suspicious_files' in result
    
    def test_compile_suspicious_files(self):
        """Test suspicious files compilation"""
        scanner = MalwareScanner()
        
        results = {
            'signature_scan': {
                'matches': [{'file_path': '/tmp/malware', 'family': 'Mirai'}]
            },
            'yara_scan': {
                'matches': [{'file': '/tmp/suspicious', 'rule': 'generic_malware'}]
            }
        }
        
        suspicious_files = scanner._compile_suspicious_files(results)
        
        assert len(suspicious_files) == 2
        assert any(file['file'] == '/tmp/malware' for file in suspicious_files)
        assert any(file['file'] == '/tmp/suspicious' for file in suspicious_files)


class TestDatabaseScanner:
    """Test DatabaseScanner module"""
    
    def test_init(self):
        """Test DatabaseScanner initialization"""
        scanner = DatabaseScanner()
        assert scanner.name == "database_scanner"
        assert scanner.timeout == 30
        assert len(scanner.database_ports) > 0
        assert len(scanner.default_credentials) > 0
    
    @pytest.mark.asyncio
    async def test_scan_basic(self):
        """Test basic database scanning"""
        scanner = DatabaseScanner()
        
        with patch.object(scanner, '_database_discovery') as mock_discovery:
            mock_discovery.return_value = {
                'detected_databases': [{'port': 3306, 'type': 'MySQL'}],
                'open_ports': [3306]
            }
            
            result = await scanner.scan('127.0.0.1', database_type='mysql')
            
            assert result['target'] == '127.0.0.1'
            assert result['database_type'] == 'mysql'
            assert 'database_discovery' in result
            assert 'authentication_test' in result
    
    def test_determine_database_type(self):
        """Test database type determination"""
        scanner = DatabaseScanner()
        
        discovery_results = {
            'detected_databases': [{'port': 3306, 'type': 'MySQL'}]
        }
        
        db_type = scanner._determine_database_type(discovery_results)
        assert db_type == 'mysql'
    
    def test_compile_vulnerabilities(self):
        """Test vulnerability compilation"""
        scanner = DatabaseScanner()
        
        results = {
            'authentication_test': {
                'default_credentials': [{'username': 'root', 'password': ''}],
                'anonymous_access': True
            },
            'encryption_analysis': {
                'ssl_test': {'ssl_enabled': False}
            }
        }
        
        vulnerabilities = scanner._compile_vulnerabilities(results)
        
        assert len(vulnerabilities) >= 2
        assert any(vuln['type'] == 'Weak Authentication' for vuln in vulnerabilities)
        assert any(vuln['type'] == 'Anonymous Access' for vuln in vulnerabilities)


class TestBaseScannerModule:
    """Test BaseScannerModule class"""
    
    def test_init(self):
        """Test BaseScannerModule initialization"""
        
        class TestScanner(BaseScannerModule):
            async def scan(self, target: str, **kwargs):
                return {'target': target}
        
        scanner = TestScanner("test_scanner")
        assert scanner.name == "test_scanner"
        assert scanner.timeout == 30
        assert scanner.results == {}
    
    def test_validate_target(self):
        """Test target validation"""
        
        class TestScanner(BaseScannerModule):
            async def scan(self, target: str, **kwargs):
                return {'target': target}
        
        scanner = TestScanner("test_scanner")
        
        # Test valid IP
        assert scanner.validate_target('127.0.0.1') is True
        
        # Test invalid IP
        assert scanner.validate_target('999.999.999.999') is False
    
    def test_get_severity_score(self):
        """Test severity score calculation"""
        
        class TestScanner(BaseScannerModule):
            async def scan(self, target: str, **kwargs):
                return {'target': target}
        
        scanner = TestScanner("test_scanner")
        
        findings = ['Critical vulnerability found', 'High severity issue']
        score = scanner.get_severity_score(findings)
        
        assert score == 18  # 10 (critical) + 8 (high)
    
    def test_get_scan_duration(self):
        """Test scan duration calculation"""
        
        class TestScanner(BaseScannerModule):
            async def scan(self, target: str, **kwargs):
                return {'target': target}
        
        scanner = TestScanner("test_scanner")
        
        scanner.scan_start_time = datetime.now()
        scanner.scan_end_time = scanner.scan_start_time
        
        duration = scanner.get_scan_duration()
        assert duration >= 0


class TestScannerRegistry:
    """Test ScannerRegistry class"""
    
    def test_register_scanner(self):
        """Test scanner registration"""
        registry = scanner_registry
        
        # Test if default scanners are registered
        assert 'port_scanner' in registry.list_scanners()
        assert 'ssh_scanner' in registry.list_scanners()
        assert registry.get_scanner('port_scanner') is not None
        assert registry.get_scanner('ssh_scanner') is not None
    
    def test_create_scanner(self):
        """Test scanner creation"""
        registry = scanner_registry
        
        scanner = registry.create_scanner('port_scanner')
        assert scanner is not None
        assert isinstance(scanner, PortScanner)
        
        ssh_scanner = registry.create_scanner('ssh_scanner')
        assert ssh_scanner is not None
        assert isinstance(ssh_scanner, SSHScanner)
    
    def test_list_scanners(self):
        """Test scanner listing"""
        registry = scanner_registry
        
        scanners = registry.list_scanners()
        assert len(scanners) > 0
        assert 'port_scanner' in scanners


# Integration tests
class TestIntegration:
    """Integration tests for scanner modules"""
    
    @pytest.mark.asyncio
    async def test_scanner_chain(self):
        """Test chaining multiple scanners"""
        port_scanner = PortScanner()
        vuln_scanner = VulnerabilityScanner()
        
        # Mock port scan results
        with patch.object(port_scanner, '_tcp_scan') as mock_tcp:
            mock_tcp.return_value = {
                'open_ports': {22: {'protocol': 'tcp', 'service': 'SSH', 'state': 'open'}},
                'closed_ports': [],
                'filtered_ports': []
            }
            
            with patch.object(port_scanner, '_detect_service') as mock_service:
                mock_service.return_value = {'name': 'SSH', 'version': 'OpenSSH_7.4'}
                
                with patch.object(port_scanner, '_grab_banner') as mock_banner:
                    mock_banner.return_value = "SSH-2.0-OpenSSH_7.4"
                    
                    with patch.object(port_scanner, '_detect_os') as mock_os:
                        mock_os.return_value = {'os_match': 'Linux'}
                        
                        with patch.object(port_scanner, '_check_vulnerabilities') as mock_vulns:
                            mock_vulns.return_value = []
                            
                            # Run port scan
                            port_results = await port_scanner.scan('127.0.0.1')
                            
                            # Use port scan results for vulnerability scan
                            services = port_results.get('service_detection', {})
                            vuln_results = await vuln_scanner.scan('127.0.0.1', services=services)
                            
                            assert port_results['target'] == '127.0.0.1'
                            assert vuln_results['target'] == '127.0.0.1'
                            assert 'vulnerabilities' in vuln_results
    
    @pytest.mark.asyncio
    async def test_error_handling(self):
        """Test error handling in scanners"""
        scanner = PortScanner()
        
        # Test with invalid target
        result = await scanner.scan('999.999.999.999')
        
        # Should handle gracefully
        assert 'error' in result or result['target'] == '999.999.999.999'
    
    def test_performance_tracking(self):
        """Test performance tracking"""
        scanner = PortScanner()
        
        scanner.log_scan_start('127.0.0.1')
        scanner.log_scan_end('127.0.0.1')
        
        duration = scanner.get_scan_duration()
        assert duration >= 0


# Fixtures
@pytest.fixture
def mock_network_response():
    """Mock network response"""
    response = MagicMock()
    response.status_code = 200
    response.text = "<html><body>Test</body></html>"
    response.headers = {'Server': 'Apache/2.4.41'}
    return response


@pytest.fixture
def sample_scan_results():
    """Sample scan results for testing"""
    return {
        'target': '127.0.0.1',
        'timestamp': datetime.now().isoformat(),
        'open_ports': {80: {'service': 'HTTP', 'state': 'open'}},
        'vulnerabilities': [
            {'type': 'Weak Authentication', 'severity': 'High'},
            {'type': 'Missing Security Headers', 'severity': 'Medium'}
        ],
        'recommendations': [
            'Enable HTTPS',
            'Implement proper authentication'
        ]
    }


if __name__ == "__main__":
    pytest.main([__file__, "-v"])