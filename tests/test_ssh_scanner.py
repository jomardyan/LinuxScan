"""
Tests for SSH Scanner module
"""

import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from linuxscan.modules.ssh_scanner import SSHScanner


class TestSSHScanner:
    """Test cases for SSH Scanner"""
    
    def setup_method(self):
        """Setup test environment"""
        self.scanner = SSHScanner(timeout=10)
        
    @pytest.mark.asyncio
    async def test_scanner_initialization(self):
        """Test SSH scanner initialization"""
        assert self.scanner.name == "ssh_scanner"
        assert self.scanner.timeout == 10
        assert len(self.scanner.common_usernames) > 0
        assert len(self.scanner.common_passwords) > 0
        assert 'root' in self.scanner.common_usernames
        assert 'password' in self.scanner.common_passwords
        
    @pytest.mark.asyncio
    async def test_check_ssh_service_not_available(self):
        """Test SSH service check when service not available"""
        with patch('socket.socket') as mock_socket:
            mock_socket.return_value.connect_ex.return_value = 1
            
            result = await self.scanner._check_ssh_service('127.0.0.1')
            
            assert result['available'] == False
            assert 'not open' in result['reason']
            
    @pytest.mark.asyncio
    async def test_check_ssh_service_available(self):
        """Test SSH service check when service is available"""
        with patch('socket.socket') as mock_socket, \
             patch('paramiko.Transport') as mock_transport:
            
            mock_socket.return_value.connect_ex.return_value = 0
            mock_transport_instance = MagicMock()
            mock_transport_instance.remote_version = 'OpenSSH_7.4'
            mock_transport.return_value = mock_transport_instance
            
            result = await self.scanner._check_ssh_service('127.0.0.1')
            
            assert result['available'] == True
            assert result['version'] == 'OpenSSH_7.4'
            
    @pytest.mark.asyncio
    async def test_analyze_ssh_protocol(self):
        """Test SSH protocol analysis"""
        with patch('paramiko.Transport') as mock_transport:
            mock_transport_instance = MagicMock()
            mock_transport_instance.kex_info = {
                'kex_algorithms': ['diffie-hellman-group14-sha256'],
                'server_host_key_algorithms': ['rsa-sha2-512'],
                'encryption_algorithms_client_to_server': ['aes128-ctr'],
                'encryption_algorithms_server_to_client': ['aes128-ctr'],
                'mac_algorithms_client_to_server': ['hmac-sha2-256'],
                'mac_algorithms_server_to_client': ['hmac-sha2-256'],
                'compression_algorithms_client_to_server': ['none'],
                'compression_algorithms_server_to_client': ['none']
            }
            mock_transport.return_value = mock_transport_instance
            
            result = await self.scanner._analyze_ssh_protocol('127.0.0.1')
            
            assert 'kex_algorithms' in result
            assert 'diffie-hellman-group14-sha256' in result['kex_algorithms']
            
    @pytest.mark.asyncio
    async def test_check_ssh_vulnerabilities(self):
        """Test SSH vulnerability checking"""
        ssh_info = {
            'version': 'OpenSSH_6.6',
            'available': True
        }
        
        with patch.object(self.scanner, '_analyze_ssh_protocol') as mock_analyze:
            mock_analyze.return_value = {
                'kex_algorithms': ['diffie-hellman-group1-sha1'],
                'encryption_algorithms_c2s': ['arcfour'],
                'mac_algorithms_c2s': ['hmac-md5']
            }
            
            vulnerabilities = await self.scanner._check_ssh_vulnerabilities('127.0.0.1', ssh_info)
            
            assert len(vulnerabilities) > 0
            # Check for version vulnerability
            version_vulns = [v for v in vulnerabilities if v['type'] == 'version']
            assert len(version_vulns) > 0
            # Check for weak algorithms
            weak_kex = [v for v in vulnerabilities if v['type'] == 'weak_kex']
            assert len(weak_kex) > 0
            
    @pytest.mark.asyncio
    async def test_attempt_ssh_login_success(self):
        """Test successful SSH login attempt"""
        with patch('paramiko.SSHClient') as mock_client:
            mock_client_instance = MagicMock()
            mock_client.return_value = mock_client_instance
            
            result = await self.scanner._attempt_ssh_login('127.0.0.1', 'test', 'password')
            
            assert result['success'] == True
            assert result['error'] is None
            assert result['response_time'] >= 0
            
    @pytest.mark.asyncio
    async def test_attempt_ssh_login_failure(self):
        """Test failed SSH login attempt"""
        with patch('paramiko.SSHClient') as mock_client:
            mock_client_instance = MagicMock()
            mock_client_instance.connect.side_effect = Exception("Authentication failed")
            mock_client.return_value = mock_client_instance
            
            result = await self.scanner._attempt_ssh_login('127.0.0.1', 'test', 'wrong')
            
            assert result['success'] == False
            assert result['error'] is not None
            assert result['response_time'] >= 0
            
    @pytest.mark.asyncio
    async def test_perform_brute_force_test(self):
        """Test SSH brute force testing"""
        kwargs = {
            'max_attempts': 5,
            'usernames': ['test'],
            'passwords': ['password'],
            'delay': 0
        }
        
        with patch.object(self.scanner, '_attempt_ssh_login') as mock_login:
            mock_login.return_value = {
                'success': False,
                'error': 'Authentication failed',
                'response_time': 0.1
            }
            
            result = await self.scanner._perform_brute_force_test('127.0.0.1', kwargs)
            
            assert result['enabled'] == True
            assert result['attempts'] == 1
            assert len(result['failed_logins']) == 1
            assert 'timing_analysis' in result
            
    @pytest.mark.asyncio
    async def test_brute_force_successful_login(self):
        """Test SSH brute force with successful login"""
        kwargs = {
            'max_attempts': 5,
            'usernames': ['admin'],
            'passwords': ['admin'],
            'delay': 0
        }
        
        with patch.object(self.scanner, '_attempt_ssh_login') as mock_login:
            mock_login.return_value = {
                'success': True,
                'error': None,
                'response_time': 0.1
            }
            
            result = await self.scanner._perform_brute_force_test('127.0.0.1', kwargs)
            
            assert result['enabled'] == True
            assert result['attempts'] == 1
            assert len(result['successful_logins']) == 1
            assert result['successful_logins'][0]['username'] == 'admin'
            
    @pytest.mark.asyncio
    async def test_full_ssh_scan(self):
        """Test complete SSH scan"""
        with patch.object(self.scanner, '_check_ssh_service') as mock_check, \
             patch.object(self.scanner, '_analyze_ssh_protocol') as mock_analyze, \
             patch.object(self.scanner, '_check_ssh_vulnerabilities') as mock_vulns:
            
            mock_check.return_value = {'available': True, 'version': 'OpenSSH_7.4'}
            mock_analyze.return_value = {'kex_algorithms': ['diffie-hellman-group14-sha256']}
            mock_vulns.return_value = [{'type': 'test', 'severity': 'low'}]
            
            result = await self.scanner.scan('127.0.0.1')
            
            assert result['target'] == '127.0.0.1'
            assert 'ssh_service' in result
            assert 'protocol_analysis' in result
            assert 'vulnerabilities' in result
            assert 'recommendations' in result
            
    @pytest.mark.asyncio
    async def test_ssh_scan_service_not_available(self):
        """Test SSH scan when service is not available"""
        with patch.object(self.scanner, '_check_ssh_service') as mock_check:
            mock_check.return_value = {'available': False, 'reason': 'Port 22 not open'}
            
            result = await self.scanner.scan('127.0.0.1')
            
            assert result['target'] == '127.0.0.1'
            assert result['status'] == 'SSH service not available'
            
    @pytest.mark.asyncio
    async def test_ssh_scan_with_brute_force(self):
        """Test SSH scan with brute force enabled"""
        with patch.object(self.scanner, '_check_ssh_service') as mock_check, \
             patch.object(self.scanner, '_perform_brute_force_test') as mock_brute:
            
            mock_check.return_value = {'available': True, 'version': 'OpenSSH_7.4'}
            mock_brute.return_value = {'enabled': True, 'attempts': 10}
            
            result = await self.scanner.scan('127.0.0.1', brute_force=True)
            
            assert result['target'] == '127.0.0.1'
            assert 'brute_force' in result
            assert result['brute_force']['enabled'] == True
            
    @pytest.mark.asyncio
    async def test_generate_recommendations(self):
        """Test recommendation generation"""
        results = {
            'ssh_service': {'available': True},
            'vulnerabilities': [
                {'severity': 'high', 'type': 'version'},
                {'severity': 'medium', 'type': 'weak_encryption'}
            ],
            'brute_force': {
                'successful_logins': [{'username': 'admin', 'password': 'admin'}],
                'failed_logins': []
            }
        }
        
        recommendations = self.scanner._generate_recommendations(results)
        
        assert len(recommendations) > 0
        assert any('high-severity' in rec for rec in recommendations)
        assert any('CRITICAL' in rec for rec in recommendations)
        assert any('SSH key-based authentication' in rec for rec in recommendations)
        
    @pytest.mark.asyncio
    async def test_scan_ssh_keys(self):
        """Test SSH key scanning"""
        result = await self.scanner.scan_ssh_keys('127.0.0.1')
        
        assert result['target'] == '127.0.0.1'
        assert 'key_enumeration' in result
        assert result['key_enumeration']['accessible'] == False
        
    def test_vulnerability_patterns(self):
        """Test vulnerability pattern definitions"""
        assert 'weak_encryption' in self.scanner.vulnerability_patterns
        assert 'weak_mac' in self.scanner.vulnerability_patterns
        assert 'weak_kex' in self.scanner.vulnerability_patterns
        
        # Check specific weak algorithms
        assert 'arcfour' in self.scanner.vulnerability_patterns['weak_encryption']
        assert 'hmac-md5' in self.scanner.vulnerability_patterns['weak_mac']
        assert 'diffie-hellman-group1-sha1' in self.scanner.vulnerability_patterns['weak_kex']
        
    def test_config_checks(self):
        """Test configuration audit checks"""
        assert 'permit_root_login' in self.scanner.config_checks
        assert 'password_authentication' in self.scanner.config_checks
        assert 'permit_empty_passwords' in self.scanner.config_checks
        
        # Check specific insecure values
        assert 'yes' in self.scanner.config_checks['permit_root_login']
        assert 'yes' in self.scanner.config_checks['password_authentication']