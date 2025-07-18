"""
Tests for System Check module
"""

import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime

from linuxscan.modules.system_check import SystemCheck


class TestSystemCheck:
    """Test SystemCheck module"""
    
    def test_init(self):
        """Test SystemCheck initialization"""
        scanner = SystemCheck()
        assert scanner.name == "system_check"
        assert scanner.timeout == 60
        assert len(scanner.critical_services) > 0
        assert len(scanner.system_files) > 0
        assert len(scanner.security_configs) > 0
    
    @pytest.mark.asyncio
    async def test_scan_basic(self):
        """Test basic system check scanning"""
        scanner = SystemCheck()
        
        with patch.object(scanner, '_system_info_check') as mock_info:
            mock_info.return_value = {
                'hostname': 'test-server',
                'os': 'Ubuntu 20.04',
                'kernel': '5.4.0-74-generic',
                'uptime': '5 days, 10:30'
            }
            
            with patch.object(scanner, '_service_status_check') as mock_services:
                mock_services.return_value = {
                    'running_services': ['ssh', 'apache2'],
                    'stopped_services': ['mysql'],
                    'failed_services': []
                }
                
                with patch.object(scanner, '_security_config_check') as mock_security:
                    mock_security.return_value = {
                        'firewall_status': 'active',
                        'selinux_status': 'disabled',
                        'password_policy': 'weak'
                    }
                    
                    result = await scanner.scan('192.168.1.100')
                    
                    assert result['target'] == '192.168.1.100'
                    assert 'system_info' in result
                    assert 'service_status' in result
                    assert 'security_config' in result
    
    @pytest.mark.asyncio
    async def test_system_info_check(self):
        """Test system information check"""
        scanner = SystemCheck()
        
        with patch('subprocess.run') as mock_subprocess:
            # Mock hostname command
            mock_subprocess.side_effect = [
                MagicMock(returncode=0, stdout=b'test-server\n'),
                MagicMock(returncode=0, stdout=b'Ubuntu 20.04.3 LTS\n'),
                MagicMock(returncode=0, stdout=b'5.4.0-74-generic\n'),
                MagicMock(returncode=0, stdout=b'up 5 days, 10:30\n')
            ]
            
            result = await scanner._system_info_check('192.168.1.100')
            
            assert result['hostname'] == 'test-server'
            assert 'Ubuntu' in result['os']
            assert '5.4.0' in result['kernel']
            assert 'days' in result['uptime']
    
    @pytest.mark.asyncio
    async def test_service_status_check(self):
        """Test service status check"""
        scanner = SystemCheck()
        
        with patch('subprocess.run') as mock_subprocess:
            # Mock systemctl status output
            mock_subprocess.return_value.returncode = 0
            mock_subprocess.return_value.stdout = b'''
ssh.service - OpenBSD Secure Shell server
     Loaded: loaded (/lib/systemd/system/ssh.service; enabled)
     Active: active (running) since Mon 2023-01-01 10:00:00 UTC
apache2.service - The Apache HTTP Server
     Loaded: loaded (/lib/systemd/system/apache2.service; enabled)
     Active: active (running) since Mon 2023-01-01 10:00:00 UTC
mysql.service - MySQL Community Server
     Loaded: loaded (/lib/systemd/system/mysql.service; enabled)
     Active: inactive (dead)
'''
            
            result = await scanner._service_status_check('192.168.1.100')
            
            assert 'running_services' in result
            assert 'stopped_services' in result
            assert 'failed_services' in result
    
    @pytest.mark.asyncio
    async def test_security_config_check(self):
        """Test security configuration check"""
        scanner = SystemCheck()
        
        with patch('subprocess.run') as mock_subprocess:
            # Mock various security command outputs
            mock_subprocess.side_effect = [
                MagicMock(returncode=0, stdout=b'Status: active\n'),  # ufw status
                MagicMock(returncode=0, stdout=b'SELinux status: disabled\n'),  # sestatus
                MagicMock(returncode=0, stdout=b'PASS_MAX_DAYS\t90\n'),  # login.defs
                MagicMock(returncode=0, stdout=b'root:!:18900:0:99999:7:::\n')  # shadow
            ]
            
            result = await scanner._security_config_check('192.168.1.100')
            
            assert 'firewall_status' in result
            assert 'selinux_status' in result
            assert 'password_policy' in result
            assert 'user_accounts' in result
    
    def test_analyze_system_vulnerabilities(self):
        """Test system vulnerability analysis"""
        scanner = SystemCheck()
        
        system_info = {
            'os': 'Ubuntu 18.04',
            'kernel': '4.15.0-20-generic',
            'installed_packages': ['openssh-server 1:7.6p1-4ubuntu0.1']
        }
        
        vulnerabilities = scanner._analyze_system_vulnerabilities(system_info)
        
        assert isinstance(vulnerabilities, list)
        # Should find vulnerabilities for older Ubuntu version
    
    def test_check_file_integrity(self):
        """Test file integrity check"""
        scanner = SystemCheck()
        
        with patch('os.path.exists') as mock_exists:
            mock_exists.return_value = True
            
            with patch('os.stat') as mock_stat:
                mock_stat.return_value = MagicMock(st_mode=0o644, st_uid=0, st_gid=0)
                
                with patch('hashlib.sha256') as mock_hash:
                    mock_hash.return_value.hexdigest.return_value = 'abc123'
                    
                    result = scanner._check_file_integrity(['/etc/passwd', '/etc/shadow'])
                    
                    assert isinstance(result, list)
                    assert len(result) > 0
    
    def test_analyze_user_accounts(self):
        """Test user account analysis"""
        scanner = SystemCheck()
        
        shadow_content = '''
root:!:18900:0:99999:7:::
daemon:*:18900:0:99999:7:::
bin:*:18900:0:99999:7:::
user1:$6$salt$hash:18900:0:99999:7:::
user2:!:18900:0:99999:7:::
'''
        
        passwd_content = '''
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
user1:x:1000:1000:User One:/home/user1:/bin/bash
user2:x:1001:1001:User Two:/home/user2:/bin/bash
'''
        
        with patch('builtins.open', mock_open_multiple_files({
            '/etc/shadow': shadow_content,
            '/etc/passwd': passwd_content
        })):
            result = scanner._analyze_user_accounts()
            
            assert 'total_users' in result
            assert 'privileged_users' in result
            assert 'locked_accounts' in result
            assert 'password_ages' in result
    
    def test_check_network_configuration(self):
        """Test network configuration check"""
        scanner = SystemCheck()
        
        with patch('subprocess.run') as mock_subprocess:
            # Mock network interface output
            mock_subprocess.return_value.returncode = 0
            mock_subprocess.return_value.stdout = b'''
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    inet 127.0.0.1/8 scope host lo
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    inet 192.168.1.100/24 brd 192.168.1.255 scope global eth0
'''
            
            result = scanner._check_network_configuration('192.168.1.100')
            
            assert 'interfaces' in result
            assert 'routes' in result
            assert 'dns' in result
            assert len(result['interfaces']) > 0
    
    def test_analyze_running_processes(self):
        """Test running process analysis"""
        scanner = SystemCheck()
        
        with patch('subprocess.run') as mock_subprocess:
            mock_subprocess.return_value.returncode = 0
            mock_subprocess.return_value.stdout = b'''
    PID TTY          TIME CMD
      1 ?        00:00:01 systemd
   1234 ?        00:00:00 sshd
   5678 ?        00:00:00 apache2
   9012 ?        00:00:00 suspicious_process
'''
            
            result = scanner._analyze_running_processes('192.168.1.100')
            
            assert 'total_processes' in result
            assert 'system_processes' in result
            assert 'user_processes' in result
            assert 'suspicious_processes' in result
    
    def test_check_system_logs(self):
        """Test system log analysis"""
        scanner = SystemCheck()
        
        log_content = '''
Jan 1 10:00:00 server sshd[1234]: Accepted password for user from 192.168.1.50 port 22
Jan 1 10:01:00 server sshd[1235]: Failed password for invalid user admin from 192.168.1.60 port 22
Jan 1 10:02:00 server sshd[1236]: Failed password for invalid user admin from 192.168.1.60 port 22
Jan 1 10:03:00 server kernel: Out of memory: Kill process 1237 (apache2) score 123
'''
        
        with patch('builtins.open', mock_open_multiple_files({
            '/var/log/auth.log': log_content,
            '/var/log/syslog': log_content
        })):
            result = scanner._check_system_logs('192.168.1.100')
            
            assert 'failed_logins' in result
            assert 'successful_logins' in result
            assert 'system_errors' in result
            assert 'security_events' in result
    
    def test_generate_system_recommendations(self):
        """Test system recommendation generation"""
        scanner = SystemCheck()
        
        results = {
            'system_info': {
                'os': 'Ubuntu 18.04',
                'kernel': '4.15.0-20-generic'
            },
            'service_status': {
                'running_services': ['ssh', 'apache2'],
                'stopped_services': ['mysql'],
                'failed_services': ['fail2ban']
            },
            'security_config': {
                'firewall_status': 'inactive',
                'selinux_status': 'disabled',
                'password_policy': 'weak'
            },
            'vulnerability_analysis': {
                'vulnerabilities': [
                    {'type': 'Outdated OS', 'severity': 'High'},
                    {'type': 'Weak Password Policy', 'severity': 'Medium'}
                ]
            }
        }
        
        recommendations = scanner._generate_system_recommendations(results)
        
        assert len(recommendations) > 0
        assert any('update' in rec.lower() for rec in recommendations)
        assert any('firewall' in rec.lower() for rec in recommendations)
        assert any('password' in rec.lower() for rec in recommendations)
    
    def test_calculate_system_health_score(self):
        """Test system health score calculation"""
        scanner = SystemCheck()
        
        # Test healthy system
        healthy_results = {
            'service_status': {
                'failed_services': [],
                'stopped_services': []
            },
            'security_config': {
                'firewall_status': 'active',
                'selinux_status': 'enforcing',
                'password_policy': 'strong'
            },
            'vulnerability_analysis': {
                'vulnerabilities': []
            }
        }
        
        score = scanner._calculate_system_health_score(healthy_results)
        assert score >= 80  # Healthy system
        
        # Test unhealthy system
        unhealthy_results = {
            'service_status': {
                'failed_services': ['fail2ban', 'clamav'],
                'stopped_services': ['mysql', 'nginx']
            },
            'security_config': {
                'firewall_status': 'inactive',
                'selinux_status': 'disabled',
                'password_policy': 'weak'
            },
            'vulnerability_analysis': {
                'vulnerabilities': [
                    {'severity': 'Critical'},
                    {'severity': 'High'},
                    {'severity': 'Medium'}
                ]
            }
        }
        
        score = scanner._calculate_system_health_score(unhealthy_results)
        assert score <= 40  # Unhealthy system


def mock_open_multiple_files(files_dict):
    """Mock open() for multiple files"""
    def mock_open_func(filename, mode='r'):
        if filename in files_dict:
            return MagicMock(read=lambda: files_dict[filename])
        raise FileNotFoundError(f"File {filename} not found")
    return mock_open_func


if __name__ == "__main__":
    pytest.main([__file__, "-v"])