"""
Tests for Enhanced CLI module
"""

import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from click.testing import CliRunner

from linuxscan.enhanced_cli import (
    cli, quick_scan, advanced_scan, network_discovery, 
    ssh_scan, configuration_cmd, list_scanners_cmd
)


class TestEnhancedCLI:
    """Test Enhanced CLI module"""
    
    def test_cli_group(self):
        """Test CLI group initialization"""
        runner = CliRunner()
        result = runner.invoke(cli, ['--help'])
        
        assert result.exit_code == 0
        assert 'LinuxScan' in result.output
        assert 'quick-scan' in result.output
        assert 'advanced-scan' in result.output
        assert 'network-discovery' in result.output
    
    def test_quick_scan_basic(self):
        """Test quick scan command"""
        runner = CliRunner()
        
        with patch('linuxscan.enhanced_cli.EnhancedScanner') as mock_scanner:
            mock_instance = MagicMock()
            mock_scanner.return_value = mock_instance
            
            # Mock async scan method
            async def mock_scan(*args, **kwargs):
                return {
                    'target': '192.168.1.100',
                    'scan_type': 'quick',
                    'results': {'open_ports': {80: 'HTTP', 22: 'SSH'}}
                }
            
            mock_instance.scan = AsyncMock(side_effect=mock_scan)
            
            result = runner.invoke(quick_scan, ['192.168.1.100'])
            
            assert result.exit_code == 0
            mock_instance.scan.assert_called_once()
    
    def test_quick_scan_with_options(self):
        """Test quick scan with options"""
        runner = CliRunner()
        
        with patch('linuxscan.enhanced_cli.EnhancedScanner') as mock_scanner:
            mock_instance = MagicMock()
            mock_scanner.return_value = mock_instance
            
            async def mock_scan(*args, **kwargs):
                return {
                    'target': '192.168.1.100',
                    'scan_type': 'quick',
                    'results': {'open_ports': {80: 'HTTP'}}
                }
            
            mock_instance.scan = AsyncMock(side_effect=mock_scan)
            
            result = runner.invoke(quick_scan, [
                '192.168.1.100',
                '--timeout', '30',
                '--ports', '80,443,22',
                '--output', '/tmp/scan_results.json'
            ])
            
            assert result.exit_code == 0
    
    def test_advanced_scan_basic(self):
        """Test advanced scan command"""
        runner = CliRunner()
        
        with patch('linuxscan.enhanced_cli.EnhancedScanner') as mock_scanner:
            mock_instance = MagicMock()
            mock_scanner.return_value = mock_instance
            
            async def mock_scan(*args, **kwargs):
                return {
                    'target': '192.168.1.100',
                    'scan_type': 'comprehensive',
                    'results': {
                        'port_scan': {'open_ports': {80: 'HTTP', 22: 'SSH'}},
                        'vulnerability_scan': {'vulnerabilities': []}
                    }
                }
            
            mock_instance.scan = AsyncMock(side_effect=mock_scan)
            
            result = runner.invoke(advanced_scan, ['192.168.1.100'])
            
            assert result.exit_code == 0
    
    def test_advanced_scan_with_modules(self):
        """Test advanced scan with specific modules"""
        runner = CliRunner()
        
        with patch('linuxscan.enhanced_cli.EnhancedScanner') as mock_scanner:
            mock_instance = MagicMock()
            mock_scanner.return_value = mock_instance
            
            async def mock_scan(*args, **kwargs):
                return {
                    'target': '192.168.1.100',
                    'scan_type': 'comprehensive',
                    'modules': kwargs.get('modules', []),
                    'results': {}
                }
            
            mock_instance.scan = AsyncMock(side_effect=mock_scan)
            
            result = runner.invoke(advanced_scan, [
                '192.168.1.100',
                '--modules', 'port_scanner,vulnerability_scanner',
                '--timeout', '60'
            ])
            
            assert result.exit_code == 0
    
    def test_network_discovery_basic(self):
        """Test network discovery command"""
        runner = CliRunner()
        
        with patch('linuxscan.enhanced_cli.NetworkScanner') as mock_scanner:
            mock_instance = MagicMock()
            mock_scanner.return_value = mock_instance
            
            async def mock_scan(*args, **kwargs):
                return {
                    'target': '192.168.1.0/24',
                    'scan_type': 'discovery',
                    'results': {
                        'live_hosts': ['192.168.1.100', '192.168.1.101'],
                        'host_details': {}
                    }
                }
            
            mock_instance.scan = AsyncMock(side_effect=mock_scan)
            
            result = runner.invoke(network_discovery, ['192.168.1.0/24'])
            
            assert result.exit_code == 0
    
    def test_ssh_scan_basic(self):
        """Test SSH scan command"""
        runner = CliRunner()
        
        with patch('linuxscan.enhanced_cli.SSHScanner') as mock_scanner:
            mock_instance = MagicMock()
            mock_scanner.return_value = mock_instance
            
            async def mock_scan(*args, **kwargs):
                return {
                    'target': '192.168.1.100',
                    'scan_type': 'ssh',
                    'results': {
                        'ssh_services': [
                            {'port': 22, 'version': 'OpenSSH_7.4'}
                        ]
                    }
                }
            
            mock_instance.scan = AsyncMock(side_effect=mock_scan)
            
            result = runner.invoke(ssh_scan, ['192.168.1.100'])
            
            assert result.exit_code == 0
    
    def test_ssh_scan_with_credentials(self):
        """Test SSH scan with credentials"""
        runner = CliRunner()
        
        with patch('linuxscan.enhanced_cli.SSHScanner') as mock_scanner:
            mock_instance = MagicMock()
            mock_scanner.return_value = mock_instance
            
            async def mock_scan(*args, **kwargs):
                return {
                    'target': '192.168.1.100',
                    'scan_type': 'ssh',
                    'results': {
                        'authentication_test': {
                            'username': 'admin',
                            'password': 'admin123',
                            'success': True
                        }
                    }
                }
            
            mock_instance.scan = AsyncMock(side_effect=mock_scan)
            
            result = runner.invoke(ssh_scan, [
                '192.168.1.100',
                '--username', 'admin',
                '--password', 'admin123'
            ])
            
            assert result.exit_code == 0
    
    def test_configuration_view(self):
        """Test configuration view command"""
        runner = CliRunner()
        
        with patch('linuxscan.enhanced_cli.ScanConfig') as mock_config:
            mock_instance = MagicMock()
            mock_config.return_value = mock_instance
            
            mock_instance.to_dict.return_value = {
                'scan_timeout': 30,
                'max_concurrent': 100,
                'output_format': 'json'
            }
            
            result = runner.invoke(configuration_cmd, ['view'])
            
            assert result.exit_code == 0
            assert 'scan_timeout' in result.output
    
    def test_configuration_set(self):
        """Test configuration set command"""
        runner = CliRunner()
        
        with patch('linuxscan.enhanced_cli.ScanConfig') as mock_config:
            mock_instance = MagicMock()
            mock_config.return_value = mock_instance
            
            result = runner.invoke(configuration_cmd, [
                'set',
                'scan_timeout', '60'
            ])
            
            assert result.exit_code == 0
            mock_instance.set_value.assert_called_once_with('scan_timeout', '60')
    
    def test_list_scanners_command(self):
        """Test list scanners command"""
        runner = CliRunner()
        
        with patch('linuxscan.enhanced_cli.scanner_registry') as mock_registry:
            mock_registry.list_scanners.return_value = [
                'port_scanner',
                'vulnerability_scanner',
                'ssh_scanner',
                'network_scanner'
            ]
            
            result = runner.invoke(list_scanners_cmd)
            
            assert result.exit_code == 0
            assert 'port_scanner' in result.output
            assert 'vulnerability_scanner' in result.output
    
    def test_output_formats(self):
        """Test different output formats"""
        runner = CliRunner()
        
        with patch('linuxscan.enhanced_cli.EnhancedScanner') as mock_scanner:
            mock_instance = MagicMock()
            mock_scanner.return_value = mock_instance
            
            async def mock_scan(*args, **kwargs):
                return {
                    'target': '192.168.1.100',
                    'scan_type': 'quick',
                    'results': {'open_ports': {80: 'HTTP'}}
                }
            
            mock_instance.scan = AsyncMock(side_effect=mock_scan)
            
            # Test JSON output
            result = runner.invoke(quick_scan, [
                '192.168.1.100',
                '--output-format', 'json'
            ])
            assert result.exit_code == 0
            
            # Test XML output
            result = runner.invoke(quick_scan, [
                '192.168.1.100',
                '--output-format', 'xml'
            ])
            assert result.exit_code == 0
            
            # Test CSV output
            result = runner.invoke(quick_scan, [
                '192.168.1.100',
                '--output-format', 'csv'
            ])
            assert result.exit_code == 0
    
    def test_error_handling(self):
        """Test error handling in CLI"""
        runner = CliRunner()
        
        with patch('linuxscan.enhanced_cli.EnhancedScanner') as mock_scanner:
            mock_instance = MagicMock()
            mock_scanner.return_value = mock_instance
            
            # Mock scan that raises exception
            async def mock_scan_error(*args, **kwargs):
                raise Exception("Scan failed")
            
            mock_instance.scan = AsyncMock(side_effect=mock_scan_error)
            
            result = runner.invoke(quick_scan, ['192.168.1.100'])
            
            assert result.exit_code != 0
            assert 'error' in result.output.lower()
    
    def test_verbose_mode(self):
        """Test verbose mode"""
        runner = CliRunner()
        
        with patch('linuxscan.enhanced_cli.EnhancedScanner') as mock_scanner:
            mock_instance = MagicMock()
            mock_scanner.return_value = mock_instance
            
            async def mock_scan(*args, **kwargs):
                return {
                    'target': '192.168.1.100',
                    'scan_type': 'quick',
                    'results': {'open_ports': {80: 'HTTP'}}
                }
            
            mock_instance.scan = AsyncMock(side_effect=mock_scan)
            
            result = runner.invoke(quick_scan, [
                '192.168.1.100',
                '--verbose'
            ])
            
            assert result.exit_code == 0
    
    def test_cidr_range_validation(self):
        """Test CIDR range validation"""
        runner = CliRunner()
        
        # Test valid CIDR
        with patch('linuxscan.enhanced_cli.EnhancedScanner') as mock_scanner:
            mock_instance = MagicMock()
            mock_scanner.return_value = mock_instance
            
            async def mock_scan(*args, **kwargs):
                return {
                    'target': '192.168.1.0/24',
                    'scan_type': 'quick',
                    'results': {}
                }
            
            mock_instance.scan = AsyncMock(side_effect=mock_scan)
            
            result = runner.invoke(quick_scan, ['192.168.1.0/24'])
            assert result.exit_code == 0
        
        # Test invalid CIDR
        result = runner.invoke(quick_scan, ['invalid.cidr.range'])
        assert result.exit_code != 0
    
    def test_concurrent_scanning(self):
        """Test concurrent scanning options"""
        runner = CliRunner()
        
        with patch('linuxscan.enhanced_cli.EnhancedScanner') as mock_scanner:
            mock_instance = MagicMock()
            mock_scanner.return_value = mock_instance
            
            async def mock_scan(*args, **kwargs):
                return {
                    'target': '192.168.1.100',
                    'scan_type': 'quick',
                    'max_concurrent': kwargs.get('max_concurrent', 100),
                    'results': {}
                }
            
            mock_instance.scan = AsyncMock(side_effect=mock_scan)
            
            result = runner.invoke(quick_scan, [
                '192.168.1.100',
                '--max-concurrent', '50'
            ])
            
            assert result.exit_code == 0
    
    def test_save_results(self):
        """Test saving scan results"""
        runner = CliRunner()
        
        with patch('linuxscan.enhanced_cli.EnhancedScanner') as mock_scanner:
            mock_instance = MagicMock()
            mock_scanner.return_value = mock_instance
            
            async def mock_scan(*args, **kwargs):
                return {
                    'target': '192.168.1.100',
                    'scan_type': 'quick',
                    'results': {'open_ports': {80: 'HTTP'}}
                }
            
            mock_instance.scan = AsyncMock(side_effect=mock_scan)
            
            with patch('builtins.open', create=True) as mock_open:
                mock_file = MagicMock()
                mock_open.return_value.__enter__.return_value = mock_file
                
                result = runner.invoke(quick_scan, [
                    '192.168.1.100',
                    '--output', '/tmp/scan_results.json'
                ])
                
                assert result.exit_code == 0
                mock_open.assert_called_once()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])