"""
Test CLI functionality
"""

import pytest
import asyncio
from unittest.mock import patch, AsyncMock, MagicMock
from argparse import Namespace

from linuxscan.cli import (
    create_parser, parse_targets, load_targets_from_file,
    load_config, run_scan, main
)


class TestCLIParser:
    """Test command line argument parsing"""
    
    def test_create_parser_basic(self):
        """Test basic parser creation"""
        parser = create_parser()
        assert parser.prog is not None
        assert "Linux Security Scanner" in parser.description
    
    def test_parse_positional_targets(self):
        """Test parsing positional target arguments"""
        parser = create_parser()
        args = parser.parse_args(['192.168.1.1', '10.0.0.0/24'])
        assert args.targets == ['192.168.1.1', '10.0.0.0/24']
    
    def test_parse_target_list_argument(self):
        """Test parsing --targets argument"""
        parser = create_parser()
        args = parser.parse_args(['-t', '192.168.1.1,10.0.0.1'])
        assert args.target_list == '192.168.1.1,10.0.0.1'
    
    def test_parse_file_argument(self):
        """Test parsing --file argument"""
        parser = create_parser()
        args = parser.parse_args(['-f', 'targets.txt'])
        assert args.target_file == 'targets.txt'
    
    def test_parse_config_argument(self):
        """Test parsing --config argument"""
        parser = create_parser()
        args = parser.parse_args(['-c', 'config.json'])
        assert args.config_file == 'config.json'
    
    def test_parse_output_arguments(self):
        """Test parsing output-related arguments"""
        parser = create_parser()
        args = parser.parse_args(['-o', 'results.json', '--format', 'csv', '192.168.1.1'])
        assert args.output_file == 'results.json'
        assert args.format == 'csv'
    
    def test_parse_scan_parameters(self):
        """Test parsing scan parameter arguments"""
        parser = create_parser()
        args = parser.parse_args(['--timeout', '10', '--max-workers', '100', '192.168.1.1'])
        assert args.timeout == 10
        assert args.max_workers == 100
    
    def test_parse_flags(self):
        """Test parsing flag arguments"""
        parser = create_parser()
        args = parser.parse_args(['--interactive', '--no-banner', '-v', '192.168.1.1'])
        assert args.interactive is True
        assert args.no_banner is True
        assert args.verbose is True


class TestTargetParsing:
    """Test target parsing functionality"""
    
    def test_parse_targets_positional(self):
        """Test parsing targets from positional arguments"""
        args = Namespace(targets=['192.168.1.1', '10.0.0.0/24'], target_list=None, target_file=None)
        targets = parse_targets(args)
        assert targets == ['192.168.1.1', '10.0.0.0/24']
    
    def test_parse_targets_list(self):
        """Test parsing targets from --targets argument"""
        args = Namespace(targets=[], target_list='192.168.1.1, 10.0.0.1, 172.16.0.1', target_file=None)
        targets = parse_targets(args)
        assert targets == ['192.168.1.1', '10.0.0.1', '172.16.0.1']
    
    @patch('linuxscan.cli.load_targets_from_file')
    def test_parse_targets_file(self, mock_load):
        """Test parsing targets from file"""
        mock_load.return_value = ['192.168.1.100', '192.168.1.101']
        args = Namespace(targets=[], target_list=None, target_file='targets.txt')
        targets = parse_targets(args)
        mock_load.assert_called_once_with('targets.txt')
        assert targets == ['192.168.1.100', '192.168.1.101']
    
    def test_parse_targets_combined(self):
        """Test parsing targets from multiple sources"""
        with patch('linuxscan.cli.load_targets_from_file') as mock_load:
            mock_load.return_value = ['file.target.1']
            args = Namespace(
                targets=['pos.target.1'],
                target_list='list.target.1,list.target.2',
                target_file='targets.txt'
            )
            targets = parse_targets(args)
            expected = ['pos.target.1', 'list.target.1', 'list.target.2', 'file.target.1']
            assert targets == expected


class TestFileLoading:
    """Test file loading functionality"""
    
    @patch('builtins.open', create=True)
    def test_load_targets_from_file_success(self, mock_open):
        """Test successful loading of targets from file"""
        mock_content = "192.168.1.1\n10.0.0.0/24\n# comment\n\n192.168.1.100"
        mock_open.return_value.__enter__.return_value = mock_content.split('\n')
        
        targets = load_targets_from_file('targets.txt')
        expected = ['192.168.1.1', '10.0.0.0/24', '192.168.1.100']
        assert targets == expected
    
    @patch('builtins.open', side_effect=FileNotFoundError())
    @patch('linuxscan.cli.console')
    def test_load_targets_from_file_not_found(self, mock_console, mock_open):
        """Test handling of file not found"""
        with pytest.raises(SystemExit):
            load_targets_from_file('nonexistent.txt')
        mock_console.print.assert_called()
    
    @patch('builtins.open', create=True)
    @patch('json.load')
    def test_load_config_success(self, mock_json_load, mock_open):
        """Test successful config loading"""
        mock_config = {'timeout': 10, 'verbose': True}
        mock_json_load.return_value = mock_config
        
        config = load_config('config.json')
        assert config == mock_config
    
    @patch('builtins.open', side_effect=FileNotFoundError())
    @patch('linuxscan.cli.console')
    def test_load_config_file_error(self, mock_console, mock_open):
        """Test handling of config file error"""
        with pytest.raises(SystemExit):
            load_config('nonexistent.json')
        mock_console.print.assert_called()


class TestScanExecution:
    """Test scan execution functionality"""
    
    @pytest.mark.asyncio
    async def test_run_scan_basic(self):
        """Test basic scan execution"""
        targets = ['192.168.1.1']
        args = Namespace(
            timeout=5, max_workers=50, verbose=False,
            output_file=None, format='json'
        )
        
        with patch('linuxscan.cli.SecurityScanner') as mock_scanner_class:
            mock_scanner = AsyncMock()
            mock_scanner.scan_network = AsyncMock()
            mock_scanner.generate_summary_table = MagicMock(return_value="Summary")
            mock_scanner_class.return_value = mock_scanner
            
            with patch('linuxscan.cli.console'):
                await run_scan(targets, args)
                
                mock_scanner.scan_network.assert_called_once_with(targets)
                assert mock_scanner.timeout == 5
                assert mock_scanner.max_workers == 50
    
    @pytest.mark.asyncio
    async def test_run_scan_with_config(self):
        """Test scan execution with configuration"""
        targets = ['192.168.1.1']
        args = Namespace(
            timeout=5, max_workers=50, verbose=True,
            output_file='results.json', format='json'
        )
        config = {'timeout': 15, 'max_workers': 100}
        
        with patch('linuxscan.cli.SecurityScanner') as mock_scanner_class:
            mock_scanner = AsyncMock()
            mock_scanner.scan_network = AsyncMock()
            mock_scanner.generate_summary_table = MagicMock(return_value="Summary")
            mock_scanner.export_json = MagicMock()
            mock_scanner_class.return_value = mock_scanner
            
            with patch('linuxscan.cli.console'):
                await run_scan(targets, args, config)
                
                # Should use config values over args
                assert mock_scanner.timeout == 15
                assert mock_scanner.max_workers == 100
                mock_scanner.export_json.assert_called_once_with('results.json')
    
    @pytest.mark.asyncio
    async def test_run_scan_export_formats(self):
        """Test scan execution with different export formats"""
        targets = ['192.168.1.1']
        
        for format_type in ['json', 'csv', 'html']:
            args = Namespace(
                timeout=5, max_workers=50, verbose=False,
                output_file=f'results.{format_type}', format=format_type
            )
            
            with patch('linuxscan.cli.SecurityScanner') as mock_scanner_class:
                mock_scanner = AsyncMock()
                mock_scanner.scan_network = AsyncMock()
                mock_scanner.generate_summary_table = MagicMock(return_value="Summary")
                
                # Mock export methods
                mock_scanner.export_json = MagicMock()
                mock_scanner.export_csv = MagicMock()
                mock_scanner.export_html = MagicMock()
                
                mock_scanner_class.return_value = mock_scanner
                
                with patch('linuxscan.cli.console'):
                    await run_scan(targets, args)
                    
                    # Check correct export method was called
                    if format_type == 'json':
                        mock_scanner.export_json.assert_called_once()
                    elif format_type == 'csv':
                        mock_scanner.export_csv.assert_called_once()
                    elif format_type == 'html':
                        mock_scanner.export_html.assert_called_once()


class TestMainFunction:
    """Test main CLI function"""
    
    @pytest.mark.asyncio
    @patch('linuxscan.cli.interactive_mode')
    async def test_main_interactive_no_targets(self, mock_interactive):
        """Test main function with no targets (interactive mode)"""
        mock_interactive.return_value = None
        
        with patch('sys.argv', ['linuxscan']):
            with patch('linuxscan.cli.display_banner'):
                await main()
                mock_interactive.assert_called_once()
    
    @pytest.mark.asyncio
    @patch('linuxscan.cli.run_scan')
    async def test_main_with_targets(self, mock_run_scan):
        """Test main function with targets"""
        mock_run_scan.return_value = None
        
        with patch('sys.argv', ['linuxscan', '192.168.1.1']):
            with patch('linuxscan.cli.display_banner'):
                await main()
                mock_run_scan.assert_called_once()
    
    @pytest.mark.asyncio
    @patch('linuxscan.cli.load_config')
    @patch('linuxscan.cli.run_scan')
    async def test_main_with_config(self, mock_run_scan, mock_load_config):
        """Test main function with configuration file"""
        mock_config = {'timeout': 20}
        mock_load_config.return_value = mock_config
        mock_run_scan.return_value = None
        
        with patch('sys.argv', ['linuxscan', '-c', 'config.json', '192.168.1.1']):
            with patch('linuxscan.cli.display_banner'):
                await main()
                mock_load_config.assert_called_once_with('config.json')
                mock_run_scan.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_main_keyboard_interrupt(self):
        """Test main function handling keyboard interrupt"""
        with patch('sys.argv', ['linuxscan', '192.168.1.1']):
            with patch('linuxscan.cli.display_banner'):
                with patch('linuxscan.cli.run_scan', side_effect=KeyboardInterrupt()):
                    with patch('linuxscan.cli.console') as mock_console:
                        await main()
                        mock_console.print.assert_called()


if __name__ == "__main__":
    pytest.main([__file__])