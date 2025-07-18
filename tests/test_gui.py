"""
Tests for GUI module
"""

import pytest
from unittest.mock import MagicMock, patch, AsyncMock
import tkinter as tk
from tkinter import ttk

from linuxscan.gui import LinuxScanGUI


class TestLinuxScanGUI:
    """Test LinuxScanGUI module"""
    
    def test_init(self):
        """Test GUI initialization"""
        with patch('tkinter.Tk') as mock_tk:
            mock_root = MagicMock()
            mock_tk.return_value = mock_root
            
            gui = LinuxScanGUI()
            
            assert gui.root is not None
            assert gui.scanner is not None
            assert gui.current_scan_task is None
    
    def test_create_widgets(self):
        """Test widget creation"""
        with patch('tkinter.Tk') as mock_tk:
            mock_root = MagicMock()
            mock_tk.return_value = mock_root
            
            gui = LinuxScanGUI()
            
            # Test that main widgets are created
            assert hasattr(gui, 'notebook')
            assert hasattr(gui, 'target_frame')
            assert hasattr(gui, 'results_frame')
            assert hasattr(gui, 'progress_frame')
    
    def test_setup_scan_tab(self):
        """Test scan tab setup"""
        with patch('tkinter.Tk') as mock_tk:
            mock_root = MagicMock()
            mock_tk.return_value = mock_root
            
            with patch('tkinter.ttk.Frame') as mock_frame:
                mock_frame_instance = MagicMock()
                mock_frame.return_value = mock_frame_instance
                
                gui = LinuxScanGUI()
                gui._setup_scan_tab()
                
                # Verify frame creation and widget setup
                assert mock_frame.called
    
    def test_setup_results_tab(self):
        """Test results tab setup"""
        with patch('tkinter.Tk') as mock_tk:
            mock_root = MagicMock()
            mock_tk.return_value = mock_root
            
            with patch('tkinter.ttk.Frame') as mock_frame:
                mock_frame_instance = MagicMock()
                mock_frame.return_value = mock_frame_instance
                
                gui = LinuxScanGUI()
                gui._setup_results_tab()
                
                # Verify results tab components
                assert hasattr(gui, 'results_tree')
                assert hasattr(gui, 'results_text')
    
    def test_setup_config_tab(self):
        """Test configuration tab setup"""
        with patch('tkinter.Tk') as mock_tk:
            mock_root = MagicMock()
            mock_tk.return_value = mock_root
            
            gui = LinuxScanGUI()
            gui._setup_config_tab()
            
            # Verify config tab components
            assert hasattr(gui, 'config_frame')
    
    def test_validate_target_ip(self):
        """Test IP address validation"""
        with patch('tkinter.Tk') as mock_tk:
            mock_root = MagicMock()
            mock_tk.return_value = mock_root
            
            gui = LinuxScanGUI()
            
            # Test valid IP
            assert gui._validate_target('192.168.1.100') == True
            
            # Test valid CIDR
            assert gui._validate_target('192.168.1.0/24') == True
            
            # Test invalid IP
            assert gui._validate_target('999.999.999.999') == False
            
            # Test invalid format
            assert gui._validate_target('not_an_ip') == False
    
    def test_start_scan_validation(self):
        """Test scan start validation"""
        with patch('tkinter.Tk') as mock_tk:
            mock_root = MagicMock()
            mock_tk.return_value = mock_root
            
            gui = LinuxScanGUI()
            
            # Mock GUI components
            gui.target_var = MagicMock()
            gui.scan_type_var = MagicMock()
            gui.start_button = MagicMock()
            gui.progress_bar = MagicMock()
            
            # Test with invalid target
            gui.target_var.get.return_value = 'invalid_target'
            gui.scan_type_var.get.return_value = 'quick'
            
            with patch('tkinter.messagebox.showerror') as mock_error:
                gui._start_scan()
                mock_error.assert_called_once()
    
    def test_start_scan_valid(self):
        """Test scan start with valid input"""
        with patch('tkinter.Tk') as mock_tk:
            mock_root = MagicMock()
            mock_tk.return_value = mock_root
            
            gui = LinuxScanGUI()
            
            # Mock GUI components
            gui.target_var = MagicMock()
            gui.scan_type_var = MagicMock()
            gui.start_button = MagicMock()
            gui.stop_button = MagicMock()
            gui.progress_bar = MagicMock()
            gui.status_var = MagicMock()
            
            # Set valid values
            gui.target_var.get.return_value = '192.168.1.100'
            gui.scan_type_var.get.return_value = 'quick'
            
            with patch('asyncio.create_task') as mock_task:
                gui._start_scan()
                mock_task.assert_called_once()
    
    def test_stop_scan(self):
        """Test scan stopping"""
        with patch('tkinter.Tk') as mock_tk:
            mock_root = MagicMock()
            mock_tk.return_value = mock_root
            
            gui = LinuxScanGUI()
            
            # Mock GUI components
            gui.start_button = MagicMock()
            gui.stop_button = MagicMock()
            gui.progress_bar = MagicMock()
            gui.status_var = MagicMock()
            
            # Mock active scan task
            gui.current_scan_task = MagicMock()
            gui.current_scan_task.cancelled.return_value = False
            
            gui._stop_scan()
            
            # Verify scan task is cancelled
            gui.current_scan_task.cancel.assert_called_once()
    
    def test_update_progress(self):
        """Test progress update"""
        with patch('tkinter.Tk') as mock_tk:
            mock_root = MagicMock()
            mock_tk.return_value = mock_root
            
            gui = LinuxScanGUI()
            
            # Mock GUI components
            gui.progress_bar = MagicMock()
            gui.status_var = MagicMock()
            
            gui._update_progress(50, "Scanning ports...")
            
            # Verify progress update
            gui.progress_bar.config.assert_called_with(value=50)
            gui.status_var.set.assert_called_with("Scanning ports...")
    
    def test_display_results(self):
        """Test results display"""
        with patch('tkinter.Tk') as mock_tk:
            mock_root = MagicMock()
            mock_tk.return_value = mock_root
            
            gui = LinuxScanGUI()
            
            # Mock GUI components
            gui.results_tree = MagicMock()
            gui.results_text = MagicMock()
            
            # Mock scan results
            results = {
                'target': '192.168.1.100',
                'scan_type': 'quick',
                'timestamp': '2023-01-01T12:00:00',
                'results': {
                    'open_ports': {80: 'HTTP', 22: 'SSH'},
                    'vulnerabilities': [
                        {'type': 'Weak Password', 'severity': 'High'}
                    ]
                }
            }
            
            gui._display_results(results)
            
            # Verify results are displayed
            gui.results_tree.insert.assert_called()
            gui.results_text.insert.assert_called()
    
    def test_export_results(self):
        """Test results export"""
        with patch('tkinter.Tk') as mock_tk:
            mock_root = MagicMock()
            mock_tk.return_value = mock_root
            
            gui = LinuxScanGUI()
            gui.scan_results = {
                'target': '192.168.1.100',
                'results': {'open_ports': {80: 'HTTP'}}
            }
            
            with patch('tkinter.filedialog.asksaveasfilename') as mock_dialog:
                mock_dialog.return_value = '/tmp/results.json'
                
                with patch('builtins.open', create=True) as mock_open:
                    mock_file = MagicMock()
                    mock_open.return_value.__enter__.return_value = mock_file
                    
                    gui._export_results()
                    
                    # Verify file dialog and file write
                    mock_dialog.assert_called_once()
                    mock_open.assert_called_once()
    
    def test_load_configuration(self):
        """Test configuration loading"""
        with patch('tkinter.Tk') as mock_tk:
            mock_root = MagicMock()
            mock_tk.return_value = mock_root
            
            gui = LinuxScanGUI()
            
            # Mock config components
            gui.timeout_var = MagicMock()
            gui.max_concurrent_var = MagicMock()
            gui.output_format_var = MagicMock()
            
            with patch('linuxscan.gui.ScanConfig') as mock_config:
                mock_config_instance = MagicMock()
                mock_config.return_value = mock_config_instance
                
                mock_config_instance.scan_timeout = 30
                mock_config_instance.max_concurrent = 100
                mock_config_instance.output_format = 'json'
                
                gui._load_configuration()
                
                # Verify config values are loaded
                gui.timeout_var.set.assert_called_with(30)
                gui.max_concurrent_var.set.assert_called_with(100)
                gui.output_format_var.set.assert_called_with('json')
    
    def test_save_configuration(self):
        """Test configuration saving"""
        with patch('tkinter.Tk') as mock_tk:
            mock_root = MagicMock()
            mock_tk.return_value = mock_root
            
            gui = LinuxScanGUI()
            
            # Mock config components
            gui.timeout_var = MagicMock()
            gui.max_concurrent_var = MagicMock()
            gui.output_format_var = MagicMock()
            
            gui.timeout_var.get.return_value = 30
            gui.max_concurrent_var.get.return_value = 100
            gui.output_format_var.get.return_value = 'json'
            
            with patch('linuxscan.gui.ScanConfig') as mock_config:
                mock_config_instance = MagicMock()
                mock_config.return_value = mock_config_instance
                
                gui._save_configuration()
                
                # Verify config values are saved
                assert mock_config_instance.scan_timeout == 30
                assert mock_config_instance.max_concurrent == 100
                assert mock_config_instance.output_format == 'json'
    
    def test_scan_modules_selection(self):
        """Test scan modules selection"""
        with patch('tkinter.Tk') as mock_tk:
            mock_root = MagicMock()
            mock_tk.return_value = mock_root
            
            gui = LinuxScanGUI()
            
            # Mock module checkboxes
            gui.module_vars = {
                'port_scanner': MagicMock(),
                'vulnerability_scanner': MagicMock(),
                'ssh_scanner': MagicMock()
            }
            
            gui.module_vars['port_scanner'].get.return_value = 1
            gui.module_vars['vulnerability_scanner'].get.return_value = 1
            gui.module_vars['ssh_scanner'].get.return_value = 0
            
            selected_modules = gui._get_selected_modules()
            
            assert 'port_scanner' in selected_modules
            assert 'vulnerability_scanner' in selected_modules
            assert 'ssh_scanner' not in selected_modules
    
    def test_scan_history(self):
        """Test scan history functionality"""
        with patch('tkinter.Tk') as mock_tk:
            mock_root = MagicMock()
            mock_tk.return_value = mock_root
            
            gui = LinuxScanGUI()
            gui.scan_history = []
            
            # Mock scan result
            scan_result = {
                'target': '192.168.1.100',
                'scan_type': 'quick',
                'timestamp': '2023-01-01T12:00:00',
                'results': {'open_ports': {80: 'HTTP'}}
            }
            
            gui._add_to_history(scan_result)
            
            assert len(gui.scan_history) == 1
            assert gui.scan_history[0]['target'] == '192.168.1.100'
    
    def test_error_handling(self):
        """Test error handling in GUI"""
        with patch('tkinter.Tk') as mock_tk:
            mock_root = MagicMock()
            mock_tk.return_value = mock_root
            
            gui = LinuxScanGUI()
            
            # Mock error scenario
            error_message = "Connection failed"
            
            with patch('tkinter.messagebox.showerror') as mock_error:
                gui._handle_scan_error(error_message)
                mock_error.assert_called_with("Scan Error", error_message)
    
    def test_theme_management(self):
        """Test theme management"""
        with patch('tkinter.Tk') as mock_tk:
            mock_root = MagicMock()
            mock_tk.return_value = mock_root
            
            gui = LinuxScanGUI()
            
            # Test theme switching
            with patch('tkinter.ttk.Style') as mock_style:
                mock_style_instance = MagicMock()
                mock_style.return_value = mock_style_instance
                
                gui._set_theme('dark')
                
                # Verify theme is applied
                mock_style_instance.theme_use.assert_called()
    
    def test_scan_scheduling(self):
        """Test scan scheduling functionality"""
        with patch('tkinter.Tk') as mock_tk:
            mock_root = MagicMock()
            mock_tk.return_value = mock_root
            
            gui = LinuxScanGUI()
            
            # Mock scheduling components
            gui.schedule_var = MagicMock()
            gui.schedule_time_var = MagicMock()
            
            gui.schedule_var.get.return_value = 1
            gui.schedule_time_var.get.return_value = '14:30'
            
            schedule_info = gui._get_schedule_info()
            
            assert schedule_info['enabled'] == True
            assert schedule_info['time'] == '14:30'
    
    def test_real_time_updates(self):
        """Test real-time scan updates"""
        with patch('tkinter.Tk') as mock_tk:
            mock_root = MagicMock()
            mock_tk.return_value = mock_root
            
            gui = LinuxScanGUI()
            
            # Mock real-time update components
            gui.real_time_text = MagicMock()
            gui.progress_bar = MagicMock()
            
            # Simulate real-time update
            update_data = {
                'message': 'Scanning port 80...',
                'progress': 25,
                'timestamp': '2023-01-01T12:00:00'
            }
            
            gui._update_real_time_display(update_data)
            
            # Verify real-time display is updated
            gui.real_time_text.insert.assert_called()
            gui.progress_bar.config.assert_called_with(value=25)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])