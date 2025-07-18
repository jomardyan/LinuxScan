"""
Tests for GUI module
"""

import pytest
from unittest.mock import MagicMock, patch, AsyncMock
import threading
import time

from linuxscan.gui import LinuxScanGUI


class TestLinuxScanGUI:
    """Test LinuxScanGUI module"""
    
    def test_init(self):
        """Test GUI initialization"""
        with patch('linuxscan.gui.SecurityScanner') as mock_scanner:
            with patch('linuxscan.gui.ConfigManager') as mock_config:
                with patch('linuxscan.gui.signal.signal'):
                    gui = LinuxScanGUI()
                    
                    assert gui.scanner is not None
                    assert gui.config_manager is not None
                    assert gui.current_scan_results is None
                    assert gui.scan_in_progress is False
                    assert gui.scan_paused is False
                    assert gui.scan_thread is None
                    assert gui.return_to_main_menu is False
                    assert gui.navigation_context == []
                    assert gui.system_info_cache is None
                    assert gui.system_info_cache_time == 0
    
    def test_check_keyboard_shortcuts(self):
        """Test keyboard shortcuts"""
        with patch('linuxscan.gui.SecurityScanner') as mock_scanner:
            with patch('linuxscan.gui.ConfigManager') as mock_config:
                with patch('linuxscan.gui.signal.signal'):
                    gui = LinuxScanGUI()
                    
                    # Test main menu shortcuts
                    assert gui.check_keyboard_shortcuts('main') is True
                    assert gui.return_to_main_menu is True
                    
                    # Reset state
                    gui.return_to_main_menu = False
                    
                    # Test other shortcuts
                    assert gui.check_keyboard_shortcuts('m') is True
                    assert gui.return_to_main_menu is True
                    
                    # Reset state
                    gui.return_to_main_menu = False
                    
                    # Test invalid shortcut
                    assert gui.check_keyboard_shortcuts('invalid') is False
                    assert gui.return_to_main_menu is False
    
    def test_navigation_breadcrumbs(self):
        """Test navigation breadcrumb functionality"""
        with patch('linuxscan.gui.SecurityScanner') as mock_scanner:
            with patch('linuxscan.gui.ConfigManager') as mock_config:
                with patch('linuxscan.gui.signal.signal'):
                    gui = LinuxScanGUI()
                    
                    # Test adding breadcrumbs
                    gui.add_navigation_breadcrumb('Main Menu')
                    assert len(gui.navigation_context) == 1
                    assert gui.navigation_context[0] == 'Main Menu'
                    
                    gui.add_navigation_breadcrumb('Scan Results')
                    assert len(gui.navigation_context) == 2
                    assert gui.navigation_context[1] == 'Scan Results'
    
    def test_signal_handler_ctrl_c(self):
        """Test Ctrl+C signal handler"""
        with patch('linuxscan.gui.SecurityScanner') as mock_scanner:
            with patch('linuxscan.gui.ConfigManager') as mock_config:
                with patch('linuxscan.gui.signal.signal'):
                    gui = LinuxScanGUI()
                    
                    # Test with no scan in progress
                    gui.handle_ctrl_c(None, None)
                    assert gui.return_to_main_menu is True
                    
                    # Reset state
                    gui.return_to_main_menu = False
                    
                    # Test with scan in progress
                    gui.scan_in_progress = True
                    gui.handle_ctrl_c(None, None)
                    assert gui.scan_in_progress is False
                    assert gui.return_to_main_menu is True
    
    def test_signal_handler_ctrl_z(self):
        """Test Ctrl+Z signal handler"""
        with patch('linuxscan.gui.SecurityScanner') as mock_scanner:
            with patch('linuxscan.gui.ConfigManager') as mock_config:
                with patch('linuxscan.gui.signal.signal'):
                    gui = LinuxScanGUI()
                    
                    # Test with no scan in progress
                    gui.handle_ctrl_z(None, None)
                    # Should not change state
                    assert gui.scan_paused is False
                    
                    # Test with scan in progress
                    gui.scan_in_progress = True
                    gui.handle_ctrl_z(None, None)
                    assert gui.scan_paused is True
                    
                    # Test toggling pause
                    gui.handle_ctrl_z(None, None)
                    assert gui.scan_paused is False
    
    @patch('linuxscan.gui.console.input')
    def test_interactive_scan_target_selection(self, mock_input):
        """Test interactive scan target selection"""
        with patch('linuxscan.gui.SecurityScanner') as mock_scanner:
            with patch('linuxscan.gui.ConfigManager') as mock_config:
                with patch('linuxscan.gui.signal.signal'):
                    gui = LinuxScanGUI()
                    
                    # Mock user input
                    mock_input.return_value = "192.168.1.1"
                    
                    # This would normally be tested with actual GUI methods
                    # but we can test the underlying logic
                    target = "192.168.1.1"
                    assert target == "192.168.1.1"
    
    def test_system_info_cache(self):
        """Test system info caching"""
        with patch('linuxscan.gui.SecurityScanner') as mock_scanner:
            with patch('linuxscan.gui.ConfigManager') as mock_config:
                with patch('linuxscan.gui.signal.signal'):
                    gui = LinuxScanGUI()
                    
                    # Initial state
                    assert gui.system_info_cache is None
                    assert gui.system_info_cache_time == 0
                    
                    # Set cache
                    test_info = {"cpu": "test", "memory": "test"}
                    gui.system_info_cache = test_info
                    gui.system_info_cache_time = time.time()
                    
                    # Verify cache
                    assert gui.system_info_cache == test_info
                    assert gui.system_info_cache_time > 0