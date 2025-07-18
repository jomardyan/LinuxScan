"""
Test configuration management
"""

import pytest
import json
import tempfile
from pathlib import Path
from unittest.mock import patch, mock_open

from linuxscan.config import ConfigManager, ScanConfig, LinuxScanConfig, get_default_config, load_config_from_file


class TestScanConfig:
    """Test ScanConfig dataclass"""
    
    def test_default_config(self):
        """Test default configuration values"""
        config = ScanConfig()
        assert config.timeout == 5
        assert config.max_workers == 50
        assert config.max_ports == 1000
        assert config.enable_ssl_check is True
        assert config.enable_ssh_check is True
        assert config.enable_vuln_check is True
        assert config.output_format == "json"
        assert config.verbose is False
        assert config.save_raw_output is False
        assert config.custom_ports == []  # Changed from None to []
        assert config.excluded_ports == []  # Changed from None to []
    
    def test_config_to_dict(self):
        """Test converting config to dictionary"""
        config = ScanConfig(timeout=10, verbose=True)
        data = config.to_dict()
        assert data['timeout'] == 10
        assert data['verbose'] is True
        assert 'max_workers' in data
    
    def test_config_from_dict(self):
        """Test creating config from dictionary"""
        data = {
            'timeout': 15,
            'max_workers': 100,
            'verbose': True,
            'invalid_key': 'should_be_ignored'
        }
        config = ScanConfig.from_dict(data)
        assert config.timeout == 15
        assert config.max_workers == 100
        assert config.verbose is True
        # Invalid key should be ignored
        assert not hasattr(config, 'invalid_key')


class TestConfigManager:
    """Test ConfigManager class"""
    
    def test_init_without_config_file(self):
        """Test initialization without config file"""
        with patch.object(ConfigManager, '_load_config'):
            manager = ConfigManager()
            assert manager.config_file is None
            assert isinstance(manager.config, LinuxScanConfig)
    
    def test_init_with_config_file(self):
        """Test initialization with config file"""
        with patch.object(ConfigManager, '_load_config'):
            manager = ConfigManager("/path/to/config.json")
            assert manager.config_file == Path("/path/to/config.json")
    
    def test_load_config_file_not_found(self):
        """Test loading config when file doesn't exist"""
        with patch.object(ConfigManager, '_find_config_file', return_value=None):
            manager = ConfigManager()
            # Should use default config
            assert manager.config.scan.timeout == 5
    
    def test_load_config_file_exists(self):
        """Test loading config from existing file"""
        config_data = {'scan': {'timeout': 20, 'verbose': True}}
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(config_data, f)
            temp_path = f.name
        
        try:
            manager = ConfigManager(temp_path)
            assert manager.config.scan.timeout == 20
            assert manager.config.scan.verbose is True
        finally:
            Path(temp_path).unlink()
    
    def test_load_config_invalid_json(self):
        """Test loading config with invalid JSON"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write("invalid json")
            temp_path = f.name
        
        try:
            # Should handle error gracefully and use defaults
            manager = ConfigManager(temp_path)
            assert manager.config.scan.timeout == 5  # default value
        finally:
            Path(temp_path).unlink()
    
    def test_save_config(self):
        """Test saving configuration"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            temp_path = f.name
        
        try:
            manager = ConfigManager()
            manager.config.scan.timeout = 30
            manager.save_config(temp_path)
            
            # Verify file was created with correct content
            with open(temp_path, 'r') as f:
                data = json.load(f)
            assert data['scan']['timeout'] == 30
        finally:
            Path(temp_path).unlink(missing_ok=True)
    
    def test_update_config(self):
        """Test updating configuration values"""
        manager = ConfigManager()
        manager.update_config(timeout=25, verbose=True)
        
        assert manager.config.scan.timeout == 25
        assert manager.config.scan.verbose is True
        
        # Test invalid key should raise error
        with pytest.raises(Exception):
            manager.update_config(invalid_key="ignored")
    
    def test_get_config(self):
        """Test getting configuration"""
        manager = ConfigManager()
        config = manager.get_config()
        assert isinstance(config, LinuxScanConfig)
        assert config is manager.config
        
        # Test getting specific section
        scan_config = manager.get_config("scan")
        assert isinstance(scan_config, ScanConfig)
    
    def test_create_sample_config(self):
        """Test creating sample configuration"""
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as f:
            temp_path = f.name
        
        try:
            manager = ConfigManager()
            manager.create_sample_config(temp_path)
            
            # Verify sample config was created
            assert Path(temp_path).exists()
            with open(temp_path, 'r') as f:
                data = json.load(f)
            assert 'scan' in data
            assert 'timeout' in data['scan']
            assert 'max_workers' in data['scan']
            assert isinstance(data['scan']['custom_ports'], list)
        finally:
            Path(temp_path).unlink(missing_ok=True)


def test_get_default_config():
    """Test get_default_config function"""
    config = get_default_config()
    assert isinstance(config, LinuxScanConfig)
    assert config.scan.timeout == 5
    assert config.scan.max_workers == 50


def test_load_config_from_file():
    """Test load_config_from_file function"""
    config_data = {'scan': {'timeout': 40, 'max_workers': 200}}
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(config_data, f)
        temp_path = f.name
    
    try:
        config = load_config_from_file(temp_path)
        assert config.scan.timeout == 40
        assert config.scan.max_workers == 200
    finally:
        Path(temp_path).unlink()


if __name__ == "__main__":
    pytest.main([__file__])