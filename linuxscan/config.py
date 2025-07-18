#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Author: Hayk Jomardyan
#
"""
Configuration management for Linux Security Scanner
"""

import json
import os
from pathlib import Path
from typing import Dict, Any, Optional
from dataclasses import dataclass, asdict


@dataclass
class ScanConfig:
    """Configuration for security scanning"""
    timeout: int = 5
    max_workers: int = 50
    max_ports: int = 1000
    enable_ssl_check: bool = True
    enable_ssh_check: bool = True
    enable_vuln_check: bool = True
    output_format: str = "json"
    verbose: bool = False
    save_raw_output: bool = False
    custom_ports: Optional[list] = None
    excluded_ports: Optional[list] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ScanConfig":
        """Create from dictionary"""
        return cls(**{k: v for k, v in data.items() if k in cls.__annotations__})


class ConfigManager:
    """Manages configuration files and settings"""
    
    DEFAULT_CONFIG_PATHS = [
        Path.home() / ".linuxscan" / "config.json",
        Path.cwd() / "linuxscan.json",
        Path("/etc/linuxscan/config.json"),
    ]
    
    def __init__(self, config_file: Optional[str] = None):
        self.config_file = Path(config_file) if config_file else None
        self.config = ScanConfig()
        self._load_config()
    
    def _load_config(self) -> None:
        """Load configuration from file"""
        config_path = self._find_config_file()
        if config_path and config_path.exists():
            try:
                with open(config_path, 'r') as f:
                    data = json.load(f)
                self.config = ScanConfig.from_dict(data)
            except Exception as e:
                print(f"Warning: Could not load config from {config_path}: {e}")
    
    def _find_config_file(self) -> Optional[Path]:
        """Find configuration file"""
        if self.config_file:
            return self.config_file
        
        for path in self.DEFAULT_CONFIG_PATHS:
            if path.exists():
                return path
        
        return None
    
    def save_config(self, config_file: Optional[str] = None) -> None:
        """Save configuration to file"""
        target_path = Path(config_file) if config_file else self.config_file
        if not target_path:
            target_path = self.DEFAULT_CONFIG_PATHS[0]
        
        # Ensure directory exists
        target_path.parent.mkdir(parents=True, exist_ok=True)
        
        try:
            with open(target_path, 'w') as f:
                json.dump(self.config.to_dict(), f, indent=2)
        except Exception as e:
            raise Exception(f"Could not save config to {target_path}: {e}")
    
    def update_config(self, **kwargs) -> None:
        """Update configuration values"""
        for key, value in kwargs.items():
            if hasattr(self.config, key):
                setattr(self.config, key, value)
    
    def get_config(self) -> ScanConfig:
        """Get current configuration"""
        return self.config
    
    def create_sample_config(self, output_file: str = "linuxscan-sample.json") -> None:
        """Create a sample configuration file"""
        sample_config = {
            "timeout": 5,
            "max_workers": 50,
            "max_ports": 1000,
            "enable_ssl_check": True,
            "enable_ssh_check": True,
            "enable_vuln_check": True,
            "output_format": "json",
            "verbose": False,
            "save_raw_output": False,
            "custom_ports": [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3389],
            "excluded_ports": []
        }
        
        with open(output_file, 'w') as f:
            json.dump(sample_config, f, indent=2)
        
        print(f"Sample configuration created: {output_file}")


def get_default_config() -> ScanConfig:
    """Get default configuration"""
    return ScanConfig()


def load_config_from_file(config_file: str) -> ScanConfig:
    """Load configuration from specific file"""
    manager = ConfigManager(config_file)
    return manager.get_config()