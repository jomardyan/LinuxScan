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
Optimized configuration manager with caching and validation
"""

import json
import os
import yaml
from typing import Dict, Any, Optional, List, Union
from pathlib import Path
from datetime import datetime, timedelta
import logging
import threading
from dataclasses import dataclass, asdict
from enum import Enum


class ConfigFormat(Enum):
    """Configuration file formats"""
    JSON = "json"
    YAML = "yaml"
    TOML = "toml"


@dataclass
class ScanConfig:
    """Scan configuration data class"""
    # Target configuration
    targets: List[str]
    modules: List[str]
    
    # Performance configuration
    timeout: int = 30
    max_workers: int = 100
    batch_size: int = 10
    
    # Output configuration
    output_format: str = "json"
    output_file: Optional[str] = None
    verbose: bool = False
    quiet: bool = False
    
    # Advanced scan options
    enable_service_detection: bool = False
    enable_os_detection: bool = False
    enable_banner_grabbing: bool = False
    
    # SSH configuration
    ssh_brute_force: bool = False
    ssh_max_attempts: int = 3
    ssh_delay: float = 1.0
    ssh_usernames: Optional[List[str]] = None
    ssh_passwords: Optional[List[str]] = None
    
    # Compliance configuration
    compliance_standard: Optional[str] = None
    
    # Cache configuration
    enable_caching: bool = True
    cache_ttl: int = 3600
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ScanConfig':
        """Create from dictionary"""
        return cls(**data)
    
    def validate(self) -> List[str]:
        """Validate configuration and return list of errors"""
        errors = []
        
        # Validate targets
        if not self.targets:
            errors.append("No targets specified")
        
        # Validate modules
        if not self.modules:
            errors.append("No modules specified")
        
        # Validate timeout
        if self.timeout <= 0:
            errors.append("Timeout must be positive")
        
        # Validate max_workers
        if self.max_workers <= 0:
            errors.append("Max workers must be positive")
        
        # Validate batch_size
        if self.batch_size <= 0:
            errors.append("Batch size must be positive")
        
        # Validate SSH configuration
        if self.ssh_brute_force and not (self.ssh_usernames or self.ssh_passwords):
            errors.append("SSH brute force requires usernames or passwords")
        
        if self.ssh_max_attempts <= 0:
            errors.append("SSH max attempts must be positive")
        
        if self.ssh_delay < 0:
            errors.append("SSH delay must be non-negative")
        
        return errors


class OptimizedConfigManager:
    """Optimized configuration manager with caching and validation"""
    
    def __init__(self, config_dir: Optional[str] = None):
        self.config_dir = Path(config_dir) if config_dir else Path.home() / ".linuxscan"
        self.config_dir.mkdir(parents=True, exist_ok=True)
        
        # Configuration cache
        self._config_cache: Dict[str, Any] = {}
        self._cache_timestamps: Dict[str, datetime] = {}
        self._cache_lock = threading.RLock()
        self._cache_ttl = timedelta(minutes=10)
        
        # Default configurations
        self._default_config = ScanConfig(
            targets=[],
            modules=['port_scanner', 'vulnerability_scanner'],
            timeout=30,
            max_workers=100,
            batch_size=10
        )
        
        self.logger = logging.getLogger(__name__)
        
        # Load system configuration
        self._load_system_config()
    
    def _load_system_config(self):
        """Load system-wide configuration"""
        system_config_path = self.config_dir / "system_config.json"
        if system_config_path.exists():
            try:
                with open(system_config_path, 'r') as f:
                    system_config = json.load(f)
                self._update_default_config(system_config)
            except Exception as e:
                self.logger.warning(f"Failed to load system config: {e}")
    
    def _update_default_config(self, config_data: Dict[str, Any]):
        """Update default configuration with system settings"""
        for key, value in config_data.items():
            if hasattr(self._default_config, key):
                setattr(self._default_config, key, value)
    
    def load_config(self, config_path: str, use_cache: bool = True) -> Optional[ScanConfig]:
        """Load configuration from file with caching"""
        config_path = Path(config_path)
        
        if not config_path.exists():
            self.logger.error(f"Configuration file not found: {config_path}")
            return None
        
        # Check cache first
        if use_cache:
            cached_config = self._get_cached_config(str(config_path))
            if cached_config:
                return cached_config
        
        try:
            # Determine format and load
            if config_path.suffix.lower() == '.json':
                with open(config_path, 'r') as f:
                    config_data = json.load(f)
            elif config_path.suffix.lower() in ['.yaml', '.yml']:
                with open(config_path, 'r') as f:
                    config_data = yaml.safe_load(f)
            else:
                self.logger.error(f"Unsupported config format: {config_path.suffix}")
                return None
            
            # Create config object
            config = ScanConfig.from_dict(config_data)
            
            # Validate configuration
            errors = config.validate()
            if errors:
                self.logger.error(f"Configuration validation errors: {errors}")
                return None
            
            # Cache the configuration
            if use_cache:
                self._cache_config(str(config_path), config)
            
            return config
            
        except Exception as e:
            self.logger.error(f"Failed to load configuration: {e}")
            return None
    
    def save_config(self, config: ScanConfig, config_path: str, 
                   format_type: ConfigFormat = ConfigFormat.JSON):
        """Save configuration to file"""
        config_path = Path(config_path)
        config_path.parent.mkdir(parents=True, exist_ok=True)
        
        try:
            config_data = config.to_dict()
            
            if format_type == ConfigFormat.JSON:
                with open(config_path, 'w') as f:
                    json.dump(config_data, f, indent=2, default=str)
            elif format_type == ConfigFormat.YAML:
                with open(config_path, 'w') as f:
                    yaml.dump(config_data, f, default_flow_style=False)
            else:
                raise ValueError(f"Unsupported format: {format_type}")
            
            # Update cache
            self._cache_config(str(config_path), config)
            
            self.logger.info(f"Configuration saved to: {config_path}")
            
        except Exception as e:
            self.logger.error(f"Failed to save configuration: {e}")
            raise
    
    def _get_cached_config(self, config_path: str) -> Optional[ScanConfig]:
        """Get configuration from cache if valid"""
        with self._cache_lock:
            if config_path not in self._config_cache:
                return None
            
            # Check cache expiration
            cache_time = self._cache_timestamps.get(config_path)
            if cache_time and datetime.now() - cache_time > self._cache_ttl:
                del self._config_cache[config_path]
                del self._cache_timestamps[config_path]
                return None
            
            return self._config_cache[config_path]
    
    def _cache_config(self, config_path: str, config: ScanConfig):
        """Cache configuration"""
        with self._cache_lock:
            self._config_cache[config_path] = config
            self._cache_timestamps[config_path] = datetime.now()
    
    def create_scan_config(self, targets: List[str], modules: List[str], 
                          **kwargs) -> ScanConfig:
        """Create scan configuration with defaults"""
        config_data = self._default_config.to_dict()
        config_data.update({
            'targets': targets,
            'modules': modules,
            **kwargs
        })
        
        return ScanConfig.from_dict(config_data)
    
    def get_default_config(self) -> ScanConfig:
        """Get default configuration"""
        return self._default_config
    
    def optimize_config_for_system(self, config: ScanConfig) -> ScanConfig:
        """Optimize configuration based on system resources"""
        import psutil
        
        optimized_config = ScanConfig.from_dict(config.to_dict())
        
        # Get system resources
        cpu_count = psutil.cpu_count()
        memory_gb = psutil.virtual_memory().total / (1024**3)
        
        # Optimize max_workers based on CPU count
        if cpu_count <= 2:
            optimized_config.max_workers = min(50, config.max_workers)
        elif cpu_count <= 4:
            optimized_config.max_workers = min(100, config.max_workers)
        elif cpu_count <= 8:
            optimized_config.max_workers = min(200, config.max_workers)
        else:
            optimized_config.max_workers = min(500, config.max_workers)
        
        # Optimize batch_size based on memory
        if memory_gb < 4:
            optimized_config.batch_size = min(5, config.batch_size)
        elif memory_gb < 8:
            optimized_config.batch_size = min(10, config.batch_size)
        else:
            optimized_config.batch_size = min(20, config.batch_size)
        
        # Optimize timeout based on system performance
        if cpu_count <= 2 or memory_gb < 4:
            optimized_config.timeout = max(config.timeout, 60)
        
        return optimized_config
    
    def get_config_templates(self) -> Dict[str, ScanConfig]:
        """Get predefined configuration templates"""
        return {
            'quick_scan': ScanConfig(
                targets=[],
                modules=['port_scanner'],
                timeout=15,
                max_workers=50,
                batch_size=5
            ),
            'comprehensive_scan': ScanConfig(
                targets=[],
                modules=['port_scanner', 'vulnerability_scanner', 'ssh_scanner', 'web_scanner'],
                timeout=120,
                max_workers=100,
                batch_size=10,
                enable_service_detection=True,
                enable_banner_grabbing=True
            ),
            'security_audit': ScanConfig(
                targets=[],
                modules=['vulnerability_scanner', 'config_scanner', 'malware_scanner'],
                timeout=300,
                max_workers=50,
                batch_size=5,
                enable_service_detection=True,
                enable_os_detection=True,
                enable_banner_grabbing=True
            ),
            'network_discovery': ScanConfig(
                targets=[],
                modules=['network_scanner', 'port_scanner'],
                timeout=60,
                max_workers=200,
                batch_size=20
            ),
            'compliance_scan': ScanConfig(
                targets=[],
                modules=['vulnerability_scanner', 'config_scanner', 'system_check'],
                timeout=180,
                max_workers=25,
                batch_size=3,
                compliance_standard='pci_dss'
            )
        }
    
    def validate_targets(self, targets: List[str]) -> List[str]:
        """Validate target list and return errors"""
        errors = []
        
        for target in targets:
            # Check if target is valid IP, CIDR, or hostname
            if not self._is_valid_target(target):
                errors.append(f"Invalid target format: {target}")
        
        return errors
    
    def _is_valid_target(self, target: str) -> bool:
        """Check if target is valid IP, CIDR, or hostname"""
        import ipaddress
        import re
        
        # Try IP address
        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            pass
        
        # Try CIDR notation
        try:
            ipaddress.ip_network(target, strict=False)
            return True
        except ValueError:
            pass
        
        # Try hostname
        hostname_pattern = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$')
        if hostname_pattern.match(target):
            return True
        
        return False
    
    def get_available_modules(self) -> List[str]:
        """Get list of available scanner modules"""
        return [
            'port_scanner',
            'vulnerability_scanner',
            'ssh_scanner',
            'network_scanner',
            'web_scanner',
            'database_scanner',
            'malware_scanner',
            'config_scanner',
            'system_check',
            'crypto_scanner',
            'forensics_scanner',
            'iot_scanner',
            'memory_scanner',
            'steganography_scanner',
            'traffic_scanner'
        ]
    
    def export_config_summary(self, config: ScanConfig) -> Dict[str, Any]:
        """Export configuration summary for reporting"""
        return {
            'targets': len(config.targets),
            'modules': len(config.modules),
            'performance': {
                'timeout': config.timeout,
                'max_workers': config.max_workers,
                'batch_size': config.batch_size
            },
            'features': {
                'service_detection': config.enable_service_detection,
                'os_detection': config.enable_os_detection,
                'banner_grabbing': config.enable_banner_grabbing,
                'ssh_brute_force': config.ssh_brute_force,
                'caching': config.enable_caching
            },
            'output': {
                'format': config.output_format,
                'file': config.output_file is not None,
                'verbose': config.verbose
            }
        }
    
    def clear_cache(self):
        """Clear configuration cache"""
        with self._cache_lock:
            self._config_cache.clear()
            self._cache_timestamps.clear()
        self.logger.info("Configuration cache cleared")


# Global configuration manager instance
config_manager = OptimizedConfigManager()