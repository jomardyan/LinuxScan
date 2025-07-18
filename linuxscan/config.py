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
Enhanced with comprehensive error handling and validation
"""

import json
import os
import yaml
from pathlib import Path
from typing import Dict, Any, Optional, List, Union
from dataclasses import dataclass, asdict, field
import logging
from datetime import datetime
import tempfile
import shutil

try:
    from .logging_config import get_logger
except ImportError:
    def get_logger(name: str) -> logging.Logger:
        return logging.getLogger(name)


class ConfigError(Exception):
    """Configuration-related errors"""
    pass


class ConfigValidationError(ConfigError):
    """Configuration validation errors"""
    pass


@dataclass
class NetworkConfig:
    """Network-related configuration"""
    timeout: int = 5
    max_workers: int = 50
    max_ports: int = 1000
    connection_timeout: int = 10
    read_timeout: int = 30
    max_retries: int = 3
    retry_delay: float = 1.0
    
    def validate(self):
        """Validate network configuration"""
        if self.timeout <= 0:
            raise ConfigValidationError("Timeout must be positive")
        if self.max_workers <= 0:
            raise ConfigValidationError("Max workers must be positive")
        if self.max_ports <= 0:
            raise ConfigValidationError("Max ports must be positive")
        if self.connection_timeout <= 0:
            raise ConfigValidationError("Connection timeout must be positive")


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
    custom_ports: Optional[List[int]] = None
    excluded_ports: Optional[List[int]] = None
    scan_modules: List[str] = field(default_factory=lambda: [
        "port_scanner", "vulnerability_scanner", "network_scanner"
    ])
    
    def __post_init__(self):
        """Post-initialization validation"""
        if self.custom_ports is None:
            self.custom_ports = []
        if self.excluded_ports is None:
            self.excluded_ports = []
        self.validate()
    
    def validate(self):
        """Validate scan configuration"""
        if self.timeout <= 0:
            raise ConfigValidationError("Timeout must be positive")
        if self.max_workers <= 0:
            raise ConfigValidationError("Max workers must be positive")
        if self.max_ports <= 0:
            raise ConfigValidationError("Max ports must be positive")
        if self.output_format not in ["json", "yaml", "csv", "html"]:
            raise ConfigValidationError(f"Invalid output format: {self.output_format}")
        
        # Validate port lists
        for port in self.custom_ports:
            if not isinstance(port, int) or port < 1 or port > 65535:
                raise ConfigValidationError(f"Invalid port: {port}")
        
        for port in self.excluded_ports:
            if not isinstance(port, int) or port < 1 or port > 65535:
                raise ConfigValidationError(f"Invalid excluded port: {port}")
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ScanConfig":
        """Create from dictionary"""
        return cls(**{k: v for k, v in data.items() if k in cls.__annotations__})


@dataclass
class LoggingConfig:
    """Logging configuration"""
    level: str = "INFO"
    format: str = "structured"
    log_to_file: bool = True
    log_to_console: bool = True
    log_directory: str = "/tmp/linuxscan_logs"
    max_log_size: int = 10 * 1024 * 1024  # 10MB
    backup_count: int = 5
    
    def validate(self):
        """Validate logging configuration"""
        valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if self.level not in valid_levels:
            raise ConfigValidationError(f"Invalid log level: {self.level}")
        
        valid_formats = ["structured", "simple", "json"]
        if self.format not in valid_formats:
            raise ConfigValidationError(f"Invalid log format: {self.format}")
        
        if self.max_log_size <= 0:
            raise ConfigValidationError("Max log size must be positive")
        
        if self.backup_count < 0:
            raise ConfigValidationError("Backup count must be non-negative")


@dataclass
class PerformanceConfig:
    """Performance monitoring configuration"""
    enable_monitoring: bool = True
    collection_interval: int = 5
    history_size: int = 100
    cpu_threshold: float = 80.0
    memory_threshold: float = 85.0
    response_time_threshold: float = 5.0
    
    def validate(self):
        """Validate performance configuration"""
        if self.collection_interval <= 0:
            raise ConfigValidationError("Collection interval must be positive")
        if self.history_size <= 0:
            raise ConfigValidationError("History size must be positive")
        if not 0 <= self.cpu_threshold <= 100:
            raise ConfigValidationError("CPU threshold must be between 0 and 100")
        if not 0 <= self.memory_threshold <= 100:
            raise ConfigValidationError("Memory threshold must be between 0 and 100")


@dataclass
class SecurityConfig:
    """Security-related configuration"""
    enable_vulnerability_scanning: bool = True
    enable_ssl_verification: bool = True
    enable_certificate_validation: bool = True
    max_scan_depth: int = 3
    allowed_targets: Optional[List[str]] = None
    blocked_targets: Optional[List[str]] = None
    
    def __post_init__(self):
        """Post-initialization"""
        if self.allowed_targets is None:
            self.allowed_targets = []
        if self.blocked_targets is None:
            self.blocked_targets = []
    
    def validate(self):
        """Validate security configuration"""
        if self.max_scan_depth <= 0:
            raise ConfigValidationError("Max scan depth must be positive")


@dataclass
class LinuxScanConfig:
    """Main configuration container"""
    network: NetworkConfig = field(default_factory=NetworkConfig)
    scan: ScanConfig = field(default_factory=ScanConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    performance: PerformanceConfig = field(default_factory=PerformanceConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    
    def validate(self):
        """Validate all configuration sections"""
        self.network.validate()
        self.scan.validate()
        self.logging.validate()
        self.performance.validate()
        self.security.validate()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "LinuxScanConfig":
        """Create from dictionary"""
        return cls(
            network=NetworkConfig(**data.get("network", {})),
            scan=ScanConfig(**data.get("scan", {})),
            logging=LoggingConfig(**data.get("logging", {})),
            performance=PerformanceConfig(**data.get("performance", {})),
            security=SecurityConfig(**data.get("security", {}))
        )


class ConfigManager:
    """Enhanced configuration manager with comprehensive error handling"""
    
    DEFAULT_CONFIG_PATHS = [
        Path.home() / ".linuxscan" / "config.json",
        Path.home() / ".linuxscan" / "config.yaml",
        Path.cwd() / "linuxscan.json",
        Path.cwd() / "linuxscan.yaml",
        Path("/etc/linuxscan/config.json"),
        Path("/etc/linuxscan/config.yaml"),
    ]
    
    def __init__(self, config_file: Optional[str] = None):
        self.config_file = Path(config_file) if config_file else None
        self.config = LinuxScanConfig()
        self.logger = get_logger("config_manager")
        self._config_history: List[Dict[str, Any]] = []
        self._load_config()
    
    def _load_config(self) -> None:
        """Load configuration from file with comprehensive error handling"""
        config_path = self._find_config_file()
        if config_path and config_path.exists():
            try:
                data = self._load_file(config_path)
                self.config = LinuxScanConfig.from_dict(data)
                self.config.validate()
                self.logger.info(f"Configuration loaded from {config_path}")
                
                # Save to history
                self._config_history.append({
                    'timestamp': datetime.now().isoformat(),
                    'source': str(config_path),
                    'action': 'loaded',
                    'config': self.config.to_dict()
                })
                
            except ConfigValidationError as e:
                self.logger.error(f"Configuration validation error in {config_path}: {e}")
                raise
            except Exception as e:
                self.logger.error(f"Could not load config from {config_path}: {e}")
                self.logger.info("Using default configuration")
        else:
            self.logger.info("No configuration file found, using defaults")
    
    def _load_file(self, path: Path) -> Dict[str, Any]:
        """Load configuration file (JSON or YAML)"""
        try:
            with open(path, 'r') as f:
                if path.suffix.lower() in ['.yaml', '.yml']:
                    return yaml.safe_load(f) or {}
                else:
                    return json.load(f) or {}
        except json.JSONDecodeError as e:
            raise ConfigError(f"Invalid JSON in {path}: {e}")
        except yaml.YAMLError as e:
            raise ConfigError(f"Invalid YAML in {path}: {e}")
        except Exception as e:
            raise ConfigError(f"Could not read {path}: {e}")
    
    def _find_config_file(self) -> Optional[Path]:
        """Find configuration file with priority"""
        if self.config_file:
            if self.config_file.exists():
                return self.config_file
            else:
                self.logger.warning(f"Specified config file not found: {self.config_file}")
                return None
        
        for path in self.DEFAULT_CONFIG_PATHS:
            if path.exists():
                return path
        
        return None
    
    def save_config(self, config_file: Optional[str] = None, format: str = "json") -> None:
        """Save configuration to file with backup"""
        target_path = Path(config_file) if config_file else self.config_file
        if not target_path:
            target_path = self.DEFAULT_CONFIG_PATHS[0]
        
        # Ensure directory exists
        target_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Create backup if file exists
        if target_path.exists():
            backup_path = target_path.with_suffix(f".backup.{datetime.now().strftime('%Y%m%d_%H%M%S')}")
            shutil.copy2(target_path, backup_path)
            self.logger.info(f"Backup created: {backup_path}")
        
        try:
            # Write to temporary file first
            with tempfile.NamedTemporaryFile(mode='w', suffix=target_path.suffix, delete=False) as tmp_file:
                if format.lower() == "yaml":
                    yaml.dump(self.config.to_dict(), tmp_file, default_flow_style=False, indent=2)
                else:
                    json.dump(self.config.to_dict(), tmp_file, indent=2)
                tmp_path = tmp_file.name
            
            # Move temporary file to target
            shutil.move(tmp_path, target_path)
            
            self.logger.info(f"Configuration saved to {target_path}")
            
            # Save to history
            self._config_history.append({
                'timestamp': datetime.now().isoformat(),
                'source': str(target_path),
                'action': 'saved',
                'config': self.config.to_dict()
            })
            
        except Exception as e:
            # Clean up temporary file if it exists
            if 'tmp_path' in locals() and Path(tmp_path).exists():
                Path(tmp_path).unlink()
            raise ConfigError(f"Could not save config to {target_path}: {e}")
    
    def update_config(self, section: str = None, **kwargs) -> None:
        """Update configuration values with validation"""
        try:
            if section:
                # Update specific section
                config_section = getattr(self.config, section, None)
                if config_section is None:
                    raise ConfigError(f"Invalid configuration section: {section}")
                
                for key, value in kwargs.items():
                    if hasattr(config_section, key):
                        setattr(config_section, key, value)
                    else:
                        raise ConfigError(f"Invalid configuration key: {section}.{key}")
                
                # Validate the updated section
                config_section.validate()
            else:
                # Update root level (scan config for backward compatibility)
                for key, value in kwargs.items():
                    if hasattr(self.config.scan, key):
                        setattr(self.config.scan, key, value)
                    else:
                        raise ConfigError(f"Invalid configuration key: {key}")
                
                # Validate the updated config
                self.config.scan.validate()
            
            # Validate entire config
            self.config.validate()
            
            self.logger.info(f"Configuration updated: {kwargs}")
            
        except ConfigValidationError as e:
            self.logger.error(f"Configuration validation error: {e}")
            raise
        except Exception as e:
            self.logger.error(f"Error updating configuration: {e}")
            raise ConfigError(f"Error updating configuration: {e}")
    
    def get_config(self, section: str = None) -> Union[LinuxScanConfig, Any]:
        """Get configuration or specific section"""
        if section:
            return getattr(self.config, section, None)
        return self.config
    
    def get_scan_config(self) -> ScanConfig:
        """Get scan configuration (backward compatibility)"""
        return self.config.scan
    
    def reload_config(self) -> None:
        """Reload configuration from file"""
        self.logger.info("Reloading configuration")
        self._load_config()
    
    def create_sample_config(self, output_file: str = "linuxscan-sample.json") -> None:
        """Create a comprehensive sample configuration file"""
        sample_config = LinuxScanConfig()
        
        # Customize with useful defaults
        sample_config.scan.custom_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3389]
        sample_config.scan.excluded_ports = []
        sample_config.logging.level = "INFO"
        sample_config.performance.enable_monitoring = True
        sample_config.security.allowed_targets = ["192.168.1.0/24", "10.0.0.0/8"]
        
        output_path = Path(output_file)
        
        try:
            with open(output_path, 'w') as f:
                if output_path.suffix.lower() in ['.yaml', '.yml']:
                    yaml.dump(sample_config.to_dict(), f, default_flow_style=False, indent=2)
                else:
                    json.dump(sample_config.to_dict(), f, indent=2)
            
            self.logger.info(f"Sample configuration created: {output_file}")
            
        except Exception as e:
            raise ConfigError(f"Could not create sample config: {e}")
    
    def validate_config(self) -> List[str]:
        """Validate current configuration and return any errors"""
        errors = []
        
        try:
            self.config.validate()
        except ConfigValidationError as e:
            errors.append(str(e))
        
        return errors
    
    def get_config_history(self) -> List[Dict[str, Any]]:
        """Get configuration change history"""
        return self._config_history.copy()
    
    def export_config(self, output_file: str, format: str = "json") -> None:
        """Export configuration to file"""
        output_path = Path(output_file)
        
        try:
            with open(output_path, 'w') as f:
                if format.lower() == "yaml":
                    yaml.dump(self.config.to_dict(), f, default_flow_style=False, indent=2)
                else:
                    json.dump(self.config.to_dict(), f, indent=2)
            
            self.logger.info(f"Configuration exported to {output_file}")
            
        except Exception as e:
            raise ConfigError(f"Could not export config: {e}")
    
    def import_config(self, input_file: str) -> None:
        """Import configuration from file"""
        input_path = Path(input_file)
        
        if not input_path.exists():
            raise ConfigError(f"Configuration file not found: {input_file}")
        
        try:
            data = self._load_file(input_path)
            new_config = LinuxScanConfig.from_dict(data)
            new_config.validate()
            
            # Backup current config
            old_config = self.config
            self.config = new_config
            
            self.logger.info(f"Configuration imported from {input_file}")
            
            # Save to history
            self._config_history.append({
                'timestamp': datetime.now().isoformat(),
                'source': str(input_path),
                'action': 'imported',
                'config': self.config.to_dict()
            })
            
        except (ConfigValidationError, ConfigError):
            raise
        except Exception as e:
            raise ConfigError(f"Could not import config from {input_file}: {e}")


def get_default_config() -> LinuxScanConfig:
    """Get default configuration"""
    return LinuxScanConfig()


def load_config_from_file(config_file: str) -> LinuxScanConfig:
    """Load configuration from specific file"""
    manager = ConfigManager(config_file)
    return manager.get_config()


# Global config manager instance
_config_manager = None


def get_config_manager() -> ConfigManager:
    """Get the global configuration manager"""
    global _config_manager
    if _config_manager is None:
        _config_manager = ConfigManager()
    return _config_manager