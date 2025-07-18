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
Scanner factory for creating and managing scanner instances
Reduces code duplication and provides consistent interface
"""

import asyncio
import logging
from typing import Dict, List, Any, Optional, Type, Union
from datetime import datetime
from .base_scanner import BaseScannerModule


class ScannerFactory:
    """Factory class for creating and managing scanner instances"""
    
    def __init__(self):
        self._scanners: Dict[str, Type[BaseScannerModule]] = {}
        self._default_configs: Dict[str, Dict[str, Any]] = {}
        self.logger = logging.getLogger(__name__)
    
    def register_scanner(self, name: str, scanner_class: Type[BaseScannerModule], 
                        default_config: Optional[Dict[str, Any]] = None):
        """Register a scanner class with the factory"""
        self._scanners[name] = scanner_class
        if default_config:
            self._default_configs[name] = default_config
        self.logger.debug(f"Registered scanner: {name}")
    
    def create_scanner(self, name: str, **kwargs) -> Optional[BaseScannerModule]:
        """Create a scanner instance with the given configuration"""
        if name not in self._scanners:
            self.logger.error(f"Unknown scanner: {name}")
            return None
        
        scanner_class = self._scanners[name]
        config = self._default_configs.get(name, {})
        config.update(kwargs)
        
        try:
            return scanner_class(**config)
        except Exception as e:
            self.logger.error(f"Failed to create scanner {name}: {e}")
            return None
    
    def get_available_scanners(self) -> List[str]:
        """Get list of available scanner names"""
        return list(self._scanners.keys())
    
    def get_scanner_info(self, name: str) -> Optional[Dict[str, Any]]:
        """Get information about a specific scanner"""
        if name not in self._scanners:
            return None
        
        scanner_class = self._scanners[name]
        return {
            'name': name,
            'class': scanner_class.__name__,
            'module': scanner_class.__module__,
            'description': scanner_class.__doc__ or 'No description available',
            'default_config': self._default_configs.get(name, {})
        }


class CommonScannerMixin:
    """Mixin class providing common functionality for all scanners"""
    
    def _generate_recommendations(self, results: Dict[str, Any]) -> List[str]:
        """Generate security recommendations based on scan results"""
        recommendations = []
        
        # Common security recommendations
        if results.get('open_ports'):
            recommendations.append("Review open ports and disable unnecessary services")
        
        if results.get('vulnerabilities'):
            critical_vulns = [v for v in results['vulnerabilities'] if v.get('severity') == 'critical']
            if critical_vulns:
                recommendations.append(f"Address {len(critical_vulns)} critical vulnerabilities immediately")
        
        if results.get('weak_configurations'):
            recommendations.append("Update weak security configurations")
        
        if results.get('outdated_software'):
            recommendations.append("Update outdated software packages")
        
        return recommendations
    
    def _compile_vulnerabilities(self, results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Compile vulnerability information from scan results"""
        vulnerabilities = []
        
        # Extract vulnerabilities from different result types
        if 'vulnerabilities' in results:
            vulnerabilities.extend(results['vulnerabilities'])
        
        if 'security_issues' in results:
            for issue in results['security_issues']:
                vulnerabilities.append({
                    'type': 'security_issue',
                    'description': issue.get('description', 'Unknown issue'),
                    'severity': issue.get('severity', 'medium'),
                    'affected_component': issue.get('component', 'unknown')
                })
        
        if 'weak_configurations' in results:
            for config in results['weak_configurations']:
                vulnerabilities.append({
                    'type': 'configuration',
                    'description': f"Weak configuration: {config}",
                    'severity': 'low',
                    'affected_component': 'system_configuration'
                })
        
        return vulnerabilities
    
    def _calculate_risk_score(self, vulnerabilities: List[Dict[str, Any]]) -> int:
        """Calculate overall risk score based on vulnerabilities"""
        if not vulnerabilities:
            return 0
        
        severity_weights = {
            'critical': 10,
            'high': 8,
            'medium': 5,
            'low': 3,
            'info': 1
        }
        
        total_score = 0
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'medium').lower()
            total_score += severity_weights.get(severity, 5)
        
        # Normalize to 0-100 scale
        max_possible_score = len(vulnerabilities) * 10
        if max_possible_score == 0:
            return 0
        
        return min(int((total_score / max_possible_score) * 100), 100)
    
    def _format_scan_results(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Format scan results in a consistent structure"""
        vulnerabilities = self._compile_vulnerabilities(results)
        recommendations = self._generate_recommendations(results)
        risk_score = self._calculate_risk_score(vulnerabilities)
        
        return {
            'scan_info': {
                'scanner': getattr(self, 'name', 'unknown'),
                'timestamp': datetime.now().isoformat(),
                'target': results.get('target', 'unknown'),
                'duration': getattr(self, 'get_scan_duration', lambda: 0)(),
                'risk_score': risk_score
            },
            'vulnerabilities': vulnerabilities,
            'recommendations': recommendations,
            'raw_results': results,
            'summary': {
                'total_vulnerabilities': len(vulnerabilities),
                'critical_vulnerabilities': len([v for v in vulnerabilities if v.get('severity') == 'critical']),
                'high_vulnerabilities': len([v for v in vulnerabilities if v.get('severity') == 'high']),
                'medium_vulnerabilities': len([v for v in vulnerabilities if v.get('severity') == 'medium']),
                'low_vulnerabilities': len([v for v in vulnerabilities if v.get('severity') == 'low'])
            }
        }


class AsyncScannerMixin:
    """Mixin class providing async functionality for scanners"""
    
    async def _run_with_timeout(self, coro, timeout: int = 30):
        """Run a coroutine with timeout"""
        try:
            return await asyncio.wait_for(coro, timeout=timeout)
        except asyncio.TimeoutError:
            self.logger.warning(f"Operation timed out after {timeout} seconds")
            return None
        except Exception as e:
            self.logger.error(f"Operation failed: {e}")
            return None
    
    async def _batch_process(self, items: List[Any], batch_size: int = 10, 
                           max_workers: int = 100) -> List[Any]:
        """Process items in batches with concurrency control"""
        results = []
        semaphore = asyncio.Semaphore(max_workers)
        
        async def process_item(item):
            async with semaphore:
                return await self._process_single_item(item)
        
        # Process items in batches
        for i in range(0, len(items), batch_size):
            batch = items[i:i + batch_size]
            batch_results = await asyncio.gather(
                *[process_item(item) for item in batch],
                return_exceptions=True
            )
            results.extend(batch_results)
        
        return results
    
    async def _process_single_item(self, item: Any) -> Any:
        """Process a single item (to be implemented by subclasses)"""
        raise NotImplementedError("Subclasses must implement _process_single_item")


# Global scanner factory instance
scanner_factory = ScannerFactory()


def register_all_scanners():
    """Register all available scanners with the factory"""
    
    # Import and register all scanner modules
    try:
        from .port_scanner import PortScanner
        scanner_factory.register_scanner('port_scanner', PortScanner, {
            'timeout': 30,
            'ports': 'common'
        })
    except ImportError:
        pass
    
    try:
        from .ssh_scanner import SSHScanner
        scanner_factory.register_scanner('ssh_scanner', SSHScanner, {
            'timeout': 30,
            'max_attempts': 3
        })
    except ImportError:
        pass
    
    try:
        from .vulnerability_scanner import VulnerabilityScanner
        scanner_factory.register_scanner('vulnerability_scanner', VulnerabilityScanner, {
            'timeout': 60
        })
    except ImportError:
        pass
    
    try:
        from .network_scanner import NetworkScanner
        scanner_factory.register_scanner('network_scanner', NetworkScanner, {
            'timeout': 30,
            'capture_duration': 60
        })
    except ImportError:
        pass
    
    try:
        from .crypto_scanner import CryptoScanner
        scanner_factory.register_scanner('crypto_scanner', CryptoScanner, {
            'timeout': 30
        })
    except ImportError:
        pass
    
    try:
        from .system_check import SystemCheckModule
        scanner_factory.register_scanner('system_check', SystemCheckModule, {
            'timeout': 30
        })
    except ImportError:
        pass
    
    try:
        from .web_scanner import WebScanner
        scanner_factory.register_scanner('web_scanner', WebScanner, {
            'timeout': 30
        })
    except ImportError:
        pass
    
    try:
        from .database_scanner import DatabaseScanner
        scanner_factory.register_scanner('database_scanner', DatabaseScanner, {
            'timeout': 30
        })
    except ImportError:
        pass
    
    try:
        from .malware_scanner import MalwareScanner
        scanner_factory.register_scanner('malware_scanner', MalwareScanner, {
            'timeout': 60
        })
    except ImportError:
        pass
    
    try:
        from .config_scanner import ConfigScanner
        scanner_factory.register_scanner('config_scanner', ConfigScanner, {
            'timeout': 30
        })
    except ImportError:
        pass
    
    try:
        from .forensics_scanner import ForensicsScanner
        scanner_factory.register_scanner('forensics_scanner', ForensicsScanner, {
            'timeout': 60
        })
    except ImportError:
        pass
    
    try:
        from .iot_scanner import IoTDeviceScanner
        scanner_factory.register_scanner('iot_scanner', IoTDeviceScanner, {
            'timeout': 30
        })
    except ImportError:
        pass
    
    try:
        from .memory_scanner import MemoryAnalysisScanner
        scanner_factory.register_scanner('memory_scanner', MemoryAnalysisScanner, {
            'timeout': 60
        })
    except ImportError:
        pass
    
    try:
        from .steganography_scanner import SteganographyScanner
        scanner_factory.register_scanner('steganography_scanner', SteganographyScanner, {
            'timeout': 30
        })
    except ImportError:
        pass
    
    try:
        from .traffic_scanner import TrafficScanner
        scanner_factory.register_scanner('traffic_scanner', TrafficScanner, {
            'timeout': 60
        })
    except ImportError:
        pass


# Auto-register scanners when module is imported
register_all_scanners()