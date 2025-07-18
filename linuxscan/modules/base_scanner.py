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
Base scanner class for all security scanning modules
"""

import asyncio
import logging
import socket
from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional
from datetime import datetime


class BaseScannerModule(ABC):
    """Base class for all security scanning modules"""
    
    def __init__(self, name: str, timeout: int = 30):
        self.name = name
        self.timeout = timeout
        self.logger = logging.getLogger(f"linuxscan.modules.{name}")
        self.results = {}
        self.scan_start_time = None
        self.scan_end_time = None
        
    @abstractmethod
    async def scan(self, target: str, **kwargs) -> Dict[str, Any]:
        """Abstract method for scanning a target"""
        pass
    
    def get_scan_duration(self) -> float:
        """Get the scan duration in seconds"""
        if self.scan_start_time and self.scan_end_time:
            return (self.scan_end_time - self.scan_start_time).total_seconds()
        return 0.0
    
    def log_scan_start(self, target: str):
        """Log the start of a scan"""
        self.scan_start_time = datetime.now()
        self.logger.info(f"Starting {self.name} scan on {target}")
    
    def log_scan_end(self, target: str):
        """Log the end of a scan"""
        self.scan_end_time = datetime.now()
        duration = self.get_scan_duration()
        self.logger.info(f"Completed {self.name} scan on {target} in {duration:.2f}s")
    
    def validate_target(self, target: str) -> bool:
        """Validate if target is reachable"""
        try:
            socket.gethostbyname(target)
            return True
        except socket.gaierror:
            return False
    
    def get_reverse_dns(self, ip: str) -> Optional[str]:
        """Get reverse DNS lookup for an IP address"""
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except socket.herror:
            return None
        except Exception:
            return None
    
    def enhance_target_info(self, target: str) -> Dict[str, Any]:
        """Enhance target information with reverse DNS and validation"""
        target_info = {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'reverse_dns': None,
            'resolved_ip': None,
            'is_reachable': False
        }
        
        try:
            # Resolve hostname to IP
            resolved_ip = socket.gethostbyname(target)
            target_info['resolved_ip'] = resolved_ip
            target_info['is_reachable'] = True
            
            # Get reverse DNS if target is already an IP
            if target == resolved_ip:
                target_info['reverse_dns'] = self.get_reverse_dns(target)
            else:
                target_info['reverse_dns'] = self.get_reverse_dns(resolved_ip)
                
        except socket.gaierror:
            target_info['is_reachable'] = False
            
        return target_info
    
    def get_severity_score(self, findings: List[str]) -> int:
        """Calculate severity score based on findings"""
        if not findings:
            return 0
        
        severity_map = {
            'critical': 10,
            'high': 8,
            'medium': 5,
            'low': 3,
            'info': 1
        }
        
        total_score = 0
        for finding in findings:
            finding_lower = finding.lower()
            if 'critical' in finding_lower:
                total_score += severity_map['critical']
            elif 'high' in finding_lower:
                total_score += severity_map['high']
            elif 'medium' in finding_lower:
                total_score += severity_map['medium']
            elif 'low' in finding_lower:
                total_score += severity_map['low']
            else:
                total_score += severity_map['info']
        
        return min(total_score, 100)  # Cap at 100


class ScannerRegistry:
    """Registry for managing scanner modules"""
    
    def __init__(self):
        self.scanners = {}
    
    def register(self, name: str, scanner_class: type):
        """Register a scanner module"""
        self.scanners[name] = scanner_class
    
    def get_scanner(self, name: str) -> Optional[type]:
        """Get a scanner by name"""
        return self.scanners.get(name)
    
    def list_scanners(self) -> List[str]:
        """List all registered scanners"""
        return list(self.scanners.keys())
    
    def create_scanner(self, name: str, **kwargs) -> Optional[BaseScannerModule]:
        """Create a scanner instance"""
        scanner_class = self.get_scanner(name)
        if scanner_class:
            return scanner_class(**kwargs)
        return None


# Global scanner registry
scanner_registry = ScannerRegistry()