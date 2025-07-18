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
Linux Security Scanner Package
A high-performance comprehensive security scanning tool for remote Linux servers
"""

__version__ = "1.0.0"
__author__ = "Security Scanner Team"
__email__ = "contact@linuxscan.dev"
__description__ = "High-performance comprehensive security scanning tool for remote Linux servers"

from .enhanced_scanner import SecurityScanner
from .config import ConfigManager

# Import all scanner modules
from .modules.port_scanner import PortScanner
from .modules.vulnerability_scanner import VulnerabilityScanner
from .modules.network_scanner import NetworkScanner
from .modules.web_scanner import WebScanner
from .modules.forensics_scanner import ForensicsScanner
from .modules.config_scanner import ConfigScanner
from .modules.malware_scanner import MalwareScanner
from .modules.database_scanner import DatabaseScanner
from .modules.ssh_scanner import SSHScanner
from .modules.system_check import SystemCheckModule
from .modules.base_scanner import BaseScannerModule, scanner_registry

__all__ = [
    'SecurityScanner',
    'ConfigManager',
    'PortScanner',
    'VulnerabilityScanner',
    'NetworkScanner',
    'WebScanner',
    'ForensicsScanner',
    'ConfigScanner',
    'MalwareScanner',
    'DatabaseScanner',
    'SSHScanner',
    'SystemCheckModule',
    'BaseScannerModule',
    'scanner_registry'
]