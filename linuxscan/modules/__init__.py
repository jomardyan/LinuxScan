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
Security scanning modules for LinuxScan
"""

from .port_scanner import PortScanner
from .vulnerability_scanner import VulnerabilityScanner
from .network_scanner import NetworkScanner
from .web_scanner import WebScanner
from .forensics_scanner import ForensicsScanner
from .config_scanner import ConfigScanner
from .malware_scanner import MalwareScanner
from .database_scanner import DatabaseScanner
from .ssh_scanner import SSHScanner
from .system_check import SystemCheckModule
from .base_scanner import scanner_registry

# Register scanners
scanner_registry.register('port_scanner', PortScanner)
scanner_registry.register('vulnerability_scanner', VulnerabilityScanner)
scanner_registry.register('network_scanner', NetworkScanner)
scanner_registry.register('web_scanner', WebScanner)
scanner_registry.register('forensics_scanner', ForensicsScanner)
scanner_registry.register('config_scanner', ConfigScanner)
scanner_registry.register('malware_scanner', MalwareScanner)
scanner_registry.register('database_scanner', DatabaseScanner)
scanner_registry.register('ssh_scanner', SSHScanner)
scanner_registry.register('system_check', SystemCheckModule)

__all__ = [
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
    'scanner_registry'
]