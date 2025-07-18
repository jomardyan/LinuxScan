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
Memory Analysis Scanner
Advanced memory forensics and analysis module
"""

import asyncio
import os
import psutil
import subprocess
import tempfile
import json
from typing import Dict, List, Any, Optional
from datetime import datetime
from .base_scanner import BaseScannerModule


class MemoryAnalysisScanner(BaseScannerModule):
    """Advanced memory forensics and analysis scanner"""
    
    def __init__(self, timeout: int = 300):
        super().__init__("memory_analysis_scanner", timeout)
        self.volatility_plugins = [
            'pslist', 'psscan', 'psxview', 'cmdline', 'consoles',
            'handles', 'dlls', 'netscan', 'netstat', 'malfind',
            'ldrmodules', 'modscan', 'modules', 'ssdt', 'callbacks',
            'devicetree', 'privs', 'getsids', 'envars', 'hashdump'
        ]
        self.suspicious_processes = [
            'nc', 'netcat', 'ncat', 'socat', 'tcpdump', 'wireshark',
            'mimikatz', 'pwdump', 'fgdump', 'gsecdump', 'wce',
            'procdump', 'python', 'powershell', 'cmd', 'bash'
        ]
    
    async def scan(self, target: str, **kwargs) -> Dict[str, Any]:
        """Perform memory analysis scan"""
        self.log_scan_start(target)
        
        # Enhanced target info with reverse DNS
        target_info = self.enhance_target_info(target)
        
        results = {
            'target_info': target_info,
            'scan_type': 'memory_analysis',
            'timestamp': datetime.now().isoformat(),
            'process_analysis': {},
            'network_analysis': {},
            'malware_indicators': [],
            'memory_artifacts': [],
            'system_information': {},
            'security_findings': []
        }
        
        try:
            # Analyze running processes
            await self._analyze_processes(results)
            
            # Analyze network connections
            await self._analyze_network_connections(results)
            
            # Check for malware indicators
            await self._check_malware_indicators(results)
            
            # Analyze memory usage patterns
            await self._analyze_memory_patterns(results)
            
            # System information gathering
            await self._gather_system_info(results)
            
            # If memory dump is available, analyze it
            memory_dump = kwargs.get('memory_dump')
            if memory_dump and os.path.exists(memory_dump):
                await self._analyze_memory_dump(memory_dump, results)
            
        except Exception as e:
            results['error'] = str(e)
            self.logger.error(f"Error in memory analysis scan: {e}")
        
        self.log_scan_end(target)
        return results
    
    async def _analyze_processes(self, results: Dict[str, Any]):
        """Analyze running processes for suspicious activity"""
        process_info = {
            'total_processes': 0,
            'suspicious_processes': [],
            'high_memory_processes': [],
            'network_processes': [],
            'process_details': []
        }
        
        try:
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'memory_info', 'cpu_percent', 'connections']):
                try:
                    pinfo = proc.info
                    pinfo['memory_mb'] = pinfo['memory_info'].rss / 1024 / 1024 if pinfo['memory_info'] else 0
                    
                    # Check for suspicious processes
                    if pinfo['name'] and any(susp in pinfo['name'].lower() for susp in self.suspicious_processes):
                        process_info['suspicious_processes'].append({
                            'pid': pinfo['pid'],
                            'name': pinfo['name'],
                            'cmdline': pinfo['cmdline'],
                            'memory_mb': pinfo['memory_mb'],
                            'reason': 'Suspicious process name'
                        })
                    
                    # Check for high memory usage
                    if pinfo['memory_mb'] > 500:  # > 500MB
                        process_info['high_memory_processes'].append({
                            'pid': pinfo['pid'],
                            'name': pinfo['name'],
                            'memory_mb': pinfo['memory_mb']
                        })
                    
                    # Check for network connections
                    if pinfo['connections']:
                        process_info['network_processes'].append({
                            'pid': pinfo['pid'],
                            'name': pinfo['name'],
                            'connections': len(pinfo['connections'])
                        })
                    
                    processes.append(pinfo)
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            process_info['total_processes'] = len(processes)
            process_info['process_details'] = processes[:50]  # Limit to first 50 for brevity
            
        except Exception as e:
            process_info['error'] = str(e)
        
        results['process_analysis'] = process_info
    
    async def _analyze_network_connections(self, results: Dict[str, Any]):
        """Analyze network connections for suspicious activity"""
        network_info = {
            'total_connections': 0,
            'listening_ports': [],
            'established_connections': [],
            'suspicious_connections': [],
            'connection_details': []
        }
        
        try:
            connections = psutil.net_connections(kind='inet')
            network_info['total_connections'] = len(connections)
            
            for conn in connections:
                conn_info = {
                    'fd': conn.fd,
                    'family': conn.family.name if conn.family else 'unknown',
                    'type': conn.type.name if conn.type else 'unknown',
                    'local_addr': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else 'unknown',
                    'remote_addr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else 'unknown',
                    'status': conn.status,
                    'pid': conn.pid
                }
                
                # Categorize connections
                if conn.status == psutil.CONN_LISTEN:
                    network_info['listening_ports'].append(conn_info)
                elif conn.status == psutil.CONN_ESTABLISHED:
                    network_info['established_connections'].append(conn_info)
                
                # Check for suspicious connections
                if conn.raddr and self._is_suspicious_connection(conn.raddr.ip, conn.raddr.port):
                    network_info['suspicious_connections'].append(conn_info)
                
                network_info['connection_details'].append(conn_info)
            
        except Exception as e:
            network_info['error'] = str(e)
        
        results['network_analysis'] = network_info
    
    def _is_suspicious_connection(self, ip: str, port: int) -> bool:
        """Check if connection is suspicious"""
        # Check for suspicious ports
        suspicious_ports = [4444, 4445, 31337, 12345, 54321, 9999, 8080, 1337]
        if port in suspicious_ports:
            return True
        
        # Check for suspicious IP ranges (private IPs connecting outbound)
        if ip.startswith(('10.', '192.168.', '172.')):
            return False
        
        # Check for known malicious IPs (placeholder)
        # In real implementation, this would check against threat intelligence
        return False
    
    async def _check_malware_indicators(self, results: Dict[str, Any]):
        """Check for malware indicators in memory"""
        malware_indicators = []
        
        try:
            # Check for suspicious process names
            for proc_info in results.get('process_analysis', {}).get('suspicious_processes', []):
                malware_indicators.append({
                    'type': 'suspicious_process',
                    'indicator': proc_info['name'],
                    'details': proc_info,
                    'severity': 'medium'
                })
            
            # Check for code injection indicators
            await self._check_code_injection(malware_indicators)
            
            # Check for persistence mechanisms
            await self._check_persistence_mechanisms(malware_indicators)
            
        except Exception as e:
            malware_indicators.append({
                'type': 'error',
                'indicator': 'malware_check_error',
                'details': str(e),
                'severity': 'low'
            })
        
        results['malware_indicators'] = malware_indicators
    
    async def _check_code_injection(self, indicators: List[Dict[str, Any]]):
        """Check for code injection techniques"""
        try:
            # Check for hollowed processes (simplified check)
            for proc in psutil.process_iter(['pid', 'name', 'memory_info']):
                try:
                    # Check for processes with unusual memory patterns
                    mem_info = proc.info['memory_info']
                    if mem_info and mem_info.rss > 100 * 1024 * 1024:  # > 100MB
                        # This is a simplified check
                        pass
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception:
            pass
    
    async def _check_persistence_mechanisms(self, indicators: List[Dict[str, Any]]):
        """Check for persistence mechanisms"""
        try:
            # Check for suspicious autostart entries
            # This would require more detailed system analysis
            pass
        except Exception:
            pass
    
    async def _analyze_memory_patterns(self, results: Dict[str, Any]):
        """Analyze memory usage patterns"""
        memory_patterns = {
            'total_memory': 0,
            'available_memory': 0,
            'memory_usage_percent': 0,
            'suspicious_patterns': [],
            'memory_statistics': {}
        }
        
        try:
            # Get memory statistics
            mem = psutil.virtual_memory()
            memory_patterns['total_memory'] = mem.total
            memory_patterns['available_memory'] = mem.available
            memory_patterns['memory_usage_percent'] = mem.percent
            
            memory_patterns['memory_statistics'] = {
                'total_gb': round(mem.total / (1024**3), 2),
                'available_gb': round(mem.available / (1024**3), 2),
                'used_gb': round(mem.used / (1024**3), 2),
                'free_gb': round(mem.free / (1024**3), 2),
                'cached_gb': round(mem.cached / (1024**3), 2) if hasattr(mem, 'cached') else 0
            }
            
            # Check for suspicious memory patterns
            if mem.percent > 90:
                memory_patterns['suspicious_patterns'].append({
                    'pattern': 'high_memory_usage',
                    'description': f'Memory usage is {mem.percent}%',
                    'severity': 'medium'
                })
            
        except Exception as e:
            memory_patterns['error'] = str(e)
        
        results['memory_artifacts'] = memory_patterns
    
    async def _gather_system_info(self, results: Dict[str, Any]):
        """Gather system information"""
        system_info = {
            'os_info': {},
            'cpu_info': {},
            'boot_time': '',
            'users': [],
            'disk_usage': []
        }
        
        try:
            # OS information
            system_info['os_info'] = {
                'system': os.name,
                'platform': os.sys.platform,
                'version': os.sys.version
            }
            
            # CPU information
            system_info['cpu_info'] = {
                'physical_cores': psutil.cpu_count(logical=False),
                'logical_cores': psutil.cpu_count(logical=True),
                'cpu_usage': psutil.cpu_percent(interval=1)
            }
            
            # Boot time
            boot_time = datetime.fromtimestamp(psutil.boot_time())
            system_info['boot_time'] = boot_time.isoformat()
            
            # Users
            users = psutil.users()
            system_info['users'] = [
                {
                    'name': user.name,
                    'terminal': user.terminal,
                    'host': user.host,
                    'started': datetime.fromtimestamp(user.started).isoformat()
                }
                for user in users
            ]
            
            # Disk usage
            disk_usage = psutil.disk_usage('/')
            system_info['disk_usage'] = {
                'total_gb': round(disk_usage.total / (1024**3), 2),
                'used_gb': round(disk_usage.used / (1024**3), 2),
                'free_gb': round(disk_usage.free / (1024**3), 2),
                'percent': round((disk_usage.used / disk_usage.total) * 100, 2)
            }
            
        except Exception as e:
            system_info['error'] = str(e)
        
        results['system_information'] = system_info
    
    async def _analyze_memory_dump(self, dump_path: str, results: Dict[str, Any]):
        """Analyze memory dump using Volatility"""
        volatility_results = {}
        
        try:
            # Check if Volatility is available
            if not await self._check_volatility_available():
                results['security_findings'].append({
                    'type': 'tool_unavailable',
                    'description': 'Volatility framework not available for memory dump analysis',
                    'severity': 'info'
                })
                return
            
            # Run basic Volatility plugins
            basic_plugins = ['pslist', 'netscan', 'malfind']
            for plugin in basic_plugins:
                plugin_result = await self._run_volatility_plugin(dump_path, plugin)
                if plugin_result:
                    volatility_results[plugin] = plugin_result
            
            results['memory_dump_analysis'] = volatility_results
            
        except Exception as e:
            results['security_findings'].append({
                'type': 'memory_dump_error',
                'description': f'Error analyzing memory dump: {str(e)}',
                'severity': 'low'
            })
    
    async def _check_volatility_available(self) -> bool:
        """Check if Volatility framework is available"""
        try:
            process = await asyncio.create_subprocess_exec(
                'vol.py', '--help',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await asyncio.wait_for(process.communicate(), timeout=10)
            return process.returncode == 0
        except Exception:
            return False
    
    async def _run_volatility_plugin(self, dump_path: str, plugin: str) -> Optional[Dict[str, Any]]:
        """Run a specific Volatility plugin"""
        try:
            cmd = ['vol.py', '-f', dump_path, plugin]
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=120)
            
            if process.returncode == 0:
                return {
                    'plugin': plugin,
                    'output': stdout.decode('utf-8', errors='ignore'),
                    'error': stderr.decode('utf-8', errors='ignore'),
                    'success': True
                }
            else:
                return {
                    'plugin': plugin,
                    'output': '',
                    'error': stderr.decode('utf-8', errors='ignore'),
                    'success': False
                }
        except Exception as e:
            return {
                'plugin': plugin,
                'output': '',
                'error': str(e),
                'success': False
            }