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
Web application security scanner
"""

import asyncio
import aiohttp
import re
import urllib.parse
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
from bs4 import BeautifulSoup
import json
import base64
import hashlib
from .base_scanner import BaseScannerModule


class WebScanner(BaseScannerModule):
    """Web application security scanner"""
    
    def __init__(self, timeout: int = 30, max_concurrent: int = 10):
        super().__init__("web_scanner", timeout)
        self.max_concurrent = max_concurrent
        self.session = None
        self.discovered_urls = set()
        self.forms = []
        self.cookies = {}
        
        # Common vulnerability payloads
        self.sql_payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR 1=1 --",
            "' UNION SELECT NULL--",
            "' AND 1=1 --",
            "' AND 1=2 --",
            "admin'--",
            "admin'/*",
            "'; DROP TABLE users--"
        ]
        
        self.xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<script>alert(String.fromCharCode(88,83,83))</script>",
            "<iframe src=javascript:alert('XSS')></iframe>",
            "<body onload=alert('XSS')>",
            "<div onmouseover=alert('XSS')>test</div>"
        ]
        
        self.command_injection_payloads = [
            "; ls",
            "&& ls",
            "| ls",
            "; cat /etc/passwd",
            "&& cat /etc/passwd",
            "| cat /etc/passwd",
            "; whoami",
            "&& whoami",
            "| whoami"
        ]
        
        self.directory_traversal_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "../../../../etc/passwd",
            "..%2f..%2f..%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc%252fpasswd",
            "....//....//....//etc/passwd",
            "....\\\\....\\\\....\\\\etc\\\\passwd"
        ]
    
    async def scan(self, target: str, scan_type: str = 'comprehensive',
                   auth_cookies: Optional[Dict[str, str]] = None,
                   **kwargs) -> Dict[str, Any]:
        """
        Comprehensive web application security scan
        """
        self.log_scan_start(target)
        
        if not target.startswith(('http://', 'https://')):
            target = f"http://{target}"
        
        results = {
            'target': target,
            'scan_type': scan_type,
            'timestamp': datetime.now().isoformat(),
            'information_gathering': {},
            'vulnerability_scan': {},
            'sql_injection': {},
            'xss_vulnerabilities': {},
            'command_injection': {},
            'directory_traversal': {},
            'file_inclusion': {},
            'authentication_bypass': {},
            'session_management': {},
            'csrf_vulnerabilities': {},
            'security_headers': {},
            'ssl_analysis': {},
            'api_security': {},
            'vulnerabilities': [],
            'recommendations': []
        }
        
        try:
            # Create HTTP session with timeout
            connector = aiohttp.TCPConnector(limit=self.max_concurrent, ttl_dns_cache=300)
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            
            self.session = aiohttp.ClientSession(
                connector=connector,
                timeout=timeout,
                headers={'User-Agent': 'LinuxScan Web Scanner 1.0'}
            )
            
            if auth_cookies:
                self.cookies.update(auth_cookies)
            
            # Information gathering
            results['information_gathering'] = await self._information_gathering(target)
            
            # Security headers analysis
            results['security_headers'] = await self._analyze_security_headers(target)
            
            # SSL/TLS analysis
            if target.startswith('https://'):
                results['ssl_analysis'] = await self._analyze_ssl_configuration(target)
            
            if scan_type in ['comprehensive', 'vulnerability']:
                # Vulnerability scanning
                results['vulnerability_scan'] = await self._general_vulnerability_scan(target)
                
                # SQL injection testing
                results['sql_injection'] = await self._test_sql_injection(target)
                
                # XSS testing
                results['xss_vulnerabilities'] = await self._test_xss_vulnerabilities(target)
                
                # Command injection testing
                results['command_injection'] = await self._test_command_injection(target)
                
                # Directory traversal testing
                results['directory_traversal'] = await self._test_directory_traversal(target)
                
                # File inclusion testing
                results['file_inclusion'] = await self._test_file_inclusion(target)
                
                # Authentication bypass testing
                results['authentication_bypass'] = await self._test_authentication_bypass(target)
                
                # Session management testing
                results['session_management'] = await self._test_session_management(target)
                
                # CSRF testing
                results['csrf_vulnerabilities'] = await self._test_csrf_vulnerabilities(target)
                
                # API security testing
                results['api_security'] = await self._test_api_security(target)
            
            # Compile all vulnerabilities
            results['vulnerabilities'] = self._compile_vulnerabilities(results)
            
            # Generate recommendations
            results['recommendations'] = self._generate_recommendations(results)
            
        except Exception as e:
            self.logger.error(f"Error during web scan of {target}: {str(e)}")
            results['error'] = str(e)
        
        finally:
            if self.session:
                await self.session.close()
        
        self.log_scan_end(target)
        return results
    
    async def _information_gathering(self, target: str) -> Dict[str, Any]:
        """Information gathering phase"""
        info = {
            'server_info': {},
            'technology_stack': {},
            'directory_structure': {},
            'robots_txt': {},
            'sitemap': {},
            'hidden_directories': [],
            'backup_files': [],
            'version_disclosure': []
        }
        
        try:
            # Get server information
            async with self.session.get(target) as response:
                headers = dict(response.headers)
                info['server_info'] = {
                    'status_code': response.status,
                    'server': headers.get('Server', 'Unknown'),
                    'powered_by': headers.get('X-Powered-By', 'Unknown'),
                    'content_type': headers.get('Content-Type', 'Unknown'),
                    'content_length': headers.get('Content-Length', 'Unknown')
                }
                
                # Technology stack detection
                content = await response.text()
                info['technology_stack'] = self._detect_technologies(content, headers)
                
                # Version disclosure detection
                info['version_disclosure'] = self._detect_version_disclosure(content, headers)
            
            # Check robots.txt
            robots_url = urllib.parse.urljoin(target, '/robots.txt')
            info['robots_txt'] = await self._check_robots_txt(robots_url)
            
            # Check sitemap
            sitemap_url = urllib.parse.urljoin(target, '/sitemap.xml')
            info['sitemap'] = await self._check_sitemap(sitemap_url)
            
            # Directory enumeration
            info['directory_structure'] = await self._enumerate_directories(target)
            
            # Hidden directory discovery
            info['hidden_directories'] = await self._discover_hidden_directories(target)
            
            # Backup file discovery
            info['backup_files'] = await self._discover_backup_files(target)
            
        except Exception as e:
            info['error'] = str(e)
        
        return info
    
    async def _analyze_security_headers(self, target: str) -> Dict[str, Any]:
        """Analyze HTTP security headers"""
        headers_analysis = {
            'present_headers': {},
            'missing_headers': [],
            'weak_headers': [],
            'security_score': 0
        }
        
        try:
            async with self.session.get(target) as response:
                headers = dict(response.headers)
                
                # Check for security headers
                security_headers = {
                    'X-Content-Type-Options': 'nosniff',
                    'X-Frame-Options': ['DENY', 'SAMEORIGIN'],
                    'X-XSS-Protection': '1; mode=block',
                    'Strict-Transport-Security': None,
                    'Content-Security-Policy': None,
                    'Referrer-Policy': None,
                    'Feature-Policy': None,
                    'X-Permitted-Cross-Domain-Policies': 'none'
                }
                
                score = 0
                max_score = len(security_headers)
                
                for header, expected_value in security_headers.items():
                    if header in headers:
                        headers_analysis['present_headers'][header] = headers[header]
                        
                        # Check if header value is secure
                        if expected_value:
                            if isinstance(expected_value, list):
                                if any(val in headers[header] for val in expected_value):
                                    score += 1
                                else:
                                    headers_analysis['weak_headers'].append(header)
                            else:
                                if expected_value in headers[header]:
                                    score += 1
                                else:
                                    headers_analysis['weak_headers'].append(header)
                        else:
                            score += 1
                    else:
                        headers_analysis['missing_headers'].append(header)
                
                headers_analysis['security_score'] = int((score / max_score) * 100)
                
        except Exception as e:
            headers_analysis['error'] = str(e)
        
        return headers_analysis
    
    async def _analyze_ssl_configuration(self, target: str) -> Dict[str, Any]:
        """Analyze SSL/TLS configuration"""
        ssl_analysis = {
            'certificate_info': {},
            'cipher_suites': [],
            'protocol_versions': [],
            'vulnerabilities': []
        }
        
        try:
            # This would require more detailed SSL analysis
            # For now, basic certificate check
            async with self.session.get(target) as response:
                if response.url.scheme == 'https':
                    ssl_analysis['certificate_info']['valid'] = True
                    ssl_analysis['certificate_info']['scheme'] = 'https'
                else:
                    ssl_analysis['vulnerabilities'].append('No SSL/TLS encryption')
                    
        except Exception as e:
            ssl_analysis['error'] = str(e)
        
        return ssl_analysis
    
    async def _general_vulnerability_scan(self, target: str) -> Dict[str, Any]:
        """General vulnerability scanning"""
        vulns = {
            'information_disclosure': [],
            'error_pages': [],
            'debug_information': [],
            'admin_interfaces': [],
            'default_files': []
        }
        
        try:
            # Check for common vulnerable pages
            vulnerable_pages = [
                '/admin', '/admin.php', '/administrator',
                '/test', '/test.php', '/debug',
                '/info.php', '/phpinfo.php',
                '/config', '/config.php',
                '/backup', '/backup.php',
                '/install', '/install.php',
                '/setup', '/setup.php'
            ]
            
            semaphore = asyncio.Semaphore(self.max_concurrent)
            
            async def check_page(page):
                async with semaphore:
                    try:
                        url = urllib.parse.urljoin(target, page)
                        async with self.session.get(url) as response:
                            if response.status == 200:
                                content = await response.text()
                                if any(keyword in content.lower() for keyword in ['admin', 'login', 'password']):
                                    return {'page': page, 'status': response.status, 'type': 'admin_interface'}
                                elif 'php' in content.lower() and 'version' in content.lower():
                                    return {'page': page, 'status': response.status, 'type': 'debug_information'}
                                else:
                                    return {'page': page, 'status': response.status, 'type': 'default_files'}
                    except:
                        pass
                    return None
            
            tasks = [check_page(page) for page in vulnerable_pages]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in results:
                if result and not isinstance(result, Exception):
                    vulns[result['type']].append(result)
                    
        except Exception as e:
            vulns['error'] = str(e)
        
        return vulns
    
    async def _test_sql_injection(self, target: str) -> Dict[str, Any]:
        """Test for SQL injection vulnerabilities"""
        sql_results = {
            'vulnerable_parameters': [],
            'injection_points': [],
            'database_info': {},
            'severity': 'None'
        }
        
        try:
            # Find forms and parameters
            forms = await self._discover_forms(target)
            
            for form in forms:
                form_action = form.get('action', '')
                form_method = form.get('method', 'GET').upper()
                
                if form_action:
                    form_url = urllib.parse.urljoin(target, form_action)
                    
                    # Test each input field
                    for input_field in form.get('inputs', []):
                        field_name = input_field.get('name', '')
                        if field_name:
                            vulnerabilities = await self._test_sql_injection_parameter(
                                form_url, field_name, form_method
                            )
                            if vulnerabilities:
                                sql_results['vulnerable_parameters'].extend(vulnerabilities)
                                sql_results['severity'] = 'High'
            
            # Test URL parameters
            parsed_url = urllib.parse.urlparse(target)
            if parsed_url.query:
                params = urllib.parse.parse_qs(parsed_url.query)
                for param in params:
                    vulnerabilities = await self._test_sql_injection_parameter(
                        target, param, 'GET'
                    )
                    if vulnerabilities:
                        sql_results['vulnerable_parameters'].extend(vulnerabilities)
                        sql_results['severity'] = 'High'
                        
        except Exception as e:
            sql_results['error'] = str(e)
        
        return sql_results
    
    async def _test_sql_injection_parameter(self, url: str, param: str, method: str) -> List[Dict[str, Any]]:
        """Test a specific parameter for SQL injection"""
        vulnerabilities = []
        
        for payload in self.sql_payloads:
            try:
                if method == 'GET':
                    # Test GET parameter
                    test_url = f"{url}?{param}={urllib.parse.quote(payload)}"
                    async with self.session.get(test_url) as response:
                        content = await response.text()
                        if self._detect_sql_error(content):
                            vulnerabilities.append({
                                'url': url,
                                'parameter': param,
                                'payload': payload,
                                'method': method,
                                'response_status': response.status
                            })
                else:
                    # Test POST parameter
                    data = {param: payload}
                    async with self.session.post(url, data=data) as response:
                        content = await response.text()
                        if self._detect_sql_error(content):
                            vulnerabilities.append({
                                'url': url,
                                'parameter': param,
                                'payload': payload,
                                'method': method,
                                'response_status': response.status
                            })
            except:
                continue
        
        return vulnerabilities
    
    async def _test_xss_vulnerabilities(self, target: str) -> Dict[str, Any]:
        """Test for XSS vulnerabilities"""
        xss_results = {
            'reflected_xss': [],
            'stored_xss': [],
            'dom_xss': [],
            'severity': 'None'
        }
        
        try:
            # Find forms and parameters
            forms = await self._discover_forms(target)
            
            for form in forms:
                form_action = form.get('action', '')
                form_method = form.get('method', 'GET').upper()
                
                if form_action:
                    form_url = urllib.parse.urljoin(target, form_action)
                    
                    # Test each input field
                    for input_field in form.get('inputs', []):
                        field_name = input_field.get('name', '')
                        if field_name:
                            vulnerabilities = await self._test_xss_parameter(
                                form_url, field_name, form_method
                            )
                            if vulnerabilities:
                                xss_results['reflected_xss'].extend(vulnerabilities)
                                xss_results['severity'] = 'High'
                                
        except Exception as e:
            xss_results['error'] = str(e)
        
        return xss_results
    
    async def _test_xss_parameter(self, url: str, param: str, method: str) -> List[Dict[str, Any]]:
        """Test a specific parameter for XSS"""
        vulnerabilities = []
        
        for payload in self.xss_payloads:
            try:
                if method == 'GET':
                    # Test GET parameter
                    test_url = f"{url}?{param}={urllib.parse.quote(payload)}"
                    async with self.session.get(test_url) as response:
                        content = await response.text()
                        if payload in content:
                            vulnerabilities.append({
                                'url': url,
                                'parameter': param,
                                'payload': payload,
                                'method': method,
                                'type': 'reflected'
                            })
                else:
                    # Test POST parameter
                    data = {param: payload}
                    async with self.session.post(url, data=data) as response:
                        content = await response.text()
                        if payload in content:
                            vulnerabilities.append({
                                'url': url,
                                'parameter': param,
                                'payload': payload,
                                'method': method,
                                'type': 'reflected'
                            })
            except:
                continue
        
        return vulnerabilities
    
    async def _test_command_injection(self, target: str) -> Dict[str, Any]:
        """Test for command injection vulnerabilities"""
        cmd_results = {
            'vulnerable_parameters': [],
            'injection_points': [],
            'severity': 'None'
        }
        
        try:
            # Find forms and parameters
            forms = await self._discover_forms(target)
            
            for form in forms:
                form_action = form.get('action', '')
                form_method = form.get('method', 'GET').upper()
                
                if form_action:
                    form_url = urllib.parse.urljoin(target, form_action)
                    
                    # Test each input field
                    for input_field in form.get('inputs', []):
                        field_name = input_field.get('name', '')
                        if field_name:
                            vulnerabilities = await self._test_command_injection_parameter(
                                form_url, field_name, form_method
                            )
                            if vulnerabilities:
                                cmd_results['vulnerable_parameters'].extend(vulnerabilities)
                                cmd_results['severity'] = 'Critical'
                                
        except Exception as e:
            cmd_results['error'] = str(e)
        
        return cmd_results
    
    async def _test_command_injection_parameter(self, url: str, param: str, method: str) -> List[Dict[str, Any]]:
        """Test a specific parameter for command injection"""
        vulnerabilities = []
        
        for payload in self.command_injection_payloads:
            try:
                if method == 'GET':
                    # Test GET parameter
                    test_url = f"{url}?{param}={urllib.parse.quote(payload)}"
                    async with self.session.get(test_url) as response:
                        content = await response.text()
                        if self._detect_command_execution(content):
                            vulnerabilities.append({
                                'url': url,
                                'parameter': param,
                                'payload': payload,
                                'method': method
                            })
                else:
                    # Test POST parameter
                    data = {param: payload}
                    async with self.session.post(url, data=data) as response:
                        content = await response.text()
                        if self._detect_command_execution(content):
                            vulnerabilities.append({
                                'url': url,
                                'parameter': param,
                                'payload': payload,
                                'method': method
                            })
            except:
                continue
        
        return vulnerabilities
    
    async def _test_directory_traversal(self, target: str) -> Dict[str, Any]:
        """Test for directory traversal vulnerabilities"""
        traversal_results = {
            'vulnerable_parameters': [],
            'accessible_files': [],
            'severity': 'None'
        }
        
        try:
            # Find forms and parameters
            forms = await self._discover_forms(target)
            
            for form in forms:
                form_action = form.get('action', '')
                form_method = form.get('method', 'GET').upper()
                
                if form_action:
                    form_url = urllib.parse.urljoin(target, form_action)
                    
                    # Test each input field
                    for input_field in form.get('inputs', []):
                        field_name = input_field.get('name', '')
                        if field_name:
                            vulnerabilities = await self._test_directory_traversal_parameter(
                                form_url, field_name, form_method
                            )
                            if vulnerabilities:
                                traversal_results['vulnerable_parameters'].extend(vulnerabilities)
                                traversal_results['severity'] = 'High'
                                
        except Exception as e:
            traversal_results['error'] = str(e)
        
        return traversal_results
    
    async def _test_directory_traversal_parameter(self, url: str, param: str, method: str) -> List[Dict[str, Any]]:
        """Test a specific parameter for directory traversal"""
        vulnerabilities = []
        
        for payload in self.directory_traversal_payloads:
            try:
                if method == 'GET':
                    # Test GET parameter
                    test_url = f"{url}?{param}={urllib.parse.quote(payload)}"
                    async with self.session.get(test_url) as response:
                        content = await response.text()
                        if self._detect_file_disclosure(content):
                            vulnerabilities.append({
                                'url': url,
                                'parameter': param,
                                'payload': payload,
                                'method': method
                            })
                else:
                    # Test POST parameter
                    data = {param: payload}
                    async with self.session.post(url, data=data) as response:
                        content = await response.text()
                        if self._detect_file_disclosure(content):
                            vulnerabilities.append({
                                'url': url,
                                'parameter': param,
                                'payload': payload,
                                'method': method
                            })
            except:
                continue
        
        return vulnerabilities
    
    async def _discover_forms(self, target: str) -> List[Dict[str, Any]]:
        """Discover forms on the target website"""
        forms = []
        
        try:
            async with self.session.get(target) as response:
                content = await response.text()
                soup = BeautifulSoup(content, 'html.parser')
                
                for form in soup.find_all('form'):
                    form_info = {
                        'action': form.get('action', ''),
                        'method': form.get('method', 'GET'),
                        'inputs': []
                    }
                    
                    for input_field in form.find_all('input'):
                        input_info = {
                            'name': input_field.get('name', ''),
                            'type': input_field.get('type', 'text'),
                            'value': input_field.get('value', '')
                        }
                        form_info['inputs'].append(input_info)
                    
                    forms.append(form_info)
                    
        except Exception as e:
            self.logger.debug(f"Form discovery failed: {str(e)}")
        
        return forms
    
    def _detect_sql_error(self, content: str) -> bool:
        """Detect SQL error messages in response"""
        sql_errors = [
            'mysql_fetch_array',
            'mysql_fetch_assoc',
            'mysql_fetch_row',
            'mysql_num_rows',
            'mysql_result',
            'mysql_select_db',
            'mysql_query',
            'ORA-[0-9]+',
            'Microsoft OLE DB Provider',
            'ODBC Microsoft Access Driver',
            'ODBC SQL Server Driver',
            'SQLServer JDBC Driver',
            'PostgreSQL query failed',
            'Warning: pg_',
            'valid PostgreSQL result',
            'Npgsql\\.'
        ]
        
        content_lower = content.lower()
        for error in sql_errors:
            if error.lower() in content_lower:
                return True
        
        return False
    
    def _detect_command_execution(self, content: str) -> bool:
        """Detect command execution in response"""
        command_indicators = [
            'uid=',
            'gid=',
            'groups=',
            'root:',
            'bin:',
            'daemon:',
            'adm:',
            'lp:',
            'sync:',
            'shutdown:',
            'halt:',
            'mail:',
            'news:',
            'uucp:',
            'operator:',
            'games:',
            'gopher:',
            'ftp:',
            'nobody:',
            'systemd-network:',
            'dbus:',
            'polkitd:'
        ]
        
        for indicator in command_indicators:
            if indicator in content:
                return True
        
        return False
    
    def _detect_file_disclosure(self, content: str) -> bool:
        """Detect file disclosure in response"""
        file_indicators = [
            'root:x:0:0:root:/root:/bin/bash',
            'daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin',
            'bin:x:2:2:bin:/bin:/usr/sbin/nologin',
            'sys:x:3:3:sys:/dev:/usr/sbin/nologin',
            'sync:x:4:65534:sync:/bin:/bin/sync',
            'games:x:5:60:games:/usr/games:/usr/sbin/nologin',
            'man:x:6:12:man:/var/cache/man:/usr/sbin/nologin',
            'lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin',
            'mail:x:8:8:mail:/var/mail:/usr/sbin/nologin',
            'news:x:9:9:news:/var/spool/news:/usr/sbin/nologin',
            'uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin',
            'proxy:x:13:13:proxy:/bin:/usr/sbin/nologin',
            'www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin',
            'backup:x:34:34:backup:/var/backups:/usr/sbin/nologin',
            'list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin',
            'irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin',
            'gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin',
            'nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin',
            'systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin',
            'systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin',
            'syslog:x:102:106::/home/syslog:/usr/sbin/nologin',
            'messagebus:x:103:107::/nonexistent:/usr/sbin/nologin',
            '_apt:x:104:65534::/nonexistent:/usr/sbin/nologin',
            'lxd:x:105:65534::/var/lib/lxd/:/bin/false',
            'uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin',
            'dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin',
            'landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin',
            'pollinate:x:109:1::/var/cache/pollinate:/bin/false',
            'sshd:x:110:65534::/run/sshd:/usr/sbin/nologin',
            'mysql:x:111:114:MySQL Server,,,:/nonexistent:/bin/false',
            'apache:x:112:115:Apache Web Server,,,:/var/www:/usr/sbin/nologin',
            'nginx:x:113:116:nginx user,,,:/var/cache/nginx:/usr/sbin/nologin',
            'redis:x:114:117::/var/lib/redis:/usr/sbin/nologin',
            'postgres:x:115:118:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash',
            'memcache:x:116:119:Memcached,,,:/nonexistent:/usr/sbin/nologin'
        ]
        
        for indicator in file_indicators:
            if indicator in content:
                return True
        
        return False
    
    def _detect_technologies(self, content: str, headers: Dict[str, str]) -> Dict[str, Any]:
        """Detect web technologies"""
        technologies = {
            'web_server': headers.get('Server', 'Unknown'),
            'programming_language': 'Unknown',
            'framework': 'Unknown',
            'cms': 'Unknown',
            'database': 'Unknown',
            'javascript_libraries': []
        }
        
        content_lower = content.lower()
        
        # Detect programming languages
        if 'php' in content_lower or '.php' in content_lower:
            technologies['programming_language'] = 'PHP'
        elif 'asp.net' in content_lower or 'aspx' in content_lower:
            technologies['programming_language'] = 'ASP.NET'
        elif 'jsp' in content_lower or 'java' in content_lower:
            technologies['programming_language'] = 'Java'
        elif 'python' in content_lower or 'django' in content_lower:
            technologies['programming_language'] = 'Python'
        elif 'ruby' in content_lower or 'rails' in content_lower:
            technologies['programming_language'] = 'Ruby'
        
        # Detect frameworks
        if 'wordpress' in content_lower or 'wp-content' in content_lower:
            technologies['cms'] = 'WordPress'
        elif 'joomla' in content_lower:
            technologies['cms'] = 'Joomla'
        elif 'drupal' in content_lower:
            technologies['cms'] = 'Drupal'
        elif 'django' in content_lower:
            technologies['framework'] = 'Django'
        elif 'laravel' in content_lower:
            technologies['framework'] = 'Laravel'
        elif 'codeigniter' in content_lower:
            technologies['framework'] = 'CodeIgniter'
        
        # Detect JavaScript libraries
        js_libraries = ['jquery', 'angular', 'react', 'vue', 'bootstrap', 'foundation']
        for lib in js_libraries:
            if lib in content_lower:
                technologies['javascript_libraries'].append(lib)
        
        return technologies
    
    def _detect_version_disclosure(self, content: str, headers: Dict[str, str]) -> List[str]:
        """Detect version disclosures"""
        versions = []
        
        # Check headers for version information
        for header, value in headers.items():
            if any(keyword in header.lower() for keyword in ['version', 'powered', 'server']):
                versions.append(f"Header {header}: {value}")
        
        # Check content for version patterns
        version_patterns = [
            r'version[\s:]+([0-9]+\.[0-9]+\.[0-9]+)',
            r'v[\s]*([0-9]+\.[0-9]+\.[0-9]+)',
            r'([0-9]+\.[0-9]+\.[0-9]+)'
        ]
        
        for pattern in version_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                versions.append(f"Version disclosure: {match}")
        
        return versions
    
    # Placeholder methods for additional functionality
    async def _check_robots_txt(self, url: str) -> Dict[str, Any]:
        """Check robots.txt file"""
        robots_info = {'exists': False, 'content': '', 'disallowed_paths': []}
        
        try:
            async with self.session.get(url) as response:
                if response.status == 200:
                    content = await response.text()
                    robots_info['exists'] = True
                    robots_info['content'] = content
                    
                    # Parse disallowed paths
                    for line in content.split('\n'):
                        if line.strip().lower().startswith('disallow:'):
                            path = line.split(':', 1)[1].strip()
                            if path:
                                robots_info['disallowed_paths'].append(path)
        except:
            pass
        
        return robots_info
    
    async def _check_sitemap(self, url: str) -> Dict[str, Any]:
        """Check sitemap.xml file"""
        sitemap_info = {'exists': False, 'urls': []}
        
        try:
            async with self.session.get(url) as response:
                if response.status == 200:
                    content = await response.text()
                    sitemap_info['exists'] = True
                    
                    # Parse URLs from sitemap
                    urls = re.findall(r'<loc>(.*?)</loc>', content)
                    sitemap_info['urls'] = urls
        except:
            pass
        
        return sitemap_info
    
    async def _enumerate_directories(self, target: str) -> Dict[str, Any]:
        """Enumerate directories"""
        return {'status': 'not_implemented'}
    
    async def _discover_hidden_directories(self, target: str) -> List[str]:
        """Discover hidden directories"""
        return []
    
    async def _discover_backup_files(self, target: str) -> List[str]:
        """Discover backup files"""
        return []
    
    async def _test_file_inclusion(self, target: str) -> Dict[str, Any]:
        """Test for file inclusion vulnerabilities"""
        return {'status': 'not_implemented'}
    
    async def _test_authentication_bypass(self, target: str) -> Dict[str, Any]:
        """Test for authentication bypass"""
        return {'status': 'not_implemented'}
    
    async def _test_session_management(self, target: str) -> Dict[str, Any]:
        """Test session management"""
        return {'status': 'not_implemented'}
    
    async def _test_csrf_vulnerabilities(self, target: str) -> Dict[str, Any]:
        """Test for CSRF vulnerabilities"""
        return {'status': 'not_implemented'}
    
    async def _test_api_security(self, target: str) -> Dict[str, Any]:
        """Test API security"""
        return {'status': 'not_implemented'}
    
    def _compile_vulnerabilities(self, results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Compile all vulnerabilities"""
        vulnerabilities = []
        
        # SQL Injection
        if results['sql_injection']['vulnerable_parameters']:
            for vuln in results['sql_injection']['vulnerable_parameters']:
                vulnerabilities.append({
                    'type': 'SQL Injection',
                    'severity': 'High',
                    'description': f"SQL injection vulnerability in parameter '{vuln['parameter']}'",
                    'url': vuln['url'],
                    'parameter': vuln['parameter'],
                    'payload': vuln['payload']
                })
        
        # XSS
        if results['xss_vulnerabilities']['reflected_xss']:
            for vuln in results['xss_vulnerabilities']['reflected_xss']:
                vulnerabilities.append({
                    'type': 'Cross-Site Scripting (XSS)',
                    'severity': 'High',
                    'description': f"XSS vulnerability in parameter '{vuln['parameter']}'",
                    'url': vuln['url'],
                    'parameter': vuln['parameter'],
                    'payload': vuln['payload']
                })
        
        # Command Injection
        if results['command_injection']['vulnerable_parameters']:
            for vuln in results['command_injection']['vulnerable_parameters']:
                vulnerabilities.append({
                    'type': 'Command Injection',
                    'severity': 'Critical',
                    'description': f"Command injection vulnerability in parameter '{vuln['parameter']}'",
                    'url': vuln['url'],
                    'parameter': vuln['parameter'],
                    'payload': vuln['payload']
                })
        
        # Directory Traversal
        if results['directory_traversal']['vulnerable_parameters']:
            for vuln in results['directory_traversal']['vulnerable_parameters']:
                vulnerabilities.append({
                    'type': 'Directory Traversal',
                    'severity': 'High',
                    'description': f"Directory traversal vulnerability in parameter '{vuln['parameter']}'",
                    'url': vuln['url'],
                    'parameter': vuln['parameter'],
                    'payload': vuln['payload']
                })
        
        # Security Headers
        if results['security_headers']['missing_headers']:
            for header in results['security_headers']['missing_headers']:
                vulnerabilities.append({
                    'type': 'Missing Security Header',
                    'severity': 'Medium',
                    'description': f"Missing security header: {header}",
                    'recommendation': f"Add {header} header to improve security"
                })
        
        return vulnerabilities
    
    def _generate_recommendations(self, results: Dict[str, Any]) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        if results['vulnerabilities']:
            recommendations.append("Address all identified vulnerabilities immediately")
        
        if results['security_headers']['missing_headers']:
            recommendations.append("Implement missing security headers")
        
        if results['information_gathering']['version_disclosure']:
            recommendations.append("Remove version disclosure from headers and content")
        
        recommendations.extend([
            "Implement proper input validation and sanitization",
            "Use parameterized queries to prevent SQL injection",
            "Implement proper authentication and authorization",
            "Use HTTPS for all communications",
            "Regular security testing and code reviews",
            "Keep all software and frameworks updated"
        ])
        
        return recommendations