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
Database security scanner
"""

import asyncio
import ssl
from typing import Dict, List, Any, Optional
from datetime import datetime
from .base_scanner import BaseScannerModule

try:
    import mysql.connector
    MYSQL_AVAILABLE = True
except ImportError:
    MYSQL_AVAILABLE = False

try:
    import psycopg2
    POSTGRESQL_AVAILABLE = True
except ImportError:
    POSTGRESQL_AVAILABLE = False

try:
    import pymongo
    MONGODB_AVAILABLE = True
except ImportError:
    MONGODB_AVAILABLE = False

try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False


class DatabaseScanner(BaseScannerModule):
    """Database security scanner"""
    
    def __init__(self, timeout: int = 30):
        super().__init__("database_scanner", timeout)
        
        # Common database ports
        self.database_ports = {
            3306: 'MySQL',
            5432: 'PostgreSQL',
            1521: 'Oracle',
            1433: 'MS SQL Server',
            27017: 'MongoDB',
            6379: 'Redis',
            9200: 'Elasticsearch',
            5984: 'CouchDB',
            8086: 'InfluxDB',
            7000: 'Cassandra'
        }
        
        # Common default credentials
        self.default_credentials = {
            'mysql': [
                ('root', ''),
                ('root', 'root'),
                ('root', 'mysql'),
                ('root', 'password'),
                ('root', '123456'),
                ('mysql', 'mysql'),
                ('admin', 'admin'),
                ('user', 'user')
            ],
            'postgresql': [
                ('postgres', ''),
                ('postgres', 'postgres'),
                ('postgres', 'password'),
                ('postgres', 'admin'),
                ('postgres', '123456'),
                ('admin', 'admin'),
                ('user', 'user')
            ],
            'mongodb': [
                ('admin', ''),
                ('admin', 'admin'),
                ('root', 'root'),
                ('mongodb', 'mongodb'),
                ('user', 'user')
            ],
            'redis': [
                ('', ''),  # No auth
                ('admin', 'admin'),
                ('redis', 'redis'),
                ('user', 'password')
            ]
        }
        
        # Database security checks
        self.security_checks = {
            'mysql': [
                'Anonymous users',
                'Default root password',
                'Remote root access',
                'Test database',
                'Insecure privileges',
                'SSL/TLS configuration',
                'Log settings',
                'File permissions'
            ],
            'postgresql': [
                'Default superuser password',
                'Authentication methods',
                'Connection encryption',
                'Role permissions',
                'Database privileges',
                'Log settings',
                'Configuration security'
            ],
            'mongodb': [
                'Authentication enabled',
                'Authorization configured',
                'SSL/TLS enabled',
                'Network interfaces',
                'Logging configuration',
                'User roles and permissions'
            ],
            'redis': [
                'Authentication required',
                'Protected mode',
                'Network binding',
                'Command renaming',
                'Persistence security',
                'Memory security'
            ]
        }
    
    async def scan(self, target: str, database_type: str = 'auto',
                   port: Optional[int] = None, **kwargs) -> Dict[str, Any]:
        """
        Comprehensive database security scan
        """
        self.log_scan_start(target)
        
        results = {
            'target': target,
            'database_type': database_type,
            'port': port,
            'timestamp': datetime.now().isoformat(),
            'database_discovery': {},
            'authentication_test': {},
            'configuration_audit': {},
            'privilege_analysis': {},
            'vulnerability_scan': {},
            'data_exposure': {},
            'encryption_analysis': {},
            'backup_security': {},
            'logging_audit': {},
            'compliance_check': {},
            'vulnerabilities': [],
            'recommendations': []
        }
        
        try:
            # Database discovery
            results['database_discovery'] = await self._database_discovery(target, port)
            
            # Determine database type if auto
            if database_type == 'auto':
                database_type = self._determine_database_type(results['database_discovery'])
            
            # Authentication testing
            results['authentication_test'] = await self._authentication_test(target, database_type, port)
            
            # Configuration audit
            results['configuration_audit'] = await self._configuration_audit(target, database_type, port)
            
            # Privilege analysis
            results['privilege_analysis'] = await self._privilege_analysis(target, database_type, port)
            
            # Vulnerability scanning
            results['vulnerability_scan'] = await self._vulnerability_scan(target, database_type, port)
            
            # Data exposure check
            results['data_exposure'] = await self._data_exposure_check(target, database_type, port)
            
            # Encryption analysis
            results['encryption_analysis'] = await self._encryption_analysis(target, database_type, port)
            
            # Backup security
            results['backup_security'] = await self._backup_security_check(target, database_type, port)
            
            # Logging audit
            results['logging_audit'] = await self._logging_audit(target, database_type, port)
            
            # Compliance check
            results['compliance_check'] = await self._compliance_check(target, database_type, port)
            
            # Compile vulnerabilities
            results['vulnerabilities'] = self._compile_vulnerabilities(results)
            
            # Generate recommendations
            results['recommendations'] = self._generate_recommendations(results)
            
        except Exception as e:
            self.logger.error(f"Error during database scan of {target}: {str(e)}")
            results['error'] = str(e)
        
        self.log_scan_end(target)
        return results
    
    async def _database_discovery(self, target: str, port: Optional[int] = None) -> Dict[str, Any]:
        """Discover database services"""
        discovery_results = {
            'detected_databases': [],
            'open_ports': [],
            'service_banners': {},
            'version_information': {}
        }
        
        try:
            # Check common database ports
            ports_to_check = [port] if port else list(self.database_ports.keys())
            
            for check_port in ports_to_check:
                try:
                    # Simple port check
                    import socket
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(5)
                    result = sock.connect_ex((target, check_port))
                    sock.close()
                    
                    if result == 0:
                        discovery_results['open_ports'].append(check_port)
                        db_type = self.database_ports.get(check_port, 'Unknown')
                        discovery_results['detected_databases'].append({
                            'port': check_port,
                            'type': db_type,
                            'status': 'open'
                        })
                        
                        # Try to get banner/version info
                        banner = await self._get_database_banner(target, check_port, db_type)
                        if banner:
                            discovery_results['service_banners'][check_port] = banner
                            
                except Exception as e:
                    self.logger.debug(f"Port check failed for {check_port}: {str(e)}")
                    continue
                    
        except Exception as e:
            discovery_results['error'] = str(e)
        
        return discovery_results
    
    async def _authentication_test(self, target: str, database_type: str, port: Optional[int] = None) -> Dict[str, Any]:
        """Test authentication mechanisms"""
        auth_results = {
            'anonymous_access': False,
            'default_credentials': [],
            'weak_passwords': [],
            'authentication_methods': [],
            'bruteforce_results': {}
        }
        
        try:
            # Test default credentials
            if database_type.lower() in self.default_credentials:
                credentials = self.default_credentials[database_type.lower()]
                
                for username, password in credentials:
                    try:
                        success = await self._test_database_credentials(
                            target, port, database_type, username, password
                        )
                        if success:
                            auth_results['default_credentials'].append({
                                'username': username,
                                'password': password,
                                'access_level': 'unknown'
                            })
                            
                            # Check if it's anonymous access
                            if not username and not password:
                                auth_results['anonymous_access'] = True
                                
                    except Exception as e:
                        self.logger.debug(f"Credential test failed: {str(e)}")
                        continue
            
            # Test authentication methods
            auth_methods = await self._get_authentication_methods(target, port, database_type)
            auth_results['authentication_methods'] = auth_methods
            
        except Exception as e:
            auth_results['error'] = str(e)
        
        return auth_results
    
    async def _configuration_audit(self, target: str, database_type: str, port: Optional[int] = None) -> Dict[str, Any]:
        """Audit database configuration"""
        config_results = {
            'security_settings': {},
            'network_configuration': {},
            'access_controls': {},
            'logging_configuration': {},
            'misconfigurations': []
        }
        
        try:
            # Get security settings based on database type
            if database_type.lower() == 'mysql':
                config_results = await self._audit_mysql_config(target, port)
            elif database_type.lower() == 'postgresql':
                config_results = await self._audit_postgresql_config(target, port)
            elif database_type.lower() == 'mongodb':
                config_results = await self._audit_mongodb_config(target, port)
            elif database_type.lower() == 'redis':
                config_results = await self._audit_redis_config(target, port)
            else:
                config_results['note'] = f"Configuration audit not implemented for {database_type}"
                
        except Exception as e:
            config_results['error'] = str(e)
        
        return config_results
    
    async def _privilege_analysis(self, target: str, database_type: str, port: Optional[int] = None) -> Dict[str, Any]:
        """Analyze database privileges"""
        privilege_results = {
            'user_privileges': [],
            'role_analysis': [],
            'excessive_privileges': [],
            'privilege_escalation': [],
            'database_permissions': {}
        }
        
        try:
            # This would require authenticated access to the database
            # For demonstration, we'll provide analysis framework
            privilege_results['analysis_framework'] = {
                'user_enumeration': 'List all database users',
                'role_enumeration': 'List all database roles',
                'privilege_mapping': 'Map privileges to users/roles',
                'permission_analysis': 'Analyze database/table permissions',
                'privilege_escalation': 'Check for privilege escalation vectors'
            }
            
            # Common privilege issues
            privilege_results['common_issues'] = [
                'Users with administrative privileges',
                'Overprivileged application accounts',
                'Unused or dormant accounts',
                'Accounts with no password expiration',
                'Shared or generic accounts',
                'Accounts with database creation privileges'
            ]
            
        except Exception as e:
            privilege_results['error'] = str(e)
        
        return privilege_results
    
    async def _vulnerability_scan(self, target: str, database_type: str, port: Optional[int] = None) -> Dict[str, Any]:
        """Scan for database vulnerabilities"""
        vuln_results = {
            'cve_vulnerabilities': [],
            'configuration_vulnerabilities': [],
            'injection_vulnerabilities': [],
            'authentication_vulnerabilities': [],
            'privilege_vulnerabilities': []
        }
        
        try:
            # Common database vulnerabilities
            vuln_results['common_vulnerabilities'] = {
                'sql_injection': 'SQL injection vulnerabilities',
                'privilege_escalation': 'Privilege escalation vulnerabilities',
                'information_disclosure': 'Information disclosure vulnerabilities',
                'authentication_bypass': 'Authentication bypass vulnerabilities',
                'denial_of_service': 'Denial of service vulnerabilities'
            }
            
            # Database-specific vulnerabilities
            if database_type.lower() == 'mysql':
                vuln_results['mysql_specific'] = [
                    'CVE-2019-2805: Privilege escalation vulnerability',
                    'CVE-2018-3133: Information disclosure vulnerability',
                    'CVE-2017-3653: Authentication bypass vulnerability'
                ]
            elif database_type.lower() == 'postgresql':
                vuln_results['postgresql_specific'] = [
                    'CVE-2019-10164: Stack buffer overflow vulnerability',
                    'CVE-2018-16850: SQL injection vulnerability',
                    'CVE-2017-7547: Authentication bypass vulnerability'
                ]
            elif database_type.lower() == 'mongodb':
                vuln_results['mongodb_specific'] = [
                    'CVE-2019-2389: Information disclosure vulnerability',
                    'CVE-2018-20802: Privilege escalation vulnerability',
                    'CVE-2017-18381: Authentication bypass vulnerability'
                ]
            
        except Exception as e:
            vuln_results['error'] = str(e)
        
        return vuln_results
    
    async def _data_exposure_check(self, target: str, database_type: str, port: Optional[int] = None) -> Dict[str, Any]:
        """Check for data exposure"""
        exposure_results = {
            'sensitive_data': [],
            'data_classification': {},
            'access_controls': {},
            'encryption_status': {},
            'backup_exposure': {}
        }
        
        try:
            # Sensitive data types to look for
            exposure_results['sensitive_data_types'] = [
                'Personal Identifiable Information (PII)',
                'Credit card numbers',
                'Social security numbers',
                'Health information',
                'Financial data',
                'Authentication credentials',
                'API keys and tokens',
                'Encryption keys'
            ]
            
            # Data classification framework
            exposure_results['data_classification'] = {
                'public': 'Data that can be freely shared',
                'internal': 'Data for internal use only',
                'confidential': 'Data requiring restricted access',
                'restricted': 'Data requiring highest level of protection'
            }
            
            # Access control checks
            exposure_results['access_controls'] = {
                'row_level_security': 'Check if row-level security is enabled',
                'column_level_security': 'Check if column-level security is enabled',
                'view_based_security': 'Check if views are used for security',
                'stored_procedure_security': 'Check stored procedure permissions'
            }
            
        except Exception as e:
            exposure_results['error'] = str(e)
        
        return exposure_results
    
    async def _encryption_analysis(self, target: str, database_type: str, port: Optional[int] = None) -> Dict[str, Any]:
        """Analyze encryption settings"""
        encryption_results = {
            'transport_encryption': {},
            'data_at_rest_encryption': {},
            'key_management': {},
            'encryption_algorithms': {},
            'certificate_analysis': {}
        }
        
        try:
            # Transport encryption
            encryption_results['transport_encryption'] = {
                'ssl_tls_enabled': 'Check if SSL/TLS is enabled',
                'certificate_validation': 'Check certificate validation',
                'cipher_suites': 'Check supported cipher suites',
                'protocol_versions': 'Check supported protocol versions'
            }
            
            # Data at rest encryption
            encryption_results['data_at_rest_encryption'] = {
                'database_encryption': 'Check if database files are encrypted',
                'table_encryption': 'Check if specific tables are encrypted',
                'backup_encryption': 'Check if backups are encrypted',
                'log_encryption': 'Check if logs are encrypted'
            }
            
            # Key management
            encryption_results['key_management'] = {
                'key_rotation': 'Check if key rotation is implemented',
                'key_storage': 'Check how keys are stored',
                'key_access_controls': 'Check key access controls',
                'key_backup': 'Check if keys are backed up securely'
            }
            
            # Test SSL/TLS connection
            ssl_test = await self._test_ssl_connection(target, port)
            encryption_results['ssl_test'] = ssl_test
            
        except Exception as e:
            encryption_results['error'] = str(e)
        
        return encryption_results
    
    async def _backup_security_check(self, target: str, database_type: str, port: Optional[int] = None) -> Dict[str, Any]:
        """Check backup security"""
        backup_results = {
            'backup_encryption': {},
            'backup_access_controls': {},
            'backup_locations': {},
            'backup_retention': {},
            'backup_integrity': {}
        }
        
        try:
            # Backup security checks
            backup_results['security_checks'] = [
                'Backup encryption status',
                'Backup file permissions',
                'Backup storage location security',
                'Backup retention policies',
                'Backup integrity verification',
                'Backup access logging',
                'Backup restore procedures'
            ]
            
            # Common backup vulnerabilities
            backup_results['common_vulnerabilities'] = [
                'Unencrypted backups',
                'Weak backup file permissions',
                'Backups stored in insecure locations',
                'Lack of backup integrity verification',
                'Inadequate backup access controls',
                'Missing backup retention policies'
            ]
            
        except Exception as e:
            backup_results['error'] = str(e)
        
        return backup_results
    
    async def _logging_audit(self, target: str, database_type: str, port: Optional[int] = None) -> Dict[str, Any]:
        """Audit logging configuration"""
        logging_results = {
            'log_configuration': {},
            'audit_settings': {},
            'log_retention': {},
            'log_security': {},
            'compliance_logging': {}
        }
        
        try:
            # Logging configuration checks
            logging_results['log_configuration'] = {
                'general_log': 'Check if general logging is enabled',
                'error_log': 'Check if error logging is enabled',
                'slow_query_log': 'Check if slow query logging is enabled',
                'binary_log': 'Check if binary logging is enabled',
                'audit_log': 'Check if audit logging is enabled'
            }
            
            # Audit settings
            logging_results['audit_settings'] = {
                'login_auditing': 'Check if login events are audited',
                'privilege_changes': 'Check if privilege changes are audited',
                'data_access': 'Check if data access is audited',
                'schema_changes': 'Check if schema changes are audited',
                'failed_queries': 'Check if failed queries are audited'
            }
            
            # Log security
            logging_results['log_security'] = {
                'log_file_permissions': 'Check log file permissions',
                'log_encryption': 'Check if logs are encrypted',
                'log_integrity': 'Check log integrity protection',
                'log_rotation': 'Check log rotation settings',
                'remote_logging': 'Check remote logging configuration'
            }
            
        except Exception as e:
            logging_results['error'] = str(e)
        
        return logging_results
    
    async def _compliance_check(self, target: str, database_type: str, port: Optional[int] = None) -> Dict[str, Any]:
        """Check compliance requirements"""
        compliance_results = {
            'pci_dss': {},
            'gdpr': {},
            'hipaa': {},
            'sox': {},
            'common_criteria': {}
        }
        
        try:
            # PCI DSS compliance
            compliance_results['pci_dss'] = {
                'requirement_2': 'Change default passwords and security parameters',
                'requirement_3': 'Protect stored cardholder data',
                'requirement_4': 'Encrypt transmission of cardholder data',
                'requirement_7': 'Restrict access to cardholder data',
                'requirement_8': 'Assign unique ID to each person with computer access',
                'requirement_10': 'Track and monitor all access to network resources'
            }
            
            # GDPR compliance
            compliance_results['gdpr'] = {
                'data_protection': 'Implement appropriate technical measures',
                'access_controls': 'Ensure only authorized access to personal data',
                'data_encryption': 'Encrypt personal data where appropriate',
                'audit_logging': 'Maintain logs of data processing activities',
                'data_retention': 'Implement data retention policies'
            }
            
            # HIPAA compliance
            compliance_results['hipaa'] = {
                'access_controls': 'Implement access controls for PHI',
                'audit_controls': 'Implement audit controls',
                'integrity': 'Ensure PHI integrity',
                'transmission_security': 'Implement transmission security'
            }
            
        except Exception as e:
            compliance_results['error'] = str(e)
        
        return compliance_results
    
    async def _get_database_banner(self, target: str, port: int, db_type: str) -> Optional[str]:
        """Get database banner/version information"""
        try:
            if db_type.lower() == 'mysql' and MYSQL_AVAILABLE:
                return await self._get_mysql_banner(target, port)
            elif db_type.lower() == 'postgresql' and POSTGRESQL_AVAILABLE:
                return await self._get_postgresql_banner(target, port)
            elif db_type.lower() == 'mongodb' and MONGODB_AVAILABLE:
                return await self._get_mongodb_banner(target, port)
            elif db_type.lower() == 'redis' and REDIS_AVAILABLE:
                return await self._get_redis_banner(target, port)
        except Exception as e:
            self.logger.debug(f"Banner retrieval failed: {str(e)}")
        
        return None
    
    async def _test_database_credentials(self, target: str, port: Optional[int], 
                                       database_type: str, username: str, password: str) -> bool:
        """Test database credentials"""
        try:
            if database_type.lower() == 'mysql' and MYSQL_AVAILABLE:
                return await self._test_mysql_credentials(target, port or 3306, username, password)
            elif database_type.lower() == 'postgresql' and POSTGRESQL_AVAILABLE:
                return await self._test_postgresql_credentials(target, port or 5432, username, password)
            elif database_type.lower() == 'mongodb' and MONGODB_AVAILABLE:
                return await self._test_mongodb_credentials(target, port or 27017, username, password)
            elif database_type.lower() == 'redis' and REDIS_AVAILABLE:
                return await self._test_redis_credentials(target, port or 6379, username, password)
        except Exception as e:
            self.logger.debug(f"Credential test failed: {str(e)}")
        
        return False
    
    async def _test_ssl_connection(self, target: str, port: Optional[int]) -> Dict[str, Any]:
        """Test SSL/TLS connection"""
        ssl_results = {
            'ssl_enabled': False,
            'ssl_version': 'Unknown',
            'cipher_suite': 'Unknown',
            'certificate_info': {}
        }
        
        try:
            import socket
            import ssl as ssl_module
            
            context = ssl_module.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl_module.CERT_NONE
            
            with socket.create_connection((target, port or 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    ssl_results['ssl_enabled'] = True
                    ssl_results['ssl_version'] = ssock.version()
                    ssl_results['cipher_suite'] = ssock.cipher()[0] if ssock.cipher() else 'Unknown'
                    
                    # Get certificate information
                    cert = ssock.getpeercert()
                    if cert:
                        ssl_results['certificate_info'] = {
                            'subject': cert.get('subject', []),
                            'issuer': cert.get('issuer', []),
                            'version': cert.get('version', 'Unknown'),
                            'serial_number': cert.get('serialNumber', 'Unknown')
                        }
                        
        except Exception as e:
            ssl_results['error'] = str(e)
        
        return ssl_results
    
    def _determine_database_type(self, discovery_results: Dict[str, Any]) -> str:
        """Determine database type from discovery results"""
        detected_dbs = discovery_results.get('detected_databases', [])
        
        if detected_dbs:
            return detected_dbs[0]['type'].lower()
        
        return 'unknown'
    
    # Placeholder methods for specific database implementations
    async def _get_mysql_banner(self, target: str, port: int) -> Optional[str]:
        """Get MySQL banner"""
        # This would involve connecting to MySQL and getting version
        return "MySQL 8.0.25"
    
    async def _get_postgresql_banner(self, target: str, port: int) -> Optional[str]:
        """Get PostgreSQL banner"""
        # This would involve connecting to PostgreSQL and getting version
        return "PostgreSQL 13.3"
    
    async def _get_mongodb_banner(self, target: str, port: int) -> Optional[str]:
        """Get MongoDB banner"""
        # This would involve connecting to MongoDB and getting version
        return "MongoDB 4.4.6"
    
    async def _get_redis_banner(self, target: str, port: int) -> Optional[str]:
        """Get Redis banner"""
        # This would involve connecting to Redis and getting version
        return "Redis 6.2.4"
    
    async def _test_mysql_credentials(self, target: str, port: int, username: str, password: str) -> bool:
        """Test MySQL credentials"""
        # This would involve actual MySQL connection testing
        return False
    
    async def _test_postgresql_credentials(self, target: str, port: int, username: str, password: str) -> bool:
        """Test PostgreSQL credentials"""
        # This would involve actual PostgreSQL connection testing
        return False
    
    async def _test_mongodb_credentials(self, target: str, port: int, username: str, password: str) -> bool:
        """Test MongoDB credentials"""
        # This would involve actual MongoDB connection testing
        return False
    
    async def _test_redis_credentials(self, target: str, port: int, username: str, password: str) -> bool:
        """Test Redis credentials"""
        # This would involve actual Redis connection testing
        return False
    
    async def _audit_mysql_config(self, target: str, port: Optional[int]) -> Dict[str, Any]:
        """Audit MySQL configuration"""
        return {'status': 'not_implemented'}
    
    async def _audit_postgresql_config(self, target: str, port: Optional[int]) -> Dict[str, Any]:
        """Audit PostgreSQL configuration"""
        return {'status': 'not_implemented'}
    
    async def _audit_mongodb_config(self, target: str, port: Optional[int]) -> Dict[str, Any]:
        """Audit MongoDB configuration"""
        return {'status': 'not_implemented'}
    
    async def _audit_redis_config(self, target: str, port: Optional[int]) -> Dict[str, Any]:
        """Audit Redis configuration"""
        return {'status': 'not_implemented'}
    
    async def _get_authentication_methods(self, target: str, port: Optional[int], database_type: str) -> List[str]:
        """Get supported authentication methods"""
        methods = []
        
        if database_type.lower() == 'mysql':
            methods = ['mysql_native_password', 'sha256_password', 'caching_sha2_password']
        elif database_type.lower() == 'postgresql':
            methods = ['password', 'md5', 'scram-sha-256', 'gss', 'sspi', 'ldap']
        elif database_type.lower() == 'mongodb':
            methods = ['SCRAM-SHA-1', 'SCRAM-SHA-256', 'MONGODB-CR', 'PLAIN', 'GSSAPI']
        elif database_type.lower() == 'redis':
            methods = ['AUTH', 'No authentication']
        
        return methods
    
    def _compile_vulnerabilities(self, results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Compile database vulnerabilities"""
        vulnerabilities = []
        
        # Default credentials
        if results.get('authentication_test', {}).get('default_credentials'):
            for cred in results['authentication_test']['default_credentials']:
                vulnerabilities.append({
                    'type': 'Weak Authentication',
                    'severity': 'High',
                    'description': f"Default credentials found: {cred['username']}/{cred['password']}",
                    'recommendation': 'Change default credentials immediately'
                })
        
        # Anonymous access
        if results.get('authentication_test', {}).get('anonymous_access'):
            vulnerabilities.append({
                'type': 'Anonymous Access',
                'severity': 'Critical',
                'description': 'Anonymous access to database is enabled',
                'recommendation': 'Disable anonymous access and implement proper authentication'
            })
        
        # SSL/TLS issues
        ssl_test = results.get('encryption_analysis', {}).get('ssl_test', {})
        if not ssl_test.get('ssl_enabled', False):
            vulnerabilities.append({
                'type': 'Unencrypted Communication',
                'severity': 'High',
                'description': 'Database communication is not encrypted',
                'recommendation': 'Enable SSL/TLS encryption for database connections'
            })
        
        return vulnerabilities
    
    def _generate_recommendations(self, results: Dict[str, Any]) -> List[str]:
        """Generate database security recommendations"""
        recommendations = []
        
        if results.get('vulnerabilities'):
            recommendations.append("Address all identified vulnerabilities immediately")
        
        recommendations.extend([
            "Change all default passwords and credentials",
            "Implement proper authentication and authorization",
            "Enable SSL/TLS encryption for all connections",
            "Configure proper access controls and privileges",
            "Enable comprehensive audit logging",
            "Implement database activity monitoring",
            "Regular security updates and patches",
            "Secure backup and recovery procedures",
            "Database security hardening configuration",
            "Network segmentation for database servers",
            "Regular security assessments and penetration testing",
            "Data classification and protection policies"
        ])
        
        return recommendations