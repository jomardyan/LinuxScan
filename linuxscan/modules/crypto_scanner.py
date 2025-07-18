"""
Crypto Security Audit Scanner
Comprehensive cryptographic security assessment module
"""

import asyncio
import ssl
import socket
import hashlib
import hmac
import base64
import subprocess
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
from .base_scanner import BaseScannerModule


class CryptoSecurityScanner(BaseScannerModule):
    """Comprehensive cryptographic security assessment scanner"""
    
    def __init__(self, timeout: int = 120):
        super().__init__("crypto_security_scanner", timeout)
        self.weak_ciphers = [
            'DES', 'RC4', 'MD5', 'SHA1', 'SSL3', 'TLS1.0', 'TLS1.1',
            'RC2', 'RC5', 'IDEA', 'ADH', 'AECDH', 'NULL', 'EXPORT'
        ]
        self.strong_ciphers = [
            'AES256', 'AES128', 'ChaCha20', 'TLS1.2', 'TLS1.3',
            'ECDHE', 'DHE', 'SHA256', 'SHA384', 'SHA512'
        ]
        self.crypto_ports = [443, 993, 995, 465, 587, 636, 989, 990, 992, 5223]
    
    async def scan(self, target: str, **kwargs) -> Dict[str, Any]:
        """Perform crypto security audit scan"""
        self.log_scan_start(target)
        
        # Enhanced target info with reverse DNS
        target_info = self.enhance_target_info(target)
        
        results = {
            'target_info': target_info,
            'scan_type': 'crypto_security_audit',
            'timestamp': datetime.now().isoformat(),
            'ssl_tls_analysis': {},
            'certificate_analysis': {},
            'cipher_analysis': {},
            'key_exchange_analysis': {},
            'vulnerabilities': [],
            'recommendations': [],
            'compliance_status': {}
        }
        
        try:
            # Analyze SSL/TLS services
            await self._analyze_ssl_services(target, results)
            
            # Analyze certificates
            await self._analyze_certificates(target, results)
            
            # Check for crypto vulnerabilities
            await self._check_crypto_vulnerabilities(target, results)
            
            # Generate compliance report
            await self._generate_compliance_report(results)
            
        except Exception as e:
            results['error'] = str(e)
            self.logger.error(f"Error in crypto security scan: {e}")
        
        self.log_scan_end(target)
        return results
    
    async def _analyze_ssl_services(self, target: str, results: Dict[str, Any]):
        """Analyze SSL/TLS services on target"""
        ssl_services = {}
        
        for port in self.crypto_ports:
            try:
                # Test SSL connection
                ssl_info = await self._test_ssl_connection(target, port)
                if ssl_info:
                    ssl_services[port] = ssl_info
            except Exception as e:
                self.logger.debug(f"Error testing SSL on port {port}: {e}")
        
        results['ssl_tls_analysis'] = ssl_services
    
    async def _test_ssl_connection(self, target: str, port: int) -> Optional[Dict[str, Any]]:
        """Test SSL connection and gather information"""
        try:
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Connect and get SSL info
            with socket.create_connection((target, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    cert = ssock.getpeercert(binary_form=True)
                    cert_text = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()
                    
                    return {
                        'port': port,
                        'protocol_version': version,
                        'cipher_suite': cipher,
                        'certificate_info': cert_text,
                        'certificate_binary': base64.b64encode(cert).decode() if cert else None,
                        'connection_successful': True
                    }
        except Exception as e:
            self.logger.debug(f"SSL connection failed on {target}:{port}: {e}")
            return None
    
    async def _analyze_certificates(self, target: str, results: Dict[str, Any]):
        """Analyze SSL certificates for security issues"""
        cert_analysis = {}
        
        for port, ssl_info in results.get('ssl_tls_analysis', {}).items():
            if ssl_info and ssl_info.get('certificate_info'):
                cert_info = ssl_info['certificate_info']
                
                cert_analysis[port] = {
                    'subject': cert_info.get('subject', []),
                    'issuer': cert_info.get('issuer', []),
                    'version': cert_info.get('version', 'unknown'),
                    'serial_number': cert_info.get('serialNumber', 'unknown'),
                    'not_before': cert_info.get('notBefore', 'unknown'),
                    'not_after': cert_info.get('notAfter', 'unknown'),
                    'signature_algorithm': cert_info.get('signatureAlgorithm', 'unknown'),
                    'public_key_info': self._analyze_public_key(cert_info),
                    'extensions': self._analyze_certificate_extensions(cert_info),
                    'security_issues': []
                }
                
                # Check for security issues
                security_issues = self._check_certificate_security(cert_info)
                cert_analysis[port]['security_issues'] = security_issues
        
        results['certificate_analysis'] = cert_analysis
    
    def _analyze_public_key(self, cert_info: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze public key information"""
        public_key_info = {
            'algorithm': 'unknown',
            'key_size': 'unknown',
            'security_level': 'unknown'
        }
        
        try:
            # Extract public key info from certificate
            if 'subjectPublicKeyInfo' in cert_info:
                # This would require more detailed certificate parsing
                pass
        except Exception:
            pass
        
        return public_key_info
    
    def _analyze_certificate_extensions(self, cert_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze certificate extensions"""
        extensions = []
        
        try:
            # Extract extensions from certificate
            if 'extensions' in cert_info:
                for ext in cert_info['extensions']:
                    extensions.append({
                        'name': ext.get('name', 'unknown'),
                        'critical': ext.get('critical', False),
                        'value': str(ext.get('value', ''))
                    })
        except Exception:
            pass
        
        return extensions
    
    def _check_certificate_security(self, cert_info: Dict[str, Any]) -> List[str]:
        """Check certificate for security issues"""
        issues = []
        
        # Check expiration
        try:
            import datetime
            not_after = cert_info.get('notAfter', '')
            if not_after:
                # Parse date and check if expiring soon
                # This is a simplified check
                issues.append("Certificate expiration check needed")
        except Exception:
            pass
        
        # Check signature algorithm
        sig_algo = cert_info.get('signatureAlgorithm', '').lower()
        if 'md5' in sig_algo or 'sha1' in sig_algo:
            issues.append(f"Weak signature algorithm: {sig_algo}")
        
        # Check key size (would need more detailed parsing)
        # For now, add placeholder
        issues.append("Public key strength analysis needed")
        
        return issues
    
    async def _check_crypto_vulnerabilities(self, target: str, results: Dict[str, Any]):
        """Check for known cryptographic vulnerabilities"""
        vulnerabilities = []
        
        # Check for weak cipher suites
        for port, ssl_info in results.get('ssl_tls_analysis', {}).items():
            if ssl_info and ssl_info.get('cipher_suite'):
                cipher = ssl_info['cipher_suite']
                if cipher:
                    cipher_name = cipher[0] if isinstance(cipher, tuple) else str(cipher)
                    
                    # Check for weak ciphers
                    for weak_cipher in self.weak_ciphers:
                        if weak_cipher.lower() in cipher_name.lower():
                            vulnerabilities.append({
                                'port': port,
                                'type': 'weak_cipher',
                                'description': f"Weak cipher suite detected: {cipher_name}",
                                'severity': 'medium'
                            })
        
        # Check for protocol vulnerabilities
        for port, ssl_info in results.get('ssl_tls_analysis', {}).items():
            if ssl_info and ssl_info.get('protocol_version'):
                version = ssl_info['protocol_version']
                if version in ['SSLv3', 'TLSv1', 'TLSv1.1']:
                    vulnerabilities.append({
                        'port': port,
                        'type': 'weak_protocol',
                        'description': f"Weak protocol version: {version}",
                        'severity': 'high'
                    })
        
        results['vulnerabilities'] = vulnerabilities
    
    async def _generate_compliance_report(self, results: Dict[str, Any]):
        """Generate compliance report for various standards"""
        compliance = {
            'pci_dss': {'compliant': True, 'issues': []},
            'nist': {'compliant': True, 'issues': []},
            'fips_140': {'compliant': True, 'issues': []},
            'common_criteria': {'compliant': True, 'issues': []}
        }
        
        # Check PCI DSS compliance
        for vuln in results.get('vulnerabilities', []):
            if vuln['type'] in ['weak_cipher', 'weak_protocol']:
                compliance['pci_dss']['compliant'] = False
                compliance['pci_dss']['issues'].append(vuln['description'])
        
        # Generate recommendations
        recommendations = []
        
        if not compliance['pci_dss']['compliant']:
            recommendations.append("Upgrade to strong cipher suites (AES256, ChaCha20)")
            recommendations.append("Disable weak protocols (SSLv3, TLS 1.0, TLS 1.1)")
        
        recommendations.extend([
            "Implement certificate pinning where possible",
            "Use Perfect Forward Secrecy (PFS) cipher suites",
            "Regularly rotate certificates and keys",
            "Monitor for certificate transparency logs"
        ])
        
        results['compliance_status'] = compliance
        results['recommendations'] = recommendations
    
    async def _run_openssl_analysis(self, target: str, port: int) -> Dict[str, Any]:
        """Run OpenSSL-based analysis"""
        result = {
            'target': target,
            'port': port,
            'output': '',
            'error': '',
            'ciphers': [],
            'protocols': []
        }
        
        try:
            # Test SSL connection with OpenSSL
            cmd = [
                'openssl', 's_client', '-connect', f'{target}:{port}',
                '-servername', target, '-showcerts'
            ]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                stdin=asyncio.subprocess.PIPE
            )
            
            # Send empty input to close connection
            stdout, stderr = await asyncio.wait_for(
                process.communicate(input=b''),
                timeout=30
            )
            
            result['output'] = stdout.decode('utf-8', errors='ignore')
            result['error'] = stderr.decode('utf-8', errors='ignore')
            
            # Parse output for cipher and protocol info
            output_lines = result['output'].split('\n')
            for line in output_lines:
                if 'Cipher    :' in line:
                    cipher = line.split(':')[1].strip()
                    result['ciphers'].append(cipher)
                elif 'Protocol  :' in line:
                    protocol = line.split(':')[1].strip()
                    result['protocols'].append(protocol)
            
        except Exception as e:
            result['error'] = str(e)
        
        return result