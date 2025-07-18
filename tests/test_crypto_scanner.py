"""
Tests for CryptoSecurityScanner module
"""

import pytest
import asyncio
import ssl
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime

from linuxscan.modules.crypto_scanner import CryptoSecurityScanner


class TestCryptoSecurityScanner:
    """Test CryptoSecurityScanner module"""
    
    def test_init(self):
        """Test CryptoSecurityScanner initialization"""
        scanner = CryptoSecurityScanner()
        assert scanner.name == "crypto_security_scanner"
        assert scanner.timeout == 120
        assert len(scanner.weak_ciphers) > 0
        assert len(scanner.strong_ciphers) > 0
        assert len(scanner.crypto_ports) > 0
        
        # Check specific weak ciphers
        assert 'DES' in scanner.weak_ciphers
        assert 'RC4' in scanner.weak_ciphers
        assert 'MD5' in scanner.weak_ciphers
        assert 'SSL3' in scanner.weak_ciphers
        
        # Check specific strong ciphers
        assert 'AES256' in scanner.strong_ciphers
        assert 'TLS1.3' in scanner.strong_ciphers
        assert 'ECDHE' in scanner.strong_ciphers
    
    @pytest.mark.asyncio
    async def test_scan_basic(self):
        """Test basic crypto security scanning"""
        scanner = CryptoSecurityScanner()
        
        with patch.object(scanner, '_ssl_tls_analysis') as mock_ssl:
            mock_ssl.return_value = {
                'protocols': ['TLSv1.2', 'TLSv1.3'],
                'ciphers': ['AES256-GCM-SHA384'],
                'vulnerabilities': []
            }
            
            with patch.object(scanner, '_certificate_analysis') as mock_cert:
                mock_cert.return_value = {
                    'certificate_chain': [{'subject': 'example.com', 'issuer': 'CA'}],
                    'expiration': '2024-12-31',
                    'key_strength': 2048
                }
                
                with patch.object(scanner, '_cryptographic_implementations') as mock_crypto:
                    mock_crypto.return_value = {
                        'hash_algorithms': ['SHA256', 'SHA384'],
                        'encryption_algorithms': ['AES256'],
                        'key_exchange': ['ECDHE']
                    }
                    
                    result = await scanner.scan('example.com')
                    
                    assert result['target'] == 'example.com'
                    assert 'ssl_tls_analysis' in result
                    assert 'certificate_analysis' in result
                    assert 'cryptographic_implementations' in result
    
    @pytest.mark.asyncio
    async def test_ssl_tls_analysis(self):
        """Test SSL/TLS analysis"""
        scanner = CryptoSecurityScanner()
        
        with patch('ssl.create_default_context') as mock_context:
            mock_ctx = MagicMock()
            mock_context.return_value = mock_ctx
            
            with patch('socket.create_connection') as mock_socket:
                mock_sock = MagicMock()
                mock_socket.return_value = mock_sock
                
                # Mock SSL socket
                mock_ssl_sock = MagicMock()
                mock_ssl_sock.version.return_value = 'TLSv1.3'
                mock_ssl_sock.cipher.return_value = ('AES256-GCM-SHA384', 'TLSv1.3', 256)
                mock_ssl_sock.getpeercert.return_value = {
                    'subject': [['CN', 'example.com']],
                    'issuer': [['CN', 'Test CA']],
                    'notAfter': 'Dec 31 23:59:59 2024 GMT'
                }
                
                mock_ctx.wrap_socket.return_value = mock_ssl_sock
                
                result = await scanner._ssl_tls_analysis('example.com', 443)
                
                assert 'protocols' in result
                assert 'ciphers' in result
                assert 'vulnerabilities' in result
    
    def test_analyze_cipher_suite(self):
        """Test cipher suite analysis"""
        scanner = CryptoSecurityScanner()
        
        # Test weak cipher
        weak_cipher = 'RC4-MD5'
        result = scanner._analyze_cipher_suite(weak_cipher)
        assert result['strength'] == 'weak'
        assert 'RC4' in result['weaknesses']
        assert 'MD5' in result['weaknesses']
        
        # Test strong cipher
        strong_cipher = 'AES256-GCM-SHA384'
        result = scanner._analyze_cipher_suite(strong_cipher)
        assert result['strength'] == 'strong'
        assert len(result['weaknesses']) == 0
    
    def test_check_certificate_validity(self):
        """Test certificate validity checking"""
        scanner = CryptoSecurityScanner()
        
        # Test valid certificate
        valid_cert = {
            'notAfter': 'Dec 31 23:59:59 2024 GMT',
            'notBefore': 'Jan 1 00:00:00 2023 GMT',
            'subject': [['CN', 'example.com']],
            'issuer': [['CN', 'Test CA']]
        }
        
        result = scanner._check_certificate_validity(valid_cert)
        assert result['valid'] == True
        assert 'days_until_expiry' in result
        assert result['days_until_expiry'] > 0
    
    def test_extract_certificate_info(self):
        """Test certificate information extraction"""
        scanner = CryptoSecurityScanner()
        
        cert_der = b'fake_certificate_data'
        
        with patch('ssl.DER_cert_to_PEM_cert') as mock_der_to_pem:
            mock_der_to_pem.return_value = "-----BEGIN CERTIFICATE-----\nfake_cert\n-----END CERTIFICATE-----"
            
            with patch('cryptography.x509.load_pem_x509_certificate') as mock_load_cert:
                mock_cert = MagicMock()
                mock_cert.subject.get_attributes_for_oid.return_value = [MagicMock(value='example.com')]
                mock_cert.issuer.get_attributes_for_oid.return_value = [MagicMock(value='Test CA')]
                mock_cert.not_valid_after = datetime(2024, 12, 31)
                mock_cert.public_key.return_value.key_size = 2048
                mock_load_cert.return_value = mock_cert
                
                result = scanner._extract_certificate_info(cert_der)
                
                assert result['subject'] == 'example.com'
                assert result['issuer'] == 'Test CA'
                assert result['key_size'] == 2048
    
    def test_analyze_hash_strength(self):
        """Test hash algorithm strength analysis"""
        scanner = CryptoSecurityScanner()
        
        # Test weak hash
        weak_hash = 'MD5'
        result = scanner._analyze_hash_strength(weak_hash)
        assert result['strength'] == 'weak'
        assert 'collision' in result['vulnerabilities'][0].lower()
        
        # Test strong hash
        strong_hash = 'SHA256'
        result = scanner._analyze_hash_strength(strong_hash)
        assert result['strength'] == 'strong'
        assert len(result['vulnerabilities']) == 0
    
    def test_check_key_strength(self):
        """Test key strength checking"""
        scanner = CryptoSecurityScanner()
        
        # Test weak key
        weak_key = scanner._check_key_strength('RSA', 1024)
        assert weak_key['strength'] == 'weak'
        assert 'insufficient' in weak_key['recommendation'].lower()
        
        # Test strong key
        strong_key = scanner._check_key_strength('RSA', 2048)
        assert strong_key['strength'] == 'adequate'
        
        # Test very strong key
        very_strong_key = scanner._check_key_strength('RSA', 4096)
        assert very_strong_key['strength'] == 'strong'
    
    @pytest.mark.asyncio
    async def test_check_hsts_support(self):
        """Test HSTS support checking"""
        scanner = CryptoSecurityScanner()
        
        with patch('aiohttp.ClientSession') as mock_session:
            mock_response = AsyncMock()
            mock_response.headers = {'Strict-Transport-Security': 'max-age=31536000; includeSubDomains'}
            mock_response.status = 200
            
            mock_session_instance = AsyncMock()
            mock_session_instance.get.return_value.__aenter__.return_value = mock_response
            mock_session.return_value = mock_session_instance
            
            result = await scanner._check_hsts_support('https://example.com')
            
            assert result['hsts_enabled'] == True
            assert result['max_age'] == 31536000
            assert result['include_subdomains'] == True
    
    def test_compile_crypto_recommendations(self):
        """Test crypto recommendations compilation"""
        scanner = CryptoSecurityScanner()
        
        results = {
            'ssl_tls_analysis': {
                'vulnerabilities': [
                    {'type': 'Weak Cipher', 'severity': 'High', 'description': 'RC4 detected'}
                ]
            },
            'certificate_analysis': {
                'validity': {'valid': False, 'reason': 'Expired'}
            },
            'cryptographic_implementations': {
                'weak_algorithms': ['MD5', 'SHA1']
            }
        }
        
        recommendations = scanner._compile_crypto_recommendations(results)
        
        assert len(recommendations) >= 3
        assert any('cipher' in rec.lower() for rec in recommendations)
        assert any('certificate' in rec.lower() for rec in recommendations)
        assert any('hash' in rec.lower() for rec in recommendations)
    
    def test_calculate_crypto_score(self):
        """Test crypto security score calculation"""
        scanner = CryptoSecurityScanner()
        
        # Test high security score
        high_security_results = {
            'ssl_tls_analysis': {
                'protocols': ['TLSv1.3'],
                'ciphers': ['AES256-GCM-SHA384'],
                'vulnerabilities': []
            },
            'certificate_analysis': {
                'validity': {'valid': True},
                'key_strength': 2048
            }
        }
        
        score = scanner._calculate_crypto_score(high_security_results)
        assert score >= 80
        
        # Test low security score
        low_security_results = {
            'ssl_tls_analysis': {
                'protocols': ['TLSv1.0'],
                'ciphers': ['RC4-MD5'],
                'vulnerabilities': [{'severity': 'Critical'}]
            },
            'certificate_analysis': {
                'validity': {'valid': False},
                'key_strength': 1024
            }
        }
        
        score = scanner._calculate_crypto_score(low_security_results)
        assert score <= 40


if __name__ == "__main__":
    pytest.main([__file__, "-v"])