"""
Tests for Memory Scanner module
"""

import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime

from linuxscan.modules.memory_scanner import MemoryAnalysisScanner


class TestMemoryAnalysisScanner:
    """Test MemoryAnalysisScanner module"""
    
    def test_init(self):
        """Test MemoryAnalysisScanner initialization"""
        scanner = MemoryAnalysisScanner()
        assert scanner.name == "memory_scanner"
        assert scanner.timeout == 180
        assert len(scanner.memory_artifacts) > 0
        assert len(scanner.rootkit_signatures) > 0
        assert scanner.volatility_profile is not None
    
    @pytest.mark.asyncio
    async def test_scan_basic(self):
        """Test basic memory scanning"""
        scanner = MemoryAnalysisScanner()
        
        with patch.object(scanner, '_memory_acquisition') as mock_acquisition:
            mock_acquisition.return_value = {
                'memory_dump': '/tmp/memory.dump',
                'dump_size': 1024000,
                'acquisition_method': 'lime'
            }
            
            with patch.object(scanner, '_volatility_analysis') as mock_volatility:
                mock_volatility.return_value = {
                    'processes': [
                        {'pid': 1234, 'name': 'suspicious_process', 'command': 'malware.exe'}
                    ],
                    'network_connections': [],
                    'loaded_modules': []
                }
                
                with patch.object(scanner, '_rootkit_detection') as mock_rootkit:
                    mock_rootkit.return_value = {
                        'rootkit_indicators': [],
                        'hidden_processes': [],
                        'modified_syscalls': []
                    }
                    
                    result = await scanner.scan('192.168.1.100')
                    
                    assert result['target'] == '192.168.1.100'
                    assert 'memory_acquisition' in result
                    assert 'volatility_analysis' in result
                    assert 'rootkit_detection' in result
    
    @pytest.mark.asyncio
    async def test_memory_acquisition(self):
        """Test memory acquisition"""
        scanner = MemoryAnalysisScanner()
        
        with patch('subprocess.run') as mock_subprocess:
            mock_subprocess.return_value.returncode = 0
            mock_subprocess.return_value.stdout = b'Memory dump completed'
            
            with patch('os.path.exists') as mock_exists:
                mock_exists.return_value = True
                
                with patch('os.path.getsize') as mock_size:
                    mock_size.return_value = 1024000
                    
                    result = await scanner._memory_acquisition('192.168.1.100')
                    
                    assert 'memory_dump' in result
                    assert 'dump_size' in result
                    assert 'acquisition_method' in result
    
    @pytest.mark.asyncio
    async def test_volatility_analysis(self):
        """Test Volatility framework analysis"""
        scanner = MemoryAnalysisScanner()
        
        with patch('subprocess.run') as mock_subprocess:
            # Mock pslist output
            mock_subprocess.return_value.returncode = 0
            mock_subprocess.return_value.stdout = b'''
PID     PPID    ImageFileName   Offset(V)   Threads Hndls   SessionId
1234    1       suspicious.exe  0x85abc123  2       45      1
5678    1       svchost.exe     0x85def456  8       123     0
'''
            
            result = await scanner._volatility_analysis('/tmp/memory.dump')
            
            assert 'processes' in result
            assert 'network_connections' in result
            assert 'loaded_modules' in result
            assert len(result['processes']) > 0
    
    def test_analyze_process_list(self):
        """Test process list analysis"""
        scanner = MemoryAnalysisScanner()
        
        processes = [
            {'pid': 1234, 'name': 'suspicious.exe', 'command': 'malware.exe'},
            {'pid': 5678, 'name': 'svchost.exe', 'command': 'svchost.exe -k netsvcs'},
            {'pid': 9012, 'name': 'explorer.exe', 'command': 'explorer.exe'}
        ]
        
        suspicious_processes = scanner._analyze_process_list(processes)
        
        assert len(suspicious_processes) > 0
        assert any(proc['name'] == 'suspicious.exe' for proc in suspicious_processes)
    
    def test_detect_process_injection(self):
        """Test process injection detection"""
        scanner = MemoryAnalysisScanner()
        
        processes = [
            {
                'pid': 1234,
                'name': 'explorer.exe',
                'command': 'explorer.exe',
                'memory_regions': [
                    {'start': 0x400000, 'end': 0x500000, 'permissions': 'rwx', 'type': 'executable'}
                ]
            }
        ]
        
        injected_processes = scanner._detect_process_injection(processes)
        
        assert isinstance(injected_processes, list)
        # Should detect processes with suspicious memory regions
    
    def test_analyze_network_connections(self):
        """Test network connection analysis"""
        scanner = MemoryAnalysisScanner()
        
        connections = [
            {'pid': 1234, 'local_addr': '192.168.1.100:1234', 'remote_addr': '192.168.1.1:80', 'state': 'ESTABLISHED'},
            {'pid': 5678, 'local_addr': '192.168.1.100:5678', 'remote_addr': '10.0.0.1:443', 'state': 'ESTABLISHED'}
        ]
        
        suspicious_connections = scanner._analyze_network_connections(connections)
        
        assert isinstance(suspicious_connections, list)
        # Should identify potentially suspicious connections
    
    def test_detect_rootkit_indicators(self):
        """Test rootkit indicator detection"""
        scanner = MemoryAnalysisScanner()
        
        # Test with rootkit signatures
        memory_content = b'some_rootkit_signature_here'
        
        indicators = scanner._detect_rootkit_indicators(memory_content)
        
        assert isinstance(indicators, list)
        # Should detect rootkit patterns in memory
    
    def test_analyze_syscall_table(self):
        """Test syscall table analysis"""
        scanner = MemoryAnalysisScanner()
        
        syscall_table = [
            {'number': 1, 'name': 'sys_exit', 'address': 0x80123456, 'original': True},
            {'number': 2, 'name': 'sys_fork', 'address': 0x80654321, 'original': False}
        ]
        
        modified_syscalls = scanner._analyze_syscall_table(syscall_table)
        
        assert len(modified_syscalls) > 0
        assert any(sc['name'] == 'sys_fork' for sc in modified_syscalls)
    
    def test_extract_memory_artifacts(self):
        """Test memory artifact extraction"""
        scanner = MemoryAnalysisScanner()
        
        memory_dump = b'''
        Some memory content with passwords:
        password123
        secretkey456
        And some URLs:
        http://malware.com/payload
        https://c2.evil.com/beacon
        '''
        
        artifacts = scanner._extract_memory_artifacts(memory_dump)
        
        assert 'passwords' in artifacts
        assert 'urls' in artifacts
        assert 'crypto_keys' in artifacts
        assert len(artifacts['passwords']) > 0
        assert len(artifacts['urls']) > 0
    
    def test_analyze_heap_spray(self):
        """Test heap spray detection"""
        scanner = MemoryAnalysisScanner()
        
        # Mock heap data with spray pattern
        heap_data = b'\x90' * 1000 + b'\x41' * 1000  # NOP sled + shellcode pattern
        
        spray_indicators = scanner._analyze_heap_spray(heap_data)
        
        assert 'nop_sleds' in spray_indicators
        assert 'shellcode_patterns' in spray_indicators
        assert spray_indicators['nop_sleds'] > 0
    
    def test_detect_code_injection(self):
        """Test code injection detection"""
        scanner = MemoryAnalysisScanner()
        
        processes = [
            {
                'pid': 1234,
                'name': 'notepad.exe',
                'memory_regions': [
                    {
                        'start': 0x400000,
                        'end': 0x500000,
                        'permissions': 'rwx',
                        'type': 'private',
                        'content': b'\x90\x90\x90\x90\x31\xc0\x50\x68'  # Suspicious shellcode
                    }
                ]
            }
        ]
        
        injected_code = scanner._detect_code_injection(processes)
        
        assert isinstance(injected_code, list)
        assert len(injected_code) > 0
    
    def test_analyze_driver_integrity(self):
        """Test driver integrity analysis"""
        scanner = MemoryAnalysisScanner()
        
        drivers = [
            {
                'name': 'ntoskrnl.exe',
                'base_address': 0x80400000,
                'size': 0x400000,
                'digital_signature': True,
                'modified': False
            },
            {
                'name': 'suspicious.sys',
                'base_address': 0x80800000,
                'size': 0x10000,
                'digital_signature': False,
                'modified': True
            }
        ]
        
        integrity_issues = scanner._analyze_driver_integrity(drivers)
        
        assert len(integrity_issues) > 0
        assert any(issue['driver'] == 'suspicious.sys' for issue in integrity_issues)
    
    def test_generate_memory_report(self):
        """Test memory analysis report generation"""
        scanner = MemoryAnalysisScanner()
        
        results = {
            'memory_acquisition': {
                'memory_dump': '/tmp/memory.dump',
                'dump_size': 1024000
            },
            'volatility_analysis': {
                'processes': [
                    {'pid': 1234, 'name': 'suspicious.exe'}
                ],
                'network_connections': [],
                'loaded_modules': []
            },
            'rootkit_detection': {
                'rootkit_indicators': [
                    {'type': 'Modified Syscall', 'description': 'sys_fork modified'}
                ],
                'hidden_processes': [],
                'modified_syscalls': []
            }
        }
        
        report = scanner._generate_memory_report(results)
        
        assert 'executive_summary' in report
        assert 'detailed_findings' in report
        assert 'recommendations' in report
        assert len(report['detailed_findings']) > 0
    
    def test_calculate_memory_risk_score(self):
        """Test memory analysis risk score calculation"""
        scanner = MemoryAnalysisScanner()
        
        # Test high risk scenario
        high_risk_results = {
            'volatility_analysis': {
                'suspicious_processes': [
                    {'name': 'malware.exe', 'pid': 1234}
                ]
            },
            'rootkit_detection': {
                'rootkit_indicators': [
                    {'type': 'Modified Syscall', 'severity': 'High'}
                ]
            },
            'artifact_analysis': {
                'suspicious_artifacts': [
                    {'type': 'Malicious URL', 'content': 'http://malware.com'}
                ]
            }
        }
        
        score = scanner._calculate_memory_risk_score(high_risk_results)
        assert score >= 70  # High risk
        
        # Test low risk scenario
        low_risk_results = {
            'volatility_analysis': {
                'suspicious_processes': []
            },
            'rootkit_detection': {
                'rootkit_indicators': []
            },
            'artifact_analysis': {
                'suspicious_artifacts': []
            }
        }
        
        score = scanner._calculate_memory_risk_score(low_risk_results)
        assert score <= 30  # Low risk


if __name__ == "__main__":
    pytest.main([__file__, "-v"])