"""
Tests for Steganography Scanner module
"""

import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime

from linuxscan.modules.steganography_scanner import SteganographyScanner


class TestSteganographyScanner:
    """Test SteganographyScanner module"""
    
    def test_init(self):
        """Test SteganographyScanner initialization"""
        scanner = SteganographyScanner()
        assert scanner.name == "steganography_scanner"
        assert scanner.timeout == 120
        assert len(scanner.stego_tools) > 0
        assert len(scanner.file_signatures) > 0
        assert len(scanner.supported_formats) > 0
        
        # Check specific steganography tools
        assert 'steghide' in scanner.stego_tools
        assert 'outguess' in scanner.stego_tools
        assert 'jsteg' in scanner.stego_tools
    
    @pytest.mark.asyncio
    async def test_scan_basic(self):
        """Test basic steganography scanning"""
        scanner = SteganographyScanner()
        
        with patch.object(scanner, '_file_discovery') as mock_discovery:
            mock_discovery.return_value = {
                'image_files': ['/tmp/test.jpg', '/tmp/test.png'],
                'audio_files': ['/tmp/test.wav'],
                'video_files': ['/tmp/test.mp4'],
                'document_files': ['/tmp/test.pdf']
            }
            
            with patch.object(scanner, '_metadata_analysis') as mock_metadata:
                mock_metadata.return_value = {
                    '/tmp/test.jpg': {
                        'exif_data': {'Camera': 'Canon'},
                        'suspicious_metadata': True
                    }
                }
                
                with patch.object(scanner, '_statistical_analysis') as mock_stats:
                    mock_stats.return_value = {
                        '/tmp/test.jpg': {
                            'chi_square': 1.5,
                            'entropy': 7.8,
                            'histogram_anomalies': True
                        }
                    }
                    
                    result = await scanner.scan('/tmp')
                    
                    assert result['target'] == '/tmp'
                    assert 'file_discovery' in result
                    assert 'metadata_analysis' in result
                    assert 'statistical_analysis' in result
    
    @pytest.mark.asyncio
    async def test_file_discovery(self):
        """Test file discovery for steganography analysis"""
        scanner = SteganographyScanner()
        
        with patch('os.walk') as mock_walk:
            mock_walk.return_value = [
                ('/tmp', ['subdir'], ['test.jpg', 'test.png', 'test.wav', 'test.mp4', 'test.pdf']),
                ('/tmp/subdir', [], ['hidden.jpg'])
            ]
            
            with patch('os.path.getsize') as mock_size:
                mock_size.return_value = 1024000  # 1MB
                
                result = await scanner._file_discovery('/tmp')
                
                assert 'image_files' in result
                assert 'audio_files' in result
                assert 'video_files' in result
                assert 'document_files' in result
                assert len(result['image_files']) > 0
    
    def test_analyze_file_metadata(self):
        """Test file metadata analysis"""
        scanner = SteganographyScanner()
        
        with patch('PIL.Image.open') as mock_pil:
            mock_image = MagicMock()
            mock_image._getexif.return_value = {
                272: 'Canon EOS 5D',  # Make
                306: '2023:01:01 12:00:00',  # DateTime
                34853: {1: 'N', 2: (40, 42, 51.89), 3: 'W', 4: (74, 0, 23.46)}  # GPS
            }
            mock_pil.return_value = mock_image
            
            result = scanner._analyze_file_metadata('/tmp/test.jpg')
            
            assert 'exif_data' in result
            assert 'gps_coordinates' in result
            assert 'suspicious_metadata' in result
    
    def test_statistical_analysis(self):
        """Test statistical analysis for steganography detection"""
        scanner = SteganographyScanner()
        
        # Mock file data
        file_data = b'\x89PNG\r\n\x1a\n' + b'\x00' * 1000 + b'\xFF' * 1000
        
        with patch('builtins.open', mock_open_binary(file_data)):
            result = scanner._statistical_analysis('/tmp/test.png')
            
            assert 'chi_square' in result
            assert 'entropy' in result
            assert 'histogram_anomalies' in result
            assert 'byte_distribution' in result
    
    def test_detect_steganography_tools(self):
        """Test steganography tool detection"""
        scanner = SteganographyScanner()
        
        with patch('subprocess.run') as mock_subprocess:
            # Mock steghide detection
            mock_subprocess.return_value.returncode = 0
            mock_subprocess.return_value.stdout = b'steghide: could not extract any data'
            
            result = scanner._detect_steganography_tools('/tmp/test.jpg')
            
            assert 'steghide' in result
            assert 'outguess' in result
            assert 'jsteg' in result
    
    def test_analyze_image_histogram(self):
        """Test image histogram analysis"""
        scanner = SteganographyScanner()
        
        with patch('PIL.Image.open') as mock_pil:
            mock_image = MagicMock()
            mock_image.histogram.return_value = [100] * 256  # Uniform histogram
            mock_pil.return_value = mock_image
            
            result = scanner._analyze_image_histogram('/tmp/test.jpg')
            
            assert 'histogram_entropy' in result
            assert 'anomaly_score' in result
            assert 'suspicious_patterns' in result
    
    def test_lsb_analysis(self):
        """Test LSB (Least Significant Bit) analysis"""
        scanner = SteganographyScanner()
        
        # Mock image data with potential LSB steganography
        image_data = bytearray(b'\x00\x01\x02\x03' * 1000)  # Pattern that might indicate LSB
        
        result = scanner._lsb_analysis(image_data)
        
        assert 'lsb_entropy' in result
        assert 'pattern_detection' in result
        assert 'probability_score' in result
    
    def test_detect_hidden_archives(self):
        """Test hidden archive detection"""
        scanner = SteganographyScanner()
        
        # Mock file with embedded ZIP
        file_data = b'Normal image data here' + b'PK\x03\x04' + b'ZIP archive data'
        
        with patch('builtins.open', mock_open_binary(file_data)):
            result = scanner._detect_hidden_archives('/tmp/test.jpg')
            
            assert 'embedded_archives' in result
            assert 'archive_types' in result
            assert len(result['embedded_archives']) > 0
    
    def test_analyze_audio_steganography(self):
        """Test audio steganography analysis"""
        scanner = SteganographyScanner()
        
        with patch('wave.open') as mock_wave:
            mock_audio = MagicMock()
            mock_audio.getnchannels.return_value = 2
            mock_audio.getsampwidth.return_value = 2
            mock_audio.getframerate.return_value = 44100
            mock_audio.getnframes.return_value = 44100
            mock_audio.readframes.return_value = b'\x00\x01' * 44100
            mock_wave.return_value = mock_audio
            
            result = scanner._analyze_audio_steganography('/tmp/test.wav')
            
            assert 'spectral_analysis' in result
            assert 'lsb_analysis' in result
            assert 'echo_hiding' in result
    
    def test_pdf_steganography_analysis(self):
        """Test PDF steganography analysis"""
        scanner = SteganographyScanner()
        
        pdf_content = b'''%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>
endobj
xref
0 4
0000000000 65535 f 
0000000009 00000 n 
0000000074 00000 n 
0000000120 00000 n 
trailer
<< /Size 4 /Root 1 0 R >>
startxref
185
%%EOF
'''
        
        with patch('builtins.open', mock_open_binary(pdf_content)):
            result = scanner._pdf_steganography_analysis('/tmp/test.pdf')
            
            assert 'metadata_analysis' in result
            assert 'javascript_analysis' in result
            assert 'embedded_files' in result
            assert 'structure_analysis' in result
    
    def test_frequency_analysis(self):
        """Test frequency analysis for steganography detection"""
        scanner = SteganographyScanner()
        
        # Mock data with suspicious frequency patterns
        data = b'A' * 500 + b'B' * 400 + b'C' * 100  # Uneven distribution
        
        result = scanner._frequency_analysis(data)
        
        assert 'frequency_distribution' in result
        assert 'entropy_score' in result
        assert 'anomaly_detected' in result
    
    def test_generate_stego_report(self):
        """Test steganography analysis report generation"""
        scanner = SteganographyScanner()
        
        results = {
            'file_discovery': {
                'image_files': ['/tmp/test.jpg'],
                'audio_files': ['/tmp/test.wav'],
                'total_files': 2
            },
            'metadata_analysis': {
                '/tmp/test.jpg': {
                    'suspicious_metadata': True,
                    'gps_coordinates': True
                }
            },
            'statistical_analysis': {
                '/tmp/test.jpg': {
                    'chi_square': 2.5,
                    'entropy': 6.5,
                    'histogram_anomalies': True
                }
            },
            'tool_detection': {
                '/tmp/test.jpg': {
                    'steghide': 'detected',
                    'outguess': 'not_detected'
                }
            }
        }
        
        report = scanner._generate_stego_report(results)
        
        assert 'summary' in report
        assert 'suspicious_files' in report
        assert 'recommendations' in report
        assert 'confidence_scores' in report
    
    def test_calculate_steganography_probability(self):
        """Test steganography probability calculation"""
        scanner = SteganographyScanner()
        
        # Test high probability scenario
        high_prob_analysis = {
            'chi_square': 3.5,  # High chi-square indicates steganography
            'entropy': 7.9,     # High entropy
            'histogram_anomalies': True,
            'metadata_suspicious': True,
            'tool_signatures': ['steghide', 'outguess']
        }
        
        probability = scanner._calculate_steganography_probability(high_prob_analysis)
        assert probability >= 0.7  # High probability
        
        # Test low probability scenario
        low_prob_analysis = {
            'chi_square': 1.0,   # Low chi-square
            'entropy': 6.0,      # Normal entropy
            'histogram_anomalies': False,
            'metadata_suspicious': False,
            'tool_signatures': []
        }
        
        probability = scanner._calculate_steganography_probability(low_prob_analysis)
        assert probability <= 0.3  # Low probability
    
    def test_extract_hidden_data(self):
        """Test hidden data extraction"""
        scanner = SteganographyScanner()
        
        with patch('subprocess.run') as mock_subprocess:
            # Mock successful steghide extraction
            mock_subprocess.return_value.returncode = 0
            mock_subprocess.return_value.stdout = b'Hidden message extracted successfully'
            
            result = scanner._extract_hidden_data('/tmp/test.jpg', 'steghide')
            
            assert 'extraction_successful' in result
            assert 'extracted_data' in result
            assert 'extraction_method' in result
    
    def test_analyze_container_capacity(self):
        """Test container capacity analysis"""
        scanner = SteganographyScanner()
        
        with patch('PIL.Image.open') as mock_pil:
            mock_image = MagicMock()
            mock_image.size = (1920, 1080)
            mock_image.mode = 'RGB'
            mock_pil.return_value = mock_image
            
            result = scanner._analyze_container_capacity('/tmp/test.jpg')
            
            assert 'max_capacity_bytes' in result
            assert 'lsb_capacity' in result
            assert 'compression_ratio' in result
            assert result['max_capacity_bytes'] > 0


def mock_open_binary(data):
    """Mock open() for binary data"""
    def mock_open_func(filename, mode='rb'):
        if 'b' in mode:
            return MagicMock(read=lambda: data)
        return MagicMock(read=lambda: data.decode('utf-8'))
    return mock_open_func


if __name__ == "__main__":
    pytest.main([__file__, "-v"])