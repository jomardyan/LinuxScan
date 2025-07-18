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
Steganography Detection Scanner
Advanced steganography detection and analysis module
"""

import asyncio
import os
import hashlib
import subprocess
import tempfile
from typing import Dict, List, Any, Optional
from datetime import datetime
from .base_scanner import BaseScannerModule


class SteganographyScanner(BaseScannerModule):
    """Advanced steganography detection and analysis scanner"""
    
    def __init__(self, timeout: int = 300):
        super().__init__("steganography_scanner", timeout)
        self.supported_formats = ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.wav', '.mp3', '.pdf']
        self.tools = {
            'steghide': 'steghide extract -sf {} -p {} -xf {}',
            'stegdetect': 'stegdetect {}',
            'binwalk': 'binwalk -e {}',
            'exiftool': 'exiftool {}',
            'strings': 'strings {} | grep -i "hidden\\|secret\\|password\\|key"'
        }
    
    async def scan(self, target: str, **kwargs) -> Dict[str, Any]:
        """Perform steganography detection scan"""
        self.log_scan_start(target)
        
        # Enhanced target info with reverse DNS
        target_info = self.enhance_target_info(target)
        
        results = {
            'target_info': target_info,
            'scan_type': 'steganography_detection',
            'timestamp': datetime.now().isoformat(),
            'findings': [],
            'suspicious_files': [],
            'metadata_analysis': [],
            'entropy_analysis': [],
            'tool_results': {}
        }
        
        try:
            # If target is a file path, analyze directly
            if os.path.isfile(target):
                await self._analyze_file(target, results)
            else:
                # If target is a URL or directory, attempt to download/scan
                await self._analyze_remote_target(target, results)
                
        except Exception as e:
            results['error'] = str(e)
            self.logger.error(f"Error in steganography scan: {e}")
        
        self.log_scan_end(target)
        return results
    
    async def _analyze_file(self, filepath: str, results: Dict[str, Any]):
        """Analyze a single file for steganography"""
        file_ext = os.path.splitext(filepath)[1].lower()
        
        if file_ext not in self.supported_formats:
            results['findings'].append(f"Unsupported file format: {file_ext}")
            return
        
        file_info = {
            'filename': os.path.basename(filepath),
            'size': os.path.getsize(filepath),
            'md5': self._calculate_md5(filepath),
            'format': file_ext,
            'suspicious_indicators': []
        }
        
        # Entropy analysis
        entropy_score = await self._calculate_entropy(filepath)
        file_info['entropy'] = entropy_score
        
        if entropy_score > 7.5:
            file_info['suspicious_indicators'].append("High entropy suggests possible hidden data")
        
        # Metadata analysis
        metadata = await self._extract_metadata(filepath)
        file_info['metadata'] = metadata
        
        # Check for suspicious metadata
        suspicious_metadata = self._check_suspicious_metadata(metadata)
        if suspicious_metadata:
            file_info['suspicious_indicators'].extend(suspicious_metadata)
        
        # Tool-based analysis
        for tool_name, tool_cmd in self.tools.items():
            if await self._check_tool_available(tool_name):
                tool_result = await self._run_tool_analysis(tool_name, filepath)
                results['tool_results'][tool_name] = tool_result
        
        results['suspicious_files'].append(file_info)
    
    async def _analyze_remote_target(self, target: str, results: Dict[str, Any]):
        """Analyze remote target for steganography"""
        # This would implement remote file discovery and analysis
        # For now, we'll focus on local analysis
        results['findings'].append(f"Remote steganography analysis not yet implemented for {target}")
    
    def _calculate_md5(self, filepath: str) -> str:
        """Calculate MD5 hash of file"""
        hash_md5 = hashlib.md5()
        try:
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_md5.update(chunk)
            return hash_md5.hexdigest()
        except Exception:
            return "error_calculating_hash"
    
    async def _calculate_entropy(self, filepath: str) -> float:
        """Calculate entropy of file to detect randomness"""
        try:
            import math
            from collections import Counter
            
            with open(filepath, 'rb') as f:
                data = f.read()
            
            if not data:
                return 0.0
            
            # Calculate byte frequency
            byte_counts = Counter(data)
            entropy = 0.0
            
            for count in byte_counts.values():
                probability = count / len(data)
                entropy -= probability * math.log2(probability)
            
            return entropy
        except Exception:
            return 0.0
    
    async def _extract_metadata(self, filepath: str) -> Dict[str, Any]:
        """Extract metadata from file"""
        metadata = {}
        try:
            if await self._check_tool_available('exiftool'):
                cmd = ['exiftool', '-json', filepath]
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=30)
                
                if process.returncode == 0:
                    import json
                    metadata = json.loads(stdout.decode())
                    if isinstance(metadata, list) and len(metadata) > 0:
                        metadata = metadata[0]
        except Exception as e:
            metadata['error'] = str(e)
        
        return metadata
    
    def _check_suspicious_metadata(self, metadata: Dict[str, Any]) -> List[str]:
        """Check for suspicious metadata indicators"""
        suspicious = []
        
        # Check for unusual comments or descriptions
        suspicious_fields = ['Comment', 'Description', 'UserComment', 'ImageDescription']
        for field in suspicious_fields:
            if field in metadata:
                value = str(metadata[field]).lower()
                if any(keyword in value for keyword in ['hidden', 'secret', 'password', 'key', 'encrypted']):
                    suspicious.append(f"Suspicious {field}: {metadata[field]}")
        
        # Check for unusual software or tools
        if 'Software' in metadata:
            software = str(metadata['Software']).lower()
            stego_tools = ['steghide', 'outguess', 'stegdetect', 'jsteg']
            for tool in stego_tools:
                if tool in software:
                    suspicious.append(f"File processed with steganography tool: {tool}")
        
        return suspicious
    
    async def _check_tool_available(self, tool_name: str) -> bool:
        """Check if steganography tool is available"""
        try:
            process = await asyncio.create_subprocess_exec(
                'which', tool_name,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await asyncio.wait_for(process.communicate(), timeout=5)
            return process.returncode == 0
        except Exception:
            return False
    
    async def _run_tool_analysis(self, tool_name: str, filepath: str) -> Dict[str, Any]:
        """Run specific steganography tool analysis"""
        result = {
            'tool': tool_name,
            'output': '',
            'error': '',
            'returncode': -1
        }
        
        try:
            if tool_name == 'steghide':
                # Try to extract without password first
                cmd = ['steghide', 'extract', '-sf', filepath, '-p', '', '-xf', '/dev/null']
            elif tool_name == 'stegdetect':
                cmd = ['stegdetect', filepath]
            elif tool_name == 'binwalk':
                cmd = ['binwalk', '-e', filepath]
            elif tool_name == 'strings':
                cmd = ['strings', filepath]
            else:
                cmd = [tool_name, filepath]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=60)
            
            result['output'] = stdout.decode('utf-8', errors='ignore')
            result['error'] = stderr.decode('utf-8', errors='ignore')
            result['returncode'] = process.returncode
            
        except Exception as e:
            result['error'] = str(e)
        

    async def _file_discovery(self, *args, **kwargs):
        """Stub method for _file_discovery"""
        return {'status': 'not_implemented', 'method': '_file_discovery'}

    async def _statistical_analysis(self, *args, **kwargs):
        """Stub method for _statistical_analysis"""
        return {'status': 'not_implemented', 'method': '_statistical_analysis'}

    async def _detect_steganography_tools(self, *args, **kwargs):
        """Stub method for _detect_steganography_tools"""
        return {'status': 'not_implemented', 'method': '_detect_steganography_tools'}

    async def _lsb_analysis(self, *args, **kwargs):
        """Stub method for _lsb_analysis"""
        return {'status': 'not_implemented', 'method': '_lsb_analysis'}

    async def _detect_hidden_archives(self, *args, **kwargs):
        """Stub method for _detect_hidden_archives"""
        return {'status': 'not_implemented', 'method': '_detect_hidden_archives'}

    def _analyze_audio_steganography(self, *args, **kwargs):
        """Stub method for _analyze_audio_steganography"""
        return {'status': 'not_implemented', 'method': '_analyze_audio_steganography'}

    async def _pdf_steganography_analysis(self, *args, **kwargs):
        """Stub method for _pdf_steganography_analysis"""
        return {'status': 'not_implemented', 'method': '_pdf_steganography_analysis'}

    async def _frequency_analysis(self, *args, **kwargs):
        """Stub method for _frequency_analysis"""
        return {'status': 'not_implemented', 'method': '_frequency_analysis'}

    def _generate_stego_report(self, *args, **kwargs):
        """Stub method for _generate_stego_report"""
        return {'status': 'not_implemented', 'method': '_generate_stego_report'}

    def _calculate_steganography_probability(self, *args, **kwargs):
        """Stub method for _calculate_steganography_probability"""
        return {'status': 'not_implemented', 'method': '_calculate_steganography_probability'}

    async def _extract_hidden_data(self, *args, **kwargs):
        """Stub method for _extract_hidden_data"""
        return {'status': 'not_implemented', 'method': '_extract_hidden_data'}

    async def _file_discovery(self, *args, **kwargs):
        """Stub method for _file_discovery"""
        return {'status': 'not_implemented', 'method': '_file_discovery'}

    async def _statistical_analysis(self, *args, **kwargs):
        """Stub method for _statistical_analysis"""
        return {'status': 'not_implemented', 'method': '_statistical_analysis'}

    async def _detect_steganography_tools(self, *args, **kwargs):
        """Stub method for _detect_steganography_tools"""
        return {'status': 'not_implemented', 'method': '_detect_steganography_tools'}

    async def _lsb_analysis(self, *args, **kwargs):
        """Stub method for _lsb_analysis"""
        return {'status': 'not_implemented', 'method': '_lsb_analysis'}

    async def _detect_hidden_archives(self, *args, **kwargs):
        """Stub method for _detect_hidden_archives"""
        return {'status': 'not_implemented', 'method': '_detect_hidden_archives'}

    def _analyze_audio_steganography(self, *args, **kwargs):
        """Stub method for _analyze_audio_steganography"""
        return {'status': 'not_implemented', 'method': '_analyze_audio_steganography'}

    async def _pdf_steganography_analysis(self, *args, **kwargs):
        """Stub method for _pdf_steganography_analysis"""
        return {'status': 'not_implemented', 'method': '_pdf_steganography_analysis'}

    async def _frequency_analysis(self, *args, **kwargs):
        """Stub method for _frequency_analysis"""
        return {'status': 'not_implemented', 'method': '_frequency_analysis'}

    def _generate_stego_report(self, *args, **kwargs):
        """Stub method for _generate_stego_report"""
        return {'status': 'not_implemented', 'method': '_generate_stego_report'}

    def _calculate_steganography_probability(self, *args, **kwargs):
        """Stub method for _calculate_steganography_probability"""
        return {'status': 'not_implemented', 'method': '_calculate_steganography_probability'}

    async def _extract_hidden_data(self, *args, **kwargs):
        """Stub method for _extract_hidden_data"""
        return {'status': 'not_implemented', 'method': '_extract_hidden_data'}
        return result