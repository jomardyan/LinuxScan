"""
System Check Module - Verify system dependencies and components
"""

import os
import sys
import subprocess
import shutil
import importlib
import platform
import getpass
from typing import Dict, List, Tuple, Optional, Any
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.text import Text
import pkg_resources
from .base_scanner import BaseScannerModule

console = Console()

class SystemCheckModule(BaseScannerModule):
    """System dependency and component verification module"""
    
    # System dependencies required for various modules
    SYSTEM_DEPENDENCIES = {
        'nmap': {
            'command': 'nmap',
            'description': 'Network mapper for port scanning',
            'required_for': ['port_scanner', 'network_scanner', 'vulnerability_scanner'],
            'install_commands': {
                'debian': 'sudo apt-get update && sudo apt-get install -y nmap',
                'ubuntu': 'sudo apt-get update && sudo apt-get install -y nmap',
                'centos': 'sudo yum install -y nmap',
                'rhel': 'sudo yum install -y nmap',
                'fedora': 'sudo dnf install -y nmap',
                'arch': 'sudo pacman -S nmap',
                'macos': 'brew install nmap'
            }
        },
        'tcpdump': {
            'command': 'tcpdump',
            'description': 'Network packet analyzer',
            'required_for': ['network_scanner', 'forensics_scanner'],
            'install_commands': {
                'debian': 'sudo apt-get update && sudo apt-get install -y tcpdump',
                'ubuntu': 'sudo apt-get update && sudo apt-get install -y tcpdump',
                'centos': 'sudo yum install -y tcpdump',
                'rhel': 'sudo yum install -y tcpdump',
                'fedora': 'sudo dnf install -y tcpdump',
                'arch': 'sudo pacman -S tcpdump',
                'macos': 'brew install tcpdump'
            }
        },
        'john': {
            'command': 'john',
            'description': 'John the Ripper password cracker',
            'required_for': ['ssh_scanner', 'vulnerability_scanner'],
            'install_commands': {
                'debian': 'sudo apt-get update && sudo apt-get install -y john',
                'ubuntu': 'sudo apt-get update && sudo apt-get install -y john',
                'centos': 'sudo yum install -y john',
                'rhel': 'sudo yum install -y john',
                'fedora': 'sudo dnf install -y john',
                'arch': 'sudo pacman -S john',
                'macos': 'brew install john'
            }
        },
        'hydra': {
            'command': 'hydra',
            'description': 'Network logon cracker',
            'required_for': ['ssh_scanner', 'web_scanner'],
            'install_commands': {
                'debian': 'sudo apt-get update && sudo apt-get install -y hydra',
                'ubuntu': 'sudo apt-get update && sudo apt-get install -y hydra',
                'centos': 'sudo yum install -y hydra',
                'rhel': 'sudo yum install -y hydra',
                'fedora': 'sudo dnf install -y hydra',
                'arch': 'sudo pacman -S hydra',
                'macos': 'brew install hydra'
            }
        },
        'sqlmap': {
            'command': 'sqlmap',
            'description': 'SQL injection testing tool',
            'required_for': ['web_scanner', 'database_scanner'],
            'install_commands': {
                'debian': 'sudo apt-get update && sudo apt-get install -y sqlmap',
                'ubuntu': 'sudo apt-get update && sudo apt-get install -y sqlmap',
                'centos': 'sudo yum install -y sqlmap',
                'rhel': 'sudo yum install -y sqlmap',
                'fedora': 'sudo dnf install -y sqlmap',
                'arch': 'sudo pacman -S sqlmap',
                'macos': 'brew install sqlmap'
            }
        },
        'nikto': {
            'command': 'nikto',
            'description': 'Web server scanner',
            'required_for': ['web_scanner'],
            'install_commands': {
                'debian': 'sudo apt-get update && sudo apt-get install -y nikto',
                'ubuntu': 'sudo apt-get update && sudo apt-get install -y nikto',
                'centos': 'sudo yum install -y nikto',
                'rhel': 'sudo yum install -y nikto',
                'fedora': 'sudo dnf install -y nikto',
                'arch': 'sudo pacman -S nikto',
                'macos': 'brew install nikto'
            }
        },
        'masscan': {
            'command': 'masscan',
            'description': 'High-speed port scanner',
            'required_for': ['port_scanner', 'network_scanner'],
            'install_commands': {
                'debian': 'sudo apt-get update && sudo apt-get install -y masscan',
                'ubuntu': 'sudo apt-get update && sudo apt-get install -y masscan',
                'centos': 'sudo yum install -y masscan',
                'rhel': 'sudo yum install -y masscan',
                'fedora': 'sudo dnf install -y masscan',
                'arch': 'sudo pacman -S masscan',
                'macos': 'brew install masscan'
            }
        },
        'clamav': {
            'command': 'clamscan',
            'description': 'ClamAV antivirus scanner',
            'required_for': ['malware_scanner'],
            'install_commands': {
                'debian': 'sudo apt-get update && sudo apt-get install -y clamav clamav-daemon',
                'ubuntu': 'sudo apt-get update && sudo apt-get install -y clamav clamav-daemon',
                'centos': 'sudo yum install -y clamav clamav-update',
                'rhel': 'sudo yum install -y clamav clamav-update',
                'fedora': 'sudo dnf install -y clamav clamav-update',
                'arch': 'sudo pacman -S clamav',
                'macos': 'brew install clamav'
            }
        },
        'yara': {
            'command': 'yara',
            'description': 'Pattern matching engine for malware detection',
            'required_for': ['malware_scanner', 'forensics_scanner'],
            'install_commands': {
                'debian': 'sudo apt-get update && sudo apt-get install -y yara',
                'ubuntu': 'sudo apt-get update && sudo apt-get install -y yara',
                'centos': 'sudo yum install -y yara',
                'rhel': 'sudo yum install -y yara',
                'fedora': 'sudo dnf install -y yara',
                'arch': 'sudo pacman -S yara',
                'macos': 'brew install yara'
            }
        },
        'hashcat': {
            'command': 'hashcat',
            'description': 'Advanced password recovery tool',
            'required_for': ['ssh_scanner', 'vulnerability_scanner'],
            'install_commands': {
                'debian': 'sudo apt-get update && sudo apt-get install -y hashcat',
                'ubuntu': 'sudo apt-get update && sudo apt-get install -y hashcat',
                'centos': 'sudo yum install -y hashcat',
                'rhel': 'sudo yum install -y hashcat',
                'fedora': 'sudo dnf install -y hashcat',
                'arch': 'sudo pacman -S hashcat',
                'macos': 'brew install hashcat'
            }
        }
    }
    
    # Python packages required for various modules
    PYTHON_DEPENDENCIES = {
        'nmap': {
            'package': 'python-nmap',
            'import_name': 'nmap',
            'description': 'Python wrapper for nmap',
            'required_for': ['port_scanner', 'network_scanner']
        },
        'paramiko': {
            'package': 'paramiko',
            'import_name': 'paramiko',
            'description': 'SSH client library',
            'required_for': ['ssh_scanner', 'vulnerability_scanner']
        },
        'scapy': {
            'package': 'scapy',
            'import_name': 'scapy',
            'description': 'Network packet manipulation library',
            'required_for': ['network_scanner', 'forensics_scanner']
        },
        'yara': {
            'package': 'yara-python',
            'import_name': 'yara',
            'description': 'Python bindings for YARA',
            'required_for': ['malware_scanner', 'forensics_scanner']
        },
        'beautifulsoup4': {
            'package': 'beautifulsoup4',
            'import_name': 'bs4',
            'description': 'HTML/XML parser for web scanning',
            'required_for': ['web_scanner']
        },
        'requests': {
            'package': 'requests',
            'import_name': 'requests',
            'description': 'HTTP library for web scanning',
            'required_for': ['web_scanner', 'vulnerability_scanner']
        },
        'cryptography': {
            'package': 'cryptography',
            'import_name': 'cryptography',
            'description': 'Cryptographic recipes and primitives',
            'required_for': ['ssh_scanner', 'network_scanner']
        },
        'mysql-connector': {
            'package': 'mysql-connector-python',
            'import_name': 'mysql.connector',
            'description': 'MySQL database connector',
            'required_for': ['database_scanner']
        },
        'psycopg2': {
            'package': 'psycopg2-binary',
            'import_name': 'psycopg2',
            'description': 'PostgreSQL database connector',
            'required_for': ['database_scanner']
        },
        'pymongo': {
            'package': 'pymongo',
            'import_name': 'pymongo',
            'description': 'MongoDB connector',
            'required_for': ['database_scanner']
        },
        'redis': {
            'package': 'redis',
            'import_name': 'redis',
            'description': 'Redis connector',
            'required_for': ['database_scanner']
        },
        'dnspython': {
            'package': 'dnspython',
            'import_name': 'dns',
            'description': 'DNS toolkit',
            'required_for': ['network_scanner']
        },
        'volatility3': {
            'package': 'volatility3',
            'import_name': 'volatility3',
            'description': 'Memory forensics framework',
            'required_for': ['forensics_scanner']
        },
        'python-magic': {
            'package': 'python-magic',
            'import_name': 'magic',
            'description': 'File type identification library',
            'required_for': ['forensics_scanner', 'malware_scanner']
        }
    }
    
    def __init__(self):
        super().__init__("system_check")
        self.distro = self._detect_distro()
        
    def _detect_distro(self) -> str:
        """Detect the Linux distribution"""
        try:
            # Check for common distro files
            if os.path.exists('/etc/os-release'):
                with open('/etc/os-release', 'r') as f:
                    content = f.read().lower()
                    if 'ubuntu' in content:
                        return 'ubuntu'
                    elif 'debian' in content:
                        return 'debian'
                    elif 'centos' in content:
                        return 'centos'
                    elif 'rhel' in content or 'red hat' in content:
                        return 'rhel'
                    elif 'fedora' in content:
                        return 'fedora'
                    elif 'arch' in content:
                        return 'arch'
            
            # Fallback to platform detection
            system = platform.system().lower()
            if system == 'darwin':
                return 'macos'
            elif system == 'linux':
                return 'debian'  # Default fallback
            else:
                return 'unknown'
                
        except Exception:
            return 'unknown'
    
    def check_system_dependency(self, dep_name: str) -> Tuple[bool, str]:
        """Check if a system dependency is installed"""
        if dep_name not in self.SYSTEM_DEPENDENCIES:
            return False, f"Unknown dependency: {dep_name}"
        
        dep_info = self.SYSTEM_DEPENDENCIES[dep_name]
        command = dep_info['command']
        
        # Check if command exists
        if shutil.which(command):
            try:
                # Try to run the command to verify it works
                result = subprocess.run([command, '--version'], 
                                      capture_output=True, 
                                      text=True, 
                                      timeout=10)  # Add timeout
                if result.returncode == 0:
                    return True, f"{command} is installed and working"
                else:
                    # Try alternative version check
                    result = subprocess.run([command, '-h'], 
                                          capture_output=True, 
                                          text=True, 
                                          timeout=10)
                    if result.returncode == 0:
                        return True, f"{command} is installed and working"
                    else:
                        # Some tools like masscan return non-zero exit codes but still work
                        # Check if the command exists and can be executed
                        try:
                            result = subprocess.run([command, '--help'], 
                                                  capture_output=True, 
                                                  text=True, 
                                                  timeout=10)
                            # If we get output, the command is working
                            if result.stdout or result.stderr:
                                return True, f"{command} is installed and working"
                            else:
                                return False, f"{command} is installed but not working properly"
                        except:
                            return False, f"{command} is installed but not working properly"
            except subprocess.TimeoutExpired:
                return False, f"{command} is installed but timed out during verification"
            except FileNotFoundError:
                return False, f"{command} is not installed"
        else:
            return False, f"{command} is not installed"
    
    def check_python_dependency(self, dep_name: str) -> Tuple[bool, str]:
        """Check if a Python dependency is installed"""
        if dep_name not in self.PYTHON_DEPENDENCIES:
            return False, f"Unknown Python dependency: {dep_name}"
        
        dep_info = self.PYTHON_DEPENDENCIES[dep_name]
        import_name = dep_info['import_name']
        
        try:
            importlib.import_module(import_name)
            return True, f"{dep_info['package']} is installed"
        except ImportError:
            return False, f"{dep_info['package']} is not installed"
    
    def get_install_command(self, dep_name: str) -> Optional[str]:
        """Get the install command for a system dependency"""
        if dep_name not in self.SYSTEM_DEPENDENCIES:
            return None
        
        dep_info = self.SYSTEM_DEPENDENCIES[dep_name]
        return dep_info['install_commands'].get(self.distro)
    
    def check_all_dependencies(self, modules: List[str] = None) -> Dict[str, Any]:
        """Check all dependencies for specified modules"""
        if modules is None:
            modules = ['port_scanner', 'vulnerability_scanner', 'network_scanner', 
                      'web_scanner', 'config_scanner', 'malware_scanner', 
                      'database_scanner', 'forensics_scanner', 'ssh_scanner']
        
        results = {
            'system_dependencies': {},
            'python_dependencies': {},
            'missing_system': [],
            'missing_python': [],
            'modules_affected': {},
            'install_commands': []
        }
        
        # Check system dependencies
        for dep_name, dep_info in self.SYSTEM_DEPENDENCIES.items():
            if any(mod in dep_info['required_for'] for mod in modules):
                is_installed, message = self.check_system_dependency(dep_name)
                results['system_dependencies'][dep_name] = {
                    'installed': is_installed,
                    'message': message,
                    'required_for': dep_info['required_for'],
                    'description': dep_info['description']
                }
                
                if not is_installed:
                    results['missing_system'].append(dep_name)
                    install_cmd = self.get_install_command(dep_name)
                    if install_cmd:
                        results['install_commands'].append(install_cmd)
        
        # Check Python dependencies
        for dep_name, dep_info in self.PYTHON_DEPENDENCIES.items():
            if any(mod in dep_info['required_for'] for mod in modules):
                is_installed, message = self.check_python_dependency(dep_name)
                results['python_dependencies'][dep_name] = {
                    'installed': is_installed,
                    'message': message,
                    'required_for': dep_info['required_for'],
                    'description': dep_info['description'],
                    'package': dep_info['package']
                }
                
                if not is_installed:
                    results['missing_python'].append(dep_name)
        
        # Determine which modules are affected
        for module in modules:
            missing_deps = []
            for dep_name, dep_result in results['system_dependencies'].items():
                if module in dep_result['required_for'] and not dep_result['installed']:
                    missing_deps.append(dep_name)
            for dep_name, dep_result in results['python_dependencies'].items():
                if module in dep_result['required_for'] and not dep_result['installed']:
                    missing_deps.append(dep_name)
            
            if missing_deps:
                results['modules_affected'][module] = missing_deps
        
        return results
    
    def display_dependency_status(self, results: Dict[str, Any]):
        """Display dependency status in a formatted table"""
        console.print(Panel.fit("🔍 [bold cyan]System Dependencies Check[/bold cyan]", 
                               border_style="cyan"))
        
        # System dependencies table
        if results['system_dependencies']:
            sys_table = Table(title="System Dependencies", show_header=True, 
                            header_style="bold magenta")
            sys_table.add_column("Dependency", style="cyan")
            sys_table.add_column("Status", justify="center")
            sys_table.add_column("Required For", style="yellow")
            sys_table.add_column("Description", style="dim")
            
            for dep_name, dep_info in results['system_dependencies'].items():
                status = "✅ Installed" if dep_info['installed'] else "❌ Missing"
                status_style = "green" if dep_info['installed'] else "red"
                
                sys_table.add_row(
                    dep_name,
                    Text(status, style=status_style),
                    ", ".join(dep_info['required_for']),
                    dep_info['description']
                )
            
            console.print(sys_table)
            console.print()
        
        # Python dependencies table
        if results['python_dependencies']:
            py_table = Table(title="Python Dependencies", show_header=True, 
                           header_style="bold magenta")
            py_table.add_column("Package", style="cyan")
            py_table.add_column("Status", justify="center")
            py_table.add_column("Required For", style="yellow")
            py_table.add_column("Description", style="dim")
            
            for dep_name, dep_info in results['python_dependencies'].items():
                status = "✅ Installed" if dep_info['installed'] else "❌ Missing"
                status_style = "green" if dep_info['installed'] else "red"
                
                py_table.add_row(
                    dep_info['package'],
                    Text(status, style=status_style),
                    ", ".join(dep_info['required_for']),
                    dep_info['description']
                )
            
            console.print(py_table)
            console.print()
        
        # Affected modules
        if results['modules_affected']:
            console.print(Panel.fit("⚠️ [bold red]Modules with Missing Dependencies[/bold red]", 
                                   border_style="red"))
            
            for module, missing_deps in results['modules_affected'].items():
                console.print(f"• [bold yellow]{module}[/bold yellow]: {', '.join(missing_deps)}")
            console.print()
        
        # Summary
        total_sys = len(results['system_dependencies'])
        missing_sys = len(results['missing_system'])
        total_py = len(results['python_dependencies'])
        missing_py = len(results['missing_python'])
        
        summary_text = f"""
System Dependencies: {total_sys - missing_sys}/{total_sys} installed
Python Dependencies: {total_py - missing_py}/{total_py} installed
Affected Modules: {len(results['modules_affected'])}
        """
        
        console.print(Panel.fit(summary_text, title="📊 Summary", border_style="blue"))
    
    def install_missing_dependencies(self, results: Dict[str, Any], 
                                   interactive: bool = True) -> bool:
        """Install missing dependencies with user confirmation"""
        if not results['missing_system'] and not results['missing_python']:
            console.print("✅ [green]All dependencies are already installed![/green]")
            return True
        
        console.print(Panel.fit("🔧 [bold yellow]Installing Missing Dependencies[/bold yellow]", 
                               border_style="yellow"))
        
        success = True
        
        # Install system dependencies
        if results['missing_system']:
            console.print(f"📦 Found {len(results['missing_system'])} missing system dependencies")
            
            if interactive:
                install_sys = console.input("Install missing system dependencies? [y/N]: ").lower() == 'y'
            else:
                install_sys = True
            
            if install_sys:
                for cmd in results['install_commands']:
                    console.print(f"🔧 Running: {cmd}")
                    try:
                        if 'sudo' in cmd:
                            # Handle sudo password prompt
                            console.print("🔐 [yellow]Administrator privileges required[/yellow]")
                        
                        # Add timeout to prevent hanging
                        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=120)
                        if result.returncode == 0:
                            console.print("✅ [green]Success[/green]")
                        else:
                            console.print(f"❌ [red]Failed: {result.stderr.strip() if result.stderr else 'Command failed'}[/red]")
                            success = False
                    except subprocess.TimeoutExpired:
                        console.print("❌ [red]Installation timed out (120 seconds)[/red]")
                        success = False
                    except Exception as e:
                        console.print(f"❌ [red]Error: {e}[/red]")
                        success = False
        
        # Install Python dependencies
        if results['missing_python']:
            console.print(f"🐍 Found {len(results['missing_python'])} missing Python packages")
            
            if interactive:
                install_py = console.input("Install missing Python packages? [y/N]: ").lower() == 'y'
            else:
                install_py = True
            
            if install_py:
                missing_packages = []
                for dep_name in results['missing_python']:
                    if dep_name in self.PYTHON_DEPENDENCIES:
                        missing_packages.append(self.PYTHON_DEPENDENCIES[dep_name]['package'])
                
                if missing_packages:
                    cmd = f"pip3 install {' '.join(missing_packages)}"
                    console.print(f"🔧 Running: {cmd}")
                    try:
                        # Add timeout to prevent hanging
                        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300)
                        if result.returncode == 0:
                            console.print("✅ [green]Python packages installed successfully[/green]")
                        else:
                            console.print(f"❌ [red]Failed to install Python packages: {result.stderr.strip() if result.stderr else 'Command failed'}[/red]")
                            success = False
                    except subprocess.TimeoutExpired:
                        console.print("❌ [red]Python package installation timed out (300 seconds)[/red]")
                        success = False
                    except Exception as e:
                        console.print(f"❌ [red]Error installing Python packages: {e}[/red]")
                        success = False
        
        return success
    
    async def scan(self, target: str = None, modules: List[str] = None, 
                   auto_install: bool = False, **kwargs) -> Dict[str, Any]:
        """Perform system check and optionally install missing dependencies"""
        console.print(Panel.fit("🔍 [bold cyan]LinuxScan System Check[/bold cyan]", 
                               border_style="cyan"))
        
        results = self.check_all_dependencies(modules)
        self.display_dependency_status(results)
        
        if auto_install and (results['missing_system'] or results['missing_python']):
            self.install_missing_dependencies(results, interactive=False)
            # Re-check after installation
            results = self.check_all_dependencies(modules)
            console.print("\n" + "="*50)
            console.print("🔍 [bold cyan]Post-Installation Check[/bold cyan]")
            console.print("="*50)
            self.display_dependency_status(results)
        
        return results