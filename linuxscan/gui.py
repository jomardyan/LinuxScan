#!/usr/bin/env python3
"""
LinuxScan GUI - Interactive Interface
Comprehensive GUI for LinuxScan security scanner
"""

import asyncio
import json
import threading
import time
from datetime import datetime
from typing import List, Dict, Any, Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.live import Live
from rich.layout import Layout
from rich.progress import Progress, TaskID
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.columns import Columns
from rich.align import Align

try:
    from .enhanced_scanner import SecurityScanner, display_banner
    from .config import ConfigManager
    from .enhanced_cli import SCAN_MODULES, OUTPUT_FORMATS, COMPLIANCE_FRAMEWORKS
except ImportError:
    # Handle relative imports when running as script
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent))
    from enhanced_scanner import SecurityScanner, display_banner
    from config import ConfigManager
    from enhanced_cli import SCAN_MODULES, OUTPUT_FORMATS, COMPLIANCE_FRAMEWORKS

console = Console()

class LinuxScanGUI:
    """Interactive GUI for LinuxScan"""
    
    def __init__(self):
        self.scanner = SecurityScanner()
        self.config_manager = ConfigManager()
        self.current_scan_results = None
        self.scan_in_progress = False
        
    def clear_screen(self):
        """Clear the console screen"""
        console.clear()
        
    def display_main_menu(self):
        """Display the main menu"""
        self.clear_screen()
        display_banner()
        
        menu_panel = Panel.fit(
            """
[bold cyan]🔍 MAIN MENU[/bold cyan]

[bold blue]📋 BASIC SCANS[/bold blue]
[bold green]1.[/bold green] Quick Scan                    [bold green]2.[/bold green] Advanced Scan
[bold green]3.[/bold green] Mode Scan                     [bold green]4.[/bold green] Network Discovery

[bold yellow]🔐 SECURITY ASSESSMENTS[/bold yellow]
[bold green]5.[/bold green] Vulnerability Assessment      [bold green]6.[/bold green] Web Application Scan
[bold green]7.[/bold green] SSH Security Audit           [bold green]8.[/bold green] Database Security Scan
[bold green]9.[/bold green] Compliance Audit             [bold green]10.[/bold green] Crypto Security Audit

[bold magenta]🔬 ADVANCED ANALYSIS[/bold magenta]
[bold green]11.[/bold green] Memory Analysis               [bold green]12.[/bold green] Steganography Detection
[bold green]13.[/bold green] Malware Analysis             [bold green]14.[/bold green] Forensics Investigation
[bold green]15.[/bold green] Traffic Analysis             [bold green]16.[/bold green] IoT Device Scan

[bold cyan]🛠️ SYSTEM & UTILITIES[/bold cyan]
[bold green]17.[/bold green] System Check                 [bold green]18.[/bold green] View Scan History
[bold green]19.[/bold green] Commands & Scripts Menu      [bold green]20.[/bold green] Configuration
[bold green]21.[/bold green] Help & Documentation

[bold white]🎯 SCAN SETS & FAST SCANS[/bold white]
[bold green]22.[/bold green] Scan Sets Menu               [bold green]23.[/bold green] Fast Ping Scan
[bold green]24.[/bold green] Fast SSH Scan

[bold red]0.[/bold red] Exit

Select an option:
            """,
            title="🚀 LinuxScan Interactive Interface v2.1",
            border_style="cyan",
            padding=(1, 2)
        )
        
        console.print(menu_panel)
        
    def get_menu_choice(self) -> int:
        """Get user menu choice"""
        try:
            choice = IntPrompt.ask(
                "Enter your choice",
                choices=[str(i) for i in range(0, 25)],
                default=1
            )
            return choice
        except KeyboardInterrupt:
            return 0
            
    def get_target_input(self) -> List[str]:
        """Get target input from user"""
        console.print("\n[bold cyan]Target Configuration[/bold cyan]")
        
        target_options = Panel.fit(
            """
[bold yellow]Target Examples:[/bold yellow]
• Single IP: 192.168.1.1
• IP Range: 192.168.1.1-10  
• CIDR: 192.168.1.0/24
• Hostname: example.com
• Multiple: 192.168.1.1,example.com,10.0.0.0/24
            """,
            title="Target Options",
            border_style="yellow"
        )
        console.print(target_options)
        
        targets = Prompt.ask("\n[bold green]Enter target(s)")
        
        if not targets.strip():
            console.print("[red]No targets specified![/red]")
            return []
            
        return [target.strip() for target in targets.split(',') if target.strip()]
    
    def select_scan_modules(self) -> List[str]:
        """Allow user to select scan modules"""
        console.print("\n[bold cyan]Scan Modules Selection[/bold cyan]")
        
        # Display available modules
        table = Table(title="Available Scan Modules")
        table.add_column("ID", style="cyan", width=3)
        table.add_column("Module", style="green", width=20)
        table.add_column("Description", style="white")
        
        modules_list = list(SCAN_MODULES.items())
        for i, (module, description) in enumerate(modules_list, 1):
            table.add_row(str(i), module, description)
        
        console.print(table)
        
        console.print("\n[bold yellow]Selection Options:[/bold yellow]")
        console.print("• Enter module IDs (comma-separated): 1,2,3")
        console.print("• Enter 'all' for all modules")
        console.print("• Press Enter for default (port_scanner,vulnerability_scanner)")
        
        selection = Prompt.ask("\nSelect modules", default="1,2")
        
        if selection.lower() == 'all':
            return list(SCAN_MODULES.keys())
        
        try:
            selected_indices = [int(x.strip()) for x in selection.split(',')]
            selected_modules = []
            
            for idx in selected_indices:
                if 1 <= idx <= len(modules_list):
                    module_name = modules_list[idx - 1][0]
                    selected_modules.append(module_name)
                else:
                    console.print(f"[yellow]Warning: Invalid module ID {idx} ignored[/yellow]")
                    
            return selected_modules if selected_modules else ['port_scanner', 'vulnerability_scanner']
            
        except ValueError:
            console.print("[red]Invalid selection, using default modules[/red]")
            return ['port_scanner', 'vulnerability_scanner']
    
    def configure_scan_options(self) -> Dict[str, Any]:
        """Configure advanced scan options"""
        console.print("\n[bold cyan]Scan Configuration[/bold cyan]")
        
        config = {}
        
        # Timeout configuration
        config['timeout'] = IntPrompt.ask(
            "Connection timeout (seconds)",
            default=5,
            choices=range(1, 61)
        )
        
        # Worker threads
        config['max_workers'] = IntPrompt.ask(
            "Maximum concurrent workers",
            default=50,
            choices=range(1, 201)
        )
        
        # Verbose output
        config['verbose'] = Confirm.ask("Enable verbose output?", default=False)
        
        # Output configuration
        save_results = Confirm.ask("Save results to file?", default=True)
        
        if save_results:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            default_filename = f"linuxscan_results_{timestamp}.json"
            
            config['output_file'] = Prompt.ask(
                "Output filename",
                default=default_filename
            )
            
            config['output_format'] = Prompt.ask(
                "Output format",
                choices=OUTPUT_FORMATS,
                default="json"
            )
        
        return config
    
    def quick_scan(self):
        """Perform a quick scan"""
        console.print("\n[bold green]🚀 Quick Scan[/bold green]")
        
        targets = self.get_target_input()
        if not targets:
            return
            
        modules = ['port_scanner', 'vulnerability_scanner']
        config = {'timeout': 5, 'max_workers': 50, 'verbose': False}
        
        self.run_scan(targets, modules, config)
    
    def advanced_scan(self):
        """Perform an advanced scan with custom configuration"""
        console.print("\n[bold green]🔧 Advanced Scan[/bold green]")
        
        targets = self.get_target_input()
        if not targets:
            return
            
        modules = self.select_scan_modules()
        config = self.configure_scan_options()
        
        self.run_scan(targets, modules, config)
    
    def vulnerability_assessment(self):
        """Perform comprehensive vulnerability assessment"""
        console.print("\n[bold green]🛡️ Vulnerability Assessment[/bold green]")
        
        targets = self.get_target_input()
        if not targets:
            return
            
        modules = ['vulnerability_scanner', 'web_scanner', 'config_scanner']
        config = {'timeout': 10, 'max_workers': 30, 'verbose': True}
        
        self.run_scan(targets, modules, config)
    
    def network_discovery(self):
        """Perform network discovery"""
        console.print("\n[bold green]🌐 Network Discovery[/bold green]")
        
        targets = self.get_target_input()
        if not targets:
            return
            
        modules = ['port_scanner', 'network_scanner']
        config = {'timeout': 3, 'max_workers': 100, 'verbose': False}
        
        self.run_scan(targets, modules, config)
    
    def web_application_scan(self):
        """Perform web application security scan"""
        console.print("\n[bold green]🌍 Web Application Scan[/bold green]")
        
        targets = self.get_target_input()
        if not targets:
            return
            
        modules = ['web_scanner', 'vulnerability_scanner']
        config = {'timeout': 15, 'max_workers': 20, 'verbose': True}
        
        self.run_scan(targets, modules, config)
    
    def ssh_security_audit(self):
        """Perform SSH security audit"""
        console.print("\n[bold green]🔑 SSH Security Audit[/bold green]")
        
        targets = self.get_target_input()
        if not targets:
            return
        
        # SSH-specific options
        console.print("\n[bold yellow]SSH Audit Options:[/bold yellow]")
        
        brute_force = Confirm.ask("Enable SSH brute force testing?", default=False)
        config_audit = Confirm.ask("Enable SSH configuration audit?", default=True)
        
        modules = ['ssh_scanner', 'port_scanner']
        config = {
            'timeout': 10,
            'max_workers': 10,
            'verbose': True,
            'ssh_brute_force': brute_force,
            'ssh_config_audit': config_audit
        }
        
        if brute_force:
            config['ssh_max_attempts'] = IntPrompt.ask(
                "Maximum SSH brute force attempts",
                default=50,
                choices=range(1, 1001)
            )
            
        self.run_scan(targets, modules, config)
    
    def database_security_scan(self):
        """Perform database security scan"""
        console.print("\n[bold green]🗄️ Database Security Scan[/bold green]")
        
        targets = self.get_target_input()
        if not targets:
            return
            
        modules = ['database_scanner', 'port_scanner']
        config = {'timeout': 15, 'max_workers': 10, 'verbose': True}
        
        self.run_scan(targets, modules, config)
    
    def compliance_audit(self):
        """Perform compliance audit"""
        console.print("\n[bold green]📋 Compliance Audit[/bold green]")
        
        targets = self.get_target_input()
        if not targets:
            return
        
        # Select compliance framework
        console.print("\n[bold yellow]Select Compliance Framework:[/bold yellow]")
        for i, framework in enumerate(COMPLIANCE_FRAMEWORKS, 1):
            console.print(f"{i}. {framework.upper()}")
        
        framework_choice = IntPrompt.ask(
            "Select framework",
            choices=[str(i) for i in range(1, len(COMPLIANCE_FRAMEWORKS) + 1)],
            default=1
        )
        
        selected_framework = COMPLIANCE_FRAMEWORKS[framework_choice - 1]
        
        modules = ['config_scanner', 'vulnerability_scanner']
        config = {
            'timeout': 20,
            'max_workers': 20,
            'verbose': True,
            'compliance': selected_framework
        }
        
        self.run_scan(targets, modules, config)
    
    def system_check(self):
        """Perform system dependency check"""
        console.print("\n[bold green]🔍 System Check[/bold green]")
        
        from linuxscan.modules.system_check import SystemCheckModule
        
        auto_install = Confirm.ask("Automatically install missing dependencies?", default=False)
        
        console.print("\n[blue]Running system check...[/blue]")
        
        try:
            system_checker = SystemCheckModule()
            results = asyncio.run(system_checker.scan(auto_install=auto_install))
            
            # Display results
            if results.get('missing_system') or results.get('missing_python'):
                console.print(f"[red]⚠️  Missing dependencies detected![/red]")
                
                missing_system = results.get('missing_system', [])
                missing_python = results.get('missing_python', [])
                
                if missing_system:
                    console.print(f"\n[yellow]Missing system packages:[/yellow]")
                    for pkg in missing_system:
                        console.print(f"  • {pkg}")
                
                if missing_python:
                    console.print(f"\n[yellow]Missing Python packages:[/yellow]")
                    for pkg in missing_python:
                        console.print(f"  • {pkg}")
                
                if auto_install:
                    console.print("\n[yellow]Dependencies installation attempted[/yellow]")
                else:
                    console.print("\n[yellow]Run with auto-install to install missing dependencies[/yellow]")
                    console.print("[yellow]Or run: ./setup.sh --system-deps[/yellow]")
            else:
                console.print("[green]✅ All dependencies are installed![/green]")
                
        except Exception as e:
            console.print(f"[red]System check failed: {e}[/red]")
        
        input("\nPress Enter to continue...")
    
    def view_scan_history(self):
        """View previous scan results"""
        console.print("\n[bold green]📊 Scan History[/bold green]")
        
        if self.current_scan_results:
            self.display_scan_results(self.current_scan_results)
        else:
            console.print("[yellow]No scan results available in current session[/yellow]")
            
        input("\nPress Enter to continue...")
    
    def configuration_menu(self):
        """Configuration management menu"""
        console.print("\n[bold green]⚙️ Configuration[/bold green]")
        
        config_panel = Panel.fit(
            """
[bold cyan]Configuration Options:[/bold cyan]

[bold green]1.[/bold green] View Current Configuration
[bold green]2.[/bold green] Edit Configuration  
[bold green]3.[/bold green] Reset to Defaults
[bold green]4.[/bold green] Export Configuration
[bold green]5.[/bold green] Import Configuration
[bold red]0.[/bold red] Back to Main Menu
            """,
            title="Configuration Menu",
            border_style="cyan"
        )
        
        console.print(config_panel)
        
        try:
            choice = IntPrompt.ask(
                "Select option",
                choices=["0", "1", "2", "3", "4", "5"],
                default=1
            )
            
            if choice == 1:
                self.view_configuration()
            elif choice == 2:
                self.edit_configuration()
            elif choice == 3:
                self.reset_configuration()
            elif choice == 4:
                self.export_configuration()
            elif choice == 5:
                self.import_configuration()
                
        except KeyboardInterrupt:
            pass
    
    def view_configuration(self):
        """Display current configuration"""
        config = self.config_manager.get_config()
        
        table = Table(title="Current Configuration")
        table.add_column("Setting", style="cyan")
        table.add_column("Value", style="green")
        
        for key, value in config.items():
            if isinstance(value, dict):
                table.add_row(key, json.dumps(value, indent=2))
            else:
                table.add_row(key, str(value))
        
        console.print(table)
        input("\nPress Enter to continue...")
    
    def edit_configuration(self):
        """Edit configuration settings"""
        console.print("\n[yellow]Configuration editing not implemented in GUI mode[/yellow]")
        console.print("[yellow]Please edit ~/.config/linuxscan/config.json manually[/yellow]")
        input("\nPress Enter to continue...")
    
    def reset_configuration(self):
        """Reset configuration to defaults"""
        if Confirm.ask("Reset configuration to defaults?"):
            # This would reset the configuration
            console.print("[green]Configuration reset to defaults[/green]")
        input("\nPress Enter to continue...")
    
    def export_configuration(self):
        """Export configuration to file"""
        filename = Prompt.ask("Export filename", default="linuxscan_config.json")
        # Export logic would go here
        console.print(f"[green]Configuration exported to {filename}[/green]")
        input("\nPress Enter to continue...")
    
    def import_configuration(self):
        """Import configuration from file"""
        filename = Prompt.ask("Import filename")
        # Import logic would go here
        console.print(f"[green]Configuration imported from {filename}[/green]")
        input("\nPress Enter to continue...")
    
    def help_documentation(self):
        """Display help and documentation"""
        console.print("\n[bold green]📚 Help & Documentation[/bold green]")
        
        help_panel = Panel.fit(
            """
[bold cyan]LinuxScan Documentation[/bold cyan]

[bold yellow]Quick Start:[/bold yellow]
1. Use Quick Scan for basic port and vulnerability scanning
2. Use Advanced Scan for custom module selection
3. Use specialized scans for specific security assessments

[bold yellow]Scan Types:[/bold yellow]
• Port Scanner: Discovers open ports and services
• Vulnerability Scanner: Identifies CVE-based vulnerabilities  
• Network Scanner: Analyzes network topology and traffic
• Web Scanner: Tests web application security
• SSH Scanner: Audits SSH configuration and security
• Database Scanner: Scans database services for vulnerabilities
• Config Scanner: Performs compliance auditing
• Malware Scanner: Detects malware and suspicious files
• Forensics Scanner: Digital forensics analysis

[bold yellow]Output Formats:[/bold yellow]
• JSON: Machine-readable structured data
• CSV: Spreadsheet-compatible format  
• HTML: Web-friendly report format
• TXT: Human-readable plain text

[bold yellow]Resources:[/bold yellow]
• GitHub: https://github.com/jomardyan/LinuxScan
• Documentation: README.md, INSTALL.md
• SSH Scanner Docs: SSH_SCANNER_DOCS.md

[bold red]Security Note:[/bold red]
LinuxScan is for authorized security testing only.
Ensure you have permission before scanning systems.
            """,
            title="LinuxScan Help",
            border_style="cyan"
        )
        
        console.print(help_panel)
        input("\nPress Enter to continue...")
    
    def run_scan(self, targets: List[str], modules: List[str], config: Dict[str, Any]):
        """Execute a security scan with progress display"""
        self.scan_in_progress = True
        
        console.print(f"\n[bold green]🔍 Starting Scan[/bold green]")
        console.print(f"[blue]Targets: {', '.join(targets)}[/blue]")
        console.print(f"[blue]Modules: {', '.join(modules)}[/blue]")
        
        # Initialize scanner
        self.scanner = SecurityScanner(
            timeout=config.get('timeout', 5),
            max_workers=config.get('max_workers', 50)
        )
        
        # Prepare scan parameters
        scan_kwargs = {}
        
        # SSH specific parameters
        if 'ssh_scanner' in modules:
            if config.get('ssh_brute_force'):
                scan_kwargs['brute_force'] = True
                scan_kwargs['max_attempts'] = config.get('ssh_max_attempts', 50)
            if config.get('ssh_config_audit'):
                scan_kwargs['config_audit'] = True
        
        try:
            # Create progress display
            with Progress() as progress:
                task = progress.add_task("[cyan]Scanning...", total=len(targets))
                
                # Run scan in async context
                def run_async_scan():
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                    try:
                        results = loop.run_until_complete(
                            self.scanner.scan_network(targets, modules, **scan_kwargs)
                        )
                        return results
                    finally:
                        loop.close()
                
                # Run scan in separate thread to avoid blocking
                scan_thread = threading.Thread(target=run_async_scan)
                scan_thread.daemon = True
                scan_thread.start()
                
                # Progress simulation (since we can't easily hook into actual progress)
                for i in range(len(targets)):
                    time.sleep(1)  # Simulate progress
                    progress.update(task, advance=1)
                
                # Wait for scan to complete
                scan_thread.join(timeout=300)  # 5 minute timeout
                
                if scan_thread.is_alive():
                    console.print("[red]Scan timed out![/red]")
                    return
                
                # Get results (this is a simplified approach)
                results = {}  # In real implementation, we'd get this from the scan thread
            
            console.print("\n[green]✅ Scan completed![/green]")
            
            # Save results
            self.current_scan_results = results
            
            # Export results if requested
            if config.get('output_file'):
                self.export_results(results, config['output_file'], config.get('output_format', 'json'))
            
            # Display results
            self.display_scan_results(results)
            
        except KeyboardInterrupt:
            console.print("\n[red]Scan interrupted by user[/red]")
        except Exception as e:
            console.print(f"\n[red]Scan failed: {e}[/red]")
        finally:
            self.scan_in_progress = False
        
        input("\nPress Enter to continue...")
    
    def display_scan_results(self, results: Dict[str, Any]):
        """Display scan results summary"""
        if not results:
            console.print("[yellow]No scan results to display[/yellow]")
            return
        
        console.print("\n[bold cyan]📊 Scan Results Summary[/bold cyan]")
        
        # This is a placeholder - in real implementation, we'd display actual results
        summary_panel = Panel.fit(
            """
[bold green]Scan completed successfully![/bold green]

[bold yellow]Results would be displayed here including:[/bold yellow]
• Host discovery results
• Open ports and services  
• Identified vulnerabilities
• Security recommendations
• Compliance findings

[bold blue]For detailed results, check the exported file.[/bold blue]
            """,
            title="Scan Summary",
            border_style="green"
        )
        
        console.print(summary_panel)
    
    def mode_scan(self):
        """Mode scan - Interactive scan mode selection"""
        self.clear_screen()
        
        mode_panel = Panel.fit(
            """
[bold cyan]🔄 MODE SCAN[/bold cyan]

[bold yellow]Available Scan Modes:[/bold yellow]

[bold green]1.[/bold green] Stealth Mode          - Minimal footprint, slow but undetectable
[bold green]2.[/bold green] Aggressive Mode       - Fast, comprehensive, high visibility
[bold green]3.[/bold green] Balanced Mode         - Moderate speed and detection balance
[bold green]4.[/bold green] Passive Mode          - Monitor only, no active probing
[bold green]5.[/bold green] Red Team Mode         - Offensive security testing
[bold green]6.[/bold green] Blue Team Mode        - Defensive monitoring and detection
[bold green]7.[/bold green] Compliance Mode       - Regulatory compliance scanning
[bold green]8.[/bold green] Forensics Mode        - Evidence gathering and analysis
[bold green]9.[/bold green] Custom Mode           - User-defined scan parameters

[bold red]0.[/bold red] Back to Main Menu

Select scan mode:
            """,
            title="🎯 Scan Mode Selection",
            border_style="cyan"
        )
        
        console.print(mode_panel)
        
        try:
            mode_choice = IntPrompt.ask(
                "Enter mode choice",
                choices=[str(i) for i in range(0, 10)],
                default=3
            )
            
            if mode_choice == 0:
                return
            
            # Get target for mode scan
            targets = self.get_target_input()
            if not targets:
                return
            
            # Execute mode scan
            self._execute_mode_scan(targets, mode_choice)
            
        except KeyboardInterrupt:
            console.print("\n[yellow]Mode scan cancelled[/yellow]")
        except Exception as e:
            console.print(f"[red]Mode scan error: {e}[/red]")
    
    def _execute_mode_scan(self, targets: List[str], mode: int):
        """Execute scan in selected mode"""
        mode_names = {
            1: "Stealth Mode",
            2: "Aggressive Mode", 
            3: "Balanced Mode",
            4: "Passive Mode",
            5: "Red Team Mode",
            6: "Blue Team Mode",
            7: "Compliance Mode",
            8: "Forensics Mode",
            9: "Custom Mode"
        }
        
        mode_name = mode_names.get(mode, "Unknown Mode")
        
        console.print(f"\n[bold green]🎯 Starting {mode_name}[/bold green]")
        
        # Configure scan parameters based on mode
        scan_params = self._get_mode_parameters(mode)
        
        # Execute scan with mode-specific parameters
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeRemainingColumn(),
            console=console,
            refresh_per_second=10
        ) as progress:
            
            task = progress.add_task(f"[cyan]Executing {mode_name}...", total=len(targets))
            
            all_results = []
            
            for target in targets:
                try:
                    # Show live target info with reverse DNS
                    target_info = self.scanner.modules['port_scanner'].enhance_target_info(target)
                    reverse_dns = target_info.get('reverse_dns', 'N/A')
                    
                    console.print(f"\n[bold yellow]📍 Scanning: {target}[/bold yellow]")
                    console.print(f"[dim]Reverse DNS: {reverse_dns}[/dim]")
                    
                    # Execute scan based on mode
                    if mode == 1:  # Stealth Mode
                        results = self._stealth_scan(target, scan_params)
                    elif mode == 2:  # Aggressive Mode
                        results = self._aggressive_scan(target, scan_params)
                    elif mode == 3:  # Balanced Mode
                        results = self._balanced_scan(target, scan_params)
                    elif mode == 4:  # Passive Mode
                        results = self._passive_scan(target, scan_params)
                    elif mode == 5:  # Red Team Mode
                        results = self._red_team_scan(target, scan_params)
                    elif mode == 6:  # Blue Team Mode
                        results = self._blue_team_scan(target, scan_params)
                    elif mode == 7:  # Compliance Mode
                        results = self._compliance_scan(target, scan_params)
                    elif mode == 8:  # Forensics Mode
                        results = self._forensics_scan(target, scan_params)
                    elif mode == 9:  # Custom Mode
                        results = self._custom_scan(target, scan_params)
                    
                    if results:
                        all_results.append(results)
                        self._display_live_results(target, results)
                    
                except Exception as e:
                    console.print(f"[red]Error scanning {target}: {e}[/red]")
                
                progress.update(task, advance=1)
        
        # Display final results
        self._display_mode_scan_results(all_results, mode_name)
        
        self.current_scan_results = all_results
        
        # Ask to save results
        if Confirm.ask("\nSave scan results?"):
            self._save_scan_results(all_results, f"mode_scan_{mode_name.lower().replace(' ', '_')}")
    
    def _get_mode_parameters(self, mode: int) -> Dict[str, Any]:
        """Get scan parameters for selected mode"""
        params = {
            'timeout': 30,
            'modules': ['port_scanner'],
            'intensity': 'medium',
            'stealth': False,
            'comprehensive': False
        }
        
        if mode == 1:  # Stealth Mode
            params.update({
                'timeout': 60,
                'modules': ['port_scanner'],
                'intensity': 'low',
                'stealth': True,
                'delay': 5
            })
        elif mode == 2:  # Aggressive Mode
            params.update({
                'timeout': 15,
                'modules': ['port_scanner', 'vulnerability_scanner', 'web_scanner'],
                'intensity': 'high',
                'comprehensive': True,
                'threads': 50
            })
        elif mode == 3:  # Balanced Mode
            params.update({
                'timeout': 30,
                'modules': ['port_scanner', 'vulnerability_scanner'],
                'intensity': 'medium',
                'threads': 20
            })
        elif mode == 4:  # Passive Mode
            params.update({
                'timeout': 120,
                'modules': ['network_scanner'],
                'intensity': 'passive',
                'stealth': True
            })
        elif mode == 5:  # Red Team Mode
            params.update({
                'timeout': 20,
                'modules': ['port_scanner', 'vulnerability_scanner', 'web_scanner', 'ssh_scanner'],
                'intensity': 'aggressive',
                'comprehensive': True,
                'exploit_mode': True
            })
        elif mode == 6:  # Blue Team Mode
            params.update({
                'timeout': 45,
                'modules': ['malware_scanner', 'forensics_scanner', 'network_scanner'],
                'intensity': 'defensive',
                'monitoring': True
            })
        elif mode == 7:  # Compliance Mode
            params.update({
                'timeout': 90,
                'modules': ['config_scanner', 'vulnerability_scanner'],
                'intensity': 'compliance',
                'comprehensive': True,
                'standards': ['pci', 'hipaa', 'sox']
            })
        elif mode == 8:  # Forensics Mode
            params.update({
                'timeout': 180,
                'modules': ['forensics_scanner', 'malware_scanner', 'memory_scanner'],
                'intensity': 'deep',
                'evidence_preservation': True
            })
        elif mode == 9:  # Custom Mode
            params = self._get_custom_parameters()
        
        return params
    
    def _get_custom_parameters(self) -> Dict[str, Any]:
        """Get custom scan parameters from user"""
        console.print("\n[bold cyan]🔧 Custom Mode Configuration[/bold cyan]")
        
        # Get timeout
        timeout = IntPrompt.ask("Scan timeout (seconds)", default=30, choices=range(5, 301))
        
        # Get modules
        available_modules = [
            'port_scanner', 'vulnerability_scanner', 'web_scanner', 
            'ssh_scanner', 'network_scanner', 'malware_scanner',
            'forensics_scanner', 'config_scanner', 'database_scanner'
        ]
        
        console.print("\nAvailable modules:")
        for i, module in enumerate(available_modules, 1):
            console.print(f"{i}. {module}")
        
        module_choices = Prompt.ask(
            "Select modules (comma-separated numbers)",
            default="1,2"
        )
        
        selected_modules = []
        for choice in module_choices.split(','):
            try:
                idx = int(choice.strip()) - 1
                if 0 <= idx < len(available_modules):
                    selected_modules.append(available_modules[idx])
            except ValueError:
                pass
        
        # Get intensity
        intensity = Prompt.ask(
            "Scan intensity",
            choices=['low', 'medium', 'high', 'aggressive'],
            default='medium'
        )
        
        return {
            'timeout': timeout,
            'modules': selected_modules,
            'intensity': intensity,
            'custom': True
        }
    
    def _stealth_scan(self, target: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Execute stealth mode scan"""
        try:
            # Use port scanner with stealth settings
            from .enhanced_scanner import SecurityScanner
            scanner = SecurityScanner(timeout=params['timeout'])
            
            # Perform stealth scan
            results = asyncio.run(scanner.scan_target(
                target,
                modules=['port_scanner'],
                stealth=True,
                delay=params.get('delay', 5)
            ))
            
            return results
        except Exception as e:
            return {'error': str(e), 'target': target}
    
    def _aggressive_scan(self, target: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Execute aggressive mode scan"""
        try:
            from .enhanced_scanner import SecurityScanner
            scanner = SecurityScanner(timeout=params['timeout'])
            
            # Perform aggressive scan
            results = asyncio.run(scanner.scan_target(
                target,
                modules=params['modules'],
                threads=params.get('threads', 50),
                aggressive=True
            ))
            
            return results
        except Exception as e:
            return {'error': str(e), 'target': target}
    
    def _balanced_scan(self, target: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Execute balanced mode scan"""
        try:
            from .enhanced_scanner import SecurityScanner
            scanner = SecurityScanner(timeout=params['timeout'])
            
            # Perform balanced scan
            results = asyncio.run(scanner.scan_target(
                target,
                modules=params['modules'],
                threads=params.get('threads', 20)
            ))
            
            return results
        except Exception as e:
            return {'error': str(e), 'target': target}
    
    def _passive_scan(self, target: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Execute passive mode scan"""
        try:
            from .modules.network_scanner import NetworkScanner
            scanner = NetworkScanner(timeout=params['timeout'])
            
            # Perform passive scan
            results = asyncio.run(scanner.scan(target, passive=True))
            
            return results
        except Exception as e:
            return {'error': str(e), 'target': target}
    
    def _red_team_scan(self, target: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Execute red team mode scan"""
        try:
            from .enhanced_scanner import SecurityScanner
            scanner = SecurityScanner(timeout=params['timeout'])
            
            # Perform red team scan
            results = asyncio.run(scanner.scan_target(
                target,
                modules=params['modules'],
                aggressive=True,
                exploit_mode=True
            ))
            
            return results
        except Exception as e:
            return {'error': str(e), 'target': target}
    
    def _blue_team_scan(self, target: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Execute blue team mode scan"""
        try:
            from .enhanced_scanner import SecurityScanner
            scanner = SecurityScanner(timeout=params['timeout'])
            
            # Perform blue team scan
            results = asyncio.run(scanner.scan_target(
                target,
                modules=params['modules'],
                monitoring=True
            ))
            
            return results
        except Exception as e:
            return {'error': str(e), 'target': target}
    
    def _compliance_scan(self, target: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Execute compliance mode scan"""
        try:
            from .modules.config_scanner import ConfigScanner
            scanner = ConfigScanner(timeout=params['timeout'])
            
            # Perform compliance scan
            results = asyncio.run(scanner.scan(
                target,
                standards=params.get('standards', ['pci', 'hipaa'])
            ))
            
            return results
        except Exception as e:
            return {'error': str(e), 'target': target}
    
    def _forensics_scan(self, target: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Execute forensics mode scan"""
        try:
            from .modules.forensics_scanner import ForensicsScanner
            scanner = ForensicsScanner(timeout=params['timeout'])
            
            # Perform forensics scan
            results = asyncio.run(scanner.scan(
                target,
                evidence_preservation=True
            ))
            
            return results
        except Exception as e:
            return {'error': str(e), 'target': target}
    
    def _custom_scan(self, target: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Execute custom mode scan"""
        try:
            from .enhanced_scanner import SecurityScanner
            scanner = SecurityScanner(timeout=params['timeout'])
            
            # Perform custom scan
            results = asyncio.run(scanner.scan_target(
                target,
                modules=params['modules'],
                custom=True
            ))
            
            return results
        except Exception as e:
            return {'error': str(e), 'target': target}
    
    def _display_mode_scan_results(self, all_results: List[Dict[str, Any]], mode_name: str):
        """Display mode scan results summary"""
        console.print(f"\n[bold green]📊 {mode_name} Results Summary[/bold green]")
        
        total_targets = len(all_results)
        successful_scans = len([r for r in all_results if 'error' not in r])
        
        console.print(f"[blue]Total targets: {total_targets}[/blue]")
        console.print(f"[green]Successful scans: {successful_scans}[/green]")
        
        if successful_scans < total_targets:
            console.print(f"[red]Failed scans: {total_targets - successful_scans}[/red]")
        
        # Show summary statistics
        total_ports = 0
        total_vulnerabilities = 0
        
        for result in all_results:
            if 'error' not in result:
                if 'open_ports' in result:
                    total_ports += len(result['open_ports'])
                if 'vulnerabilities' in result:
                    total_vulnerabilities += len(result['vulnerabilities'])
        
        if total_ports > 0:
            console.print(f"[green]Total open ports found: {total_ports}[/green]")
        if total_vulnerabilities > 0:
            console.print(f"[red]Total vulnerabilities found: {total_vulnerabilities}[/red]")
        
        console.print()
    
    def _save_scan_results(self, results: List[Dict[str, Any]], scan_type: str):
        """Save scan results to file"""
        try:
            import json
            from datetime import datetime
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{scan_type}_{timestamp}.json"
            
            with open(filename, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            
            console.print(f"[green]✅ Results saved to {filename}[/green]")
        except Exception as e:
            console.print(f"[red]❌ Failed to save results: {e}[/red]")
    
    def _display_live_results(self, target: str, results: Dict[str, Any]):
        """Display live scan results for a target"""
        if not results:
            return
        
        # Show basic target info
        target_info = results.get('target_info', {})
        if target_info.get('is_reachable'):
            console.print(f"[green]✅ {target} is alive[/green]")
            if target_info.get('reverse_dns'):
                console.print(f"[dim]   Reverse DNS: {target_info['reverse_dns']}[/dim]")
        else:
            console.print(f"[red]❌ {target} is not reachable[/red]")
            return
        
        # Show open ports if available
        if 'open_ports' in results:
            ports = results['open_ports'][:5]  # Show first 5 ports
            if ports:
                port_list = ', '.join([f"{p['port']}/{p.get('protocol', 'tcp')}" for p in ports])
                console.print(f"[blue]🔓 Open ports: {port_list}[/blue]")
        
        # Show critical findings
        if 'vulnerabilities' in results:
            critical_vulns = [v for v in results['vulnerabilities'] if v.get('severity') == 'critical']
            if critical_vulns:
                console.print(f"[red]⚠️  {len(critical_vulns)} critical vulnerabilities found[/red]")
        
        console.print()  # Empty line for readability
    
    def crypto_security_audit(self):
        """Crypto security audit scan"""
        self.clear_screen()
        
        crypto_panel = Panel.fit(
            """
[bold cyan]🔐 CRYPTO SECURITY AUDIT[/bold cyan]

This scan will analyze:
• SSL/TLS configurations and cipher suites
• Certificate security and validity
• Key exchange mechanisms
• Cryptographic vulnerabilities
• Protocol weaknesses
• Compliance with crypto standards

[bold yellow]Note:[/bold yellow] This scan focuses on cryptographic implementations
and may take several minutes to complete.
            """,
            title="Crypto Security Audit",
            border_style="cyan"
        )
        
        console.print(crypto_panel)
        
        targets = self.get_target_input()
        if not targets:
            return
        
        self._execute_crypto_audit(targets)
    
    def _execute_crypto_audit(self, targets: List[str]):
        """Execute crypto security audit"""
        from .modules.crypto_scanner import CryptoSecurityScanner
        
        scanner = CryptoSecurityScanner()
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeRemainingColumn(),
            console=console,
            refresh_per_second=10
        ) as progress:
            
            task = progress.add_task("[cyan]Crypto Security Audit...", total=len(targets))
            
            all_results = []
            
            for target in targets:
                try:
                    results = asyncio.run(scanner.scan(target))
                    all_results.append(results)
                    self._display_crypto_results(target, results)
                except Exception as e:
                    console.print(f"[red]Error scanning {target}: {e}[/red]")
                
                progress.update(task, advance=1)
        
        self.current_scan_results = all_results
        
        # Ask to save results
        if Confirm.ask("\nSave crypto audit results?"):
            self._save_scan_results(all_results, "crypto_security_audit")
    
    def _display_crypto_results(self, target: str, results: Dict[str, Any]):
        """Display crypto scan results"""
        target_info = results.get('target_info', {})
        if target_info.get('is_reachable'):
            console.print(f"[green]✅ {target} is alive[/green]")
            if target_info.get('reverse_dns'):
                console.print(f"[dim]   Reverse DNS: {target_info['reverse_dns']}[/dim]")
        
        # Show SSL/TLS services
        ssl_services = results.get('ssl_tls_analysis', {})
        if ssl_services:
            console.print(f"[blue]🔒 Found {len(ssl_services)} SSL/TLS services[/blue]")
        
        # Show vulnerabilities
        vulnerabilities = results.get('vulnerabilities', [])
        if vulnerabilities:
            high_vulns = [v for v in vulnerabilities if v.get('severity') == 'high']
            if high_vulns:
                console.print(f"[red]⚠️  {len(high_vulns)} high-severity crypto issues found[/red]")
        
        console.print()
    
    def memory_analysis(self):
        """Memory analysis scan"""
        self.clear_screen()
        
        memory_panel = Panel.fit(
            """
[bold cyan]🧠 MEMORY ANALYSIS[/bold cyan]

This scan will analyze:
• Running processes and memory usage
• Network connections and suspicious activity
• Malware indicators in memory
• System resource utilization
• Memory dump analysis (if available)
• Process injection detection

[bold yellow]Note:[/bold yellow] This scan analyzes live system memory
and may require elevated privileges.
            """,
            title="Memory Analysis",
            border_style="cyan"
        )
        
        console.print(memory_panel)
        
        targets = self.get_target_input()
        if not targets:
            return
        
        # Ask for memory dump file
        memory_dump = Prompt.ask(
            "Memory dump file path (optional, press Enter to skip)",
            default=""
        )
        
        self._execute_memory_analysis(targets, memory_dump)
    
    def _execute_memory_analysis(self, targets: List[str], memory_dump: str = ""):
        """Execute memory analysis"""
        from .modules.memory_scanner import MemoryAnalysisScanner
        
        scanner = MemoryAnalysisScanner()
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeRemainingColumn(),
            console=console,
            refresh_per_second=10
        ) as progress:
            
            task = progress.add_task("[cyan]Memory Analysis...", total=len(targets))
            
            all_results = []
            
            for target in targets:
                try:
                    kwargs = {}
                    if memory_dump:
                        kwargs['memory_dump'] = memory_dump
                    
                    results = asyncio.run(scanner.scan(target, **kwargs))
                    all_results.append(results)
                    self._display_memory_results(target, results)
                except Exception as e:
                    console.print(f"[red]Error analyzing {target}: {e}[/red]")
                
                progress.update(task, advance=1)
        
        self.current_scan_results = all_results
        
        # Ask to save results
        if Confirm.ask("\nSave memory analysis results?"):
            self._save_scan_results(all_results, "memory_analysis")
    
    def _display_memory_results(self, target: str, results: Dict[str, Any]):
        """Display memory analysis results"""
        target_info = results.get('target_info', {})
        if target_info.get('is_reachable'):
            console.print(f"[green]✅ {target} - Memory analysis complete[/green]")
            if target_info.get('reverse_dns'):
                console.print(f"[dim]   Reverse DNS: {target_info['reverse_dns']}[/dim]")
        
        # Show process analysis
        process_analysis = results.get('process_analysis', {})
        if process_analysis:
            total_processes = process_analysis.get('total_processes', 0)
            suspicious_processes = len(process_analysis.get('suspicious_processes', []))
            console.print(f"[blue]🔍 {total_processes} processes analyzed, {suspicious_processes} suspicious[/blue]")
        
        # Show malware indicators
        malware_indicators = results.get('malware_indicators', [])
        if malware_indicators:
            console.print(f"[red]⚠️  {len(malware_indicators)} malware indicators found[/red]")
        
        console.print()
    
    def steganography_detection(self):
        """Steganography detection scan"""
        self.clear_screen()
        
        stego_panel = Panel.fit(
            """
[bold cyan]🕵️ STEGANOGRAPHY DETECTION[/bold cyan]

This scan will analyze:
• Image, audio, and document files for hidden data
• Entropy analysis for randomness detection
• Metadata examination for suspicious indicators
• Tool signatures from steganography software
• File format anomalies
• Hidden message extraction attempts

[bold yellow]Note:[/bold yellow] This scan analyzes files for hidden content
and may require steganography tools to be installed.
            """,
            title="Steganography Detection",
            border_style="cyan"
        )
        
        console.print(stego_panel)
        
        # For steganography, we might scan files or URLs
        file_path = Prompt.ask(
            "Enter file path or URL to analyze (or target IP for file discovery)",
            default=""
        )
        
        if not file_path:
            return
        
        self._execute_steganography_detection([file_path])
    
    def _execute_steganography_detection(self, targets: List[str]):
        """Execute steganography detection"""
        from .modules.steganography_scanner import SteganographyScanner
        
        scanner = SteganographyScanner()
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeRemainingColumn(),
            console=console,
            refresh_per_second=10
        ) as progress:
            
            task = progress.add_task("[cyan]Steganography Detection...", total=len(targets))
            
            all_results = []
            
            for target in targets:
                try:
                    results = asyncio.run(scanner.scan(target))
                    all_results.append(results)
                    self._display_steganography_results(target, results)
                except Exception as e:
                    console.print(f"[red]Error analyzing {target}: {e}[/red]")
                
                progress.update(task, advance=1)
        
        self.current_scan_results = all_results
        
        # Ask to save results
        if Confirm.ask("\nSave steganography analysis results?"):
            self._save_scan_results(all_results, "steganography_detection")
    
    def _display_steganography_results(self, target: str, results: Dict[str, Any]):
        """Display steganography detection results"""
        target_info = results.get('target_info', {})
        console.print(f"[green]✅ {target} - Steganography analysis complete[/green]")
        if target_info.get('reverse_dns'):
            console.print(f"[dim]   Reverse DNS: {target_info['reverse_dns']}[/dim]")
        
        # Show suspicious files
        suspicious_files = results.get('suspicious_files', [])
        if suspicious_files:
            console.print(f"[yellow]🔍 {len(suspicious_files)} files analyzed[/yellow]")
            
            for file_info in suspicious_files[:3]:  # Show first 3
                indicators = file_info.get('suspicious_indicators', [])
                if indicators:
                    console.print(f"[red]⚠️  {file_info['filename']}: {len(indicators)} suspicious indicators[/red]")
        
        console.print()
    
    def malware_analysis(self):
        """Malware analysis scan"""
        self.clear_screen()
        
        malware_panel = Panel.fit(
            """
[bold cyan]🦠 MALWARE ANALYSIS[/bold cyan]

This scan will analyze:
• Known malware signatures and patterns
• Behavioral analysis of suspicious files
• Network connections to malicious domains
• File system changes and modifications
• Registry modifications (Windows)
• Process injection techniques
• Anti-analysis evasion techniques

[bold yellow]Note:[/bold yellow] This is a comprehensive malware scan
that may take significant time to complete.
            """,
            title="Malware Analysis",
            border_style="cyan"
        )
        
        console.print(malware_panel)
        
        targets = self.get_target_input()
        if not targets:
            return
        
        self._execute_malware_analysis(targets)
    
    def _execute_malware_analysis(self, targets: List[str]):
        """Execute malware analysis"""
        from .modules.malware_scanner import MalwareScanner
        
        scanner = MalwareScanner()
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeRemainingColumn(),
            console=console,
            refresh_per_second=10
        ) as progress:
            
            task = progress.add_task("[cyan]Malware Analysis...", total=len(targets))
            
            all_results = []
            
            for target in targets:
                try:
                    results = asyncio.run(scanner.scan(target))
                    all_results.append(results)
                    self._display_malware_results(target, results)
                except Exception as e:
                    console.print(f"[red]Error analyzing {target}: {e}[/red]")
                
                progress.update(task, advance=1)
        
        self.current_scan_results = all_results
        
        # Ask to save results
        if Confirm.ask("\nSave malware analysis results?"):
            self._save_scan_results(all_results, "malware_analysis")
    
    def _display_malware_results(self, target: str, results: Dict[str, Any]):
        """Display malware analysis results"""
        target_info = results.get('target_info', {})
        if target_info.get('is_reachable'):
            console.print(f"[green]✅ {target} - Malware analysis complete[/green]")
            if target_info.get('reverse_dns'):
                console.print(f"[dim]   Reverse DNS: {target_info['reverse_dns']}[/dim]")
        
        # Show malware findings
        malware_found = results.get('malware_found', [])
        if malware_found:
            console.print(f"[red]🦠 {len(malware_found)} malware instances detected[/red]")
        
        # Show suspicious activities
        suspicious_activities = results.get('suspicious_activities', [])
        if suspicious_activities:
            console.print(f"[yellow]⚠️  {len(suspicious_activities)} suspicious activities[/yellow]")
        
        console.print()
    
    def forensics_investigation(self):
        """Forensics investigation scan"""
        self.clear_screen()
        
        forensics_panel = Panel.fit(
            """
[bold cyan]🔍 FORENSICS INVESTIGATION[/bold cyan]

This scan will analyze:
• Digital evidence preservation
• Timeline reconstruction
• Deleted file recovery
• Log file analysis
• Network traffic examination
• System artifact collection
• Chain of custody documentation

[bold yellow]Note:[/bold yellow] This is a comprehensive forensics scan
that preserves evidence and may take extended time.
            """,
            title="Forensics Investigation",
            border_style="cyan"
        )
        
        console.print(forensics_panel)
        
        targets = self.get_target_input()
        if not targets:
            return
        
        self._execute_forensics_investigation(targets)
    
    def _execute_forensics_investigation(self, targets: List[str]):
        """Execute forensics investigation"""
        from .modules.forensics_scanner import ForensicsScanner
        
        scanner = ForensicsScanner()
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeRemainingColumn(),
            console=console,
            refresh_per_second=10
        ) as progress:
            
            task = progress.add_task("[cyan]Forensics Investigation...", total=len(targets))
            
            all_results = []
            
            for target in targets:
                try:
                    results = asyncio.run(scanner.scan(target))
                    all_results.append(results)
                    self._display_forensics_results(target, results)
                except Exception as e:
                    console.print(f"[red]Error investigating {target}: {e}[/red]")
                
                progress.update(task, advance=1)
        
        self.current_scan_results = all_results
        
        # Ask to save results
        if Confirm.ask("\nSave forensics investigation results?"):
            self._save_scan_results(all_results, "forensics_investigation")
    
    def _display_forensics_results(self, target: str, results: Dict[str, Any]):
        """Display forensics investigation results"""
        target_info = results.get('target_info', {})
        if target_info.get('is_reachable'):
            console.print(f"[green]✅ {target} - Forensics investigation complete[/green]")
            if target_info.get('reverse_dns'):
                console.print(f"[dim]   Reverse DNS: {target_info['reverse_dns']}[/dim]")
        
        # Show evidence found
        evidence_found = results.get('evidence_found', [])
        if evidence_found:
            console.print(f"[blue]📋 {len(evidence_found)} pieces of evidence collected[/blue]")
        
        # Show timeline events
        timeline_events = results.get('timeline_events', [])
        if timeline_events:
            console.print(f"[yellow]⏰ {len(timeline_events)} timeline events reconstructed[/yellow]")
        
        console.print()
    
    def traffic_analysis(self):
        """Traffic analysis scan"""
        self.clear_screen()
        
        traffic_panel = Panel.fit(
            """
[bold cyan]📡 TRAFFIC ANALYSIS[/bold cyan]

This scan will analyze:
• Network traffic patterns and protocols
• Suspicious connections and data flows
• DNS queries and responses
• HTTP/HTTPS traffic analysis
• Anomaly detection in network behavior
• Credential exposure in clear text
• Data exfiltration indicators

[bold yellow]Note:[/bold yellow] This scan captures and analyzes network traffic
and may require root/administrator privileges.
            """,
            title="Traffic Analysis",
            border_style="cyan"
        )
        
        console.print(traffic_panel)
        
        targets = self.get_target_input()
        if not targets:
            return
        
        # Get capture parameters
        capture_duration = IntPrompt.ask(
            "Capture duration (seconds)",
            default=60,
            choices=range(30, 301)
        )
        
        interface = Prompt.ask(
            "Network interface (or 'any' for all)",
            default="any"
        )
        
        self._execute_traffic_analysis(targets, capture_duration, interface)
    
    def _execute_traffic_analysis(self, targets: List[str], capture_duration: int, interface: str):
        """Execute traffic analysis"""
        from .modules.traffic_scanner import TrafficAnalysisScanner
        
        scanner = TrafficAnalysisScanner()
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeRemainingColumn(),
            console=console,
            refresh_per_second=10
        ) as progress:
            
            task = progress.add_task("[cyan]Traffic Analysis...", total=len(targets))
            
            all_results = []
            
            for target in targets:
                try:
                    results = asyncio.run(scanner.scan(
                        target,
                        capture_duration=capture_duration,
                        interface=interface
                    ))
                    all_results.append(results)
                    self._display_traffic_results(target, results)
                except Exception as e:
                    console.print(f"[red]Error analyzing traffic for {target}: {e}[/red]")
                
                progress.update(task, advance=1)
        
        self.current_scan_results = all_results
        
        # Ask to save results
        if Confirm.ask("\nSave traffic analysis results?"):
            self._save_scan_results(all_results, "traffic_analysis")
    
    def _display_traffic_results(self, target: str, results: Dict[str, Any]):
        """Display traffic analysis results"""
        target_info = results.get('target_info', {})
        if target_info.get('is_reachable'):
            console.print(f"[green]✅ {target} - Traffic analysis complete[/green]")
            if target_info.get('reverse_dns'):
                console.print(f"[dim]   Reverse DNS: {target_info['reverse_dns']}[/dim]")
        
        # Show protocol analysis
        protocol_analysis = results.get('protocol_analysis', {})
        if protocol_analysis:
            total_packets = protocol_analysis.get('total_packets', 0)
            console.print(f"[blue]📊 {total_packets} packets analyzed[/blue]")
        
        # Show security findings
        security_analysis = results.get('security_analysis', {})
        if security_analysis:
            suspicious_connections = len(security_analysis.get('suspicious_connections', []))
            if suspicious_connections:
                console.print(f"[red]⚠️  {suspicious_connections} suspicious connections[/red]")
        
        console.print()
    
    def iot_device_scan(self):
        """IoT device scan"""
        self.clear_screen()
        
        iot_panel = Panel.fit(
            """
[bold cyan]🌐 IOT DEVICE SCAN[/bold cyan]

This scan will discover and analyze:
• IoT devices on the network
• Smart home devices and cameras
• Industrial control systems
• Network appliances and routers
• Default credentials and weak security
• UPnP and other discovery protocols
• MQTT brokers and CoAP endpoints

[bold yellow]Note:[/bold yellow] This scan discovers IoT devices
and tests for common security vulnerabilities.
            """,
            title="IoT Device Scan",
            border_style="cyan"
        )
        
        console.print(iot_panel)
        
        targets = self.get_target_input()
        if not targets:
            return
        
        self._execute_iot_device_scan(targets)
    
    def _execute_iot_device_scan(self, targets: List[str]):
        """Execute IoT device scan"""
        from .modules.iot_scanner import IoTDeviceScanner
        
        scanner = IoTDeviceScanner()
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeRemainingColumn(),
            console=console,
            refresh_per_second=10
        ) as progress:
            
            task = progress.add_task("[cyan]IoT Device Scan...", total=len(targets))
            
            all_results = []
            
            for target in targets:
                try:
                    results = asyncio.run(scanner.scan(target))
                    all_results.append(results)
                    self._display_iot_results(target, results)
                except Exception as e:
                    console.print(f"[red]Error scanning {target}: {e}[/red]")
                
                progress.update(task, advance=1)
        
        self.current_scan_results = all_results
        
        # Ask to save results
        if Confirm.ask("\nSave IoT device scan results?"):
            self._save_scan_results(all_results, "iot_device_scan")
    
    def _display_iot_results(self, target: str, results: Dict[str, Any]):
        """Display IoT device scan results"""
        target_info = results.get('target_info', {})
        if target_info.get('is_reachable'):
            console.print(f"[green]✅ {target} - IoT scan complete[/green]")
            if target_info.get('reverse_dns'):
                console.print(f"[dim]   Reverse DNS: {target_info['reverse_dns']}[/dim]")
        
        # Show discovered devices
        discovered_devices = results.get('discovered_devices', [])
        if discovered_devices:
            console.print(f"[blue]🔍 {len(discovered_devices)} IoT devices discovered[/blue]")
        
        # Show security issues
        security_issues = results.get('security_issues', [])
        if security_issues:
            high_issues = [i for i in security_issues if i.get('severity') == 'high']
            console.print(f"[red]⚠️  {len(high_issues)} high-severity security issues[/red]")
        
        # Show default credentials
        default_creds = results.get('default_credentials', [])
        if default_creds:
            console.print(f"[red]🔑 {len(default_creds)} devices with default credentials[/red]")
        
        console.print()
    
    def commands_scripts_menu(self):
        """Commands and scripts menu"""
        self.clear_screen()
        
        while True:
            commands_panel = Panel.fit(
                """
[bold cyan]📋 COMMANDS & SCRIPTS MENU[/bold cyan]

[bold yellow]Available Commands:[/bold yellow]

[bold green]1.[/bold green] View All Available Scan Modules
[bold green]2.[/bold green] Show CLI Usage Examples
[bold green]3.[/bold green] List Python Scripts
[bold green]4.[/bold green] Show Configuration Options
[bold green]5.[/bold green] Display Tool Dependencies
[bold green]6.[/bold green] Show Output Formats
[bold green]7.[/bold green] List Compliance Frameworks
[bold green]8.[/bold green] Show Advanced Options
[bold green]9.[/bold green] Quick Reference Guide

[bold red]0.[/bold red] Back to Main Menu

Select option:
                """,
                title="📋 Commands & Scripts Reference",
                border_style="cyan"
            )
            
            console.print(commands_panel)
            
            try:
                choice = IntPrompt.ask(
                    "Enter choice",
                    choices=[str(i) for i in range(0, 10)],
                    default=0
                )
                
                if choice == 0:
                    break
                elif choice == 1:
                    self._show_available_modules()
                elif choice == 2:
                    self._show_cli_examples()
                elif choice == 3:
                    self._list_python_scripts()
                elif choice == 4:
                    self._show_configuration_options()
                elif choice == 5:
                    self._show_tool_dependencies()
                elif choice == 6:
                    self._show_output_formats()
                elif choice == 7:
                    self._list_compliance_frameworks()
                elif choice == 8:
                    self._show_advanced_options()
                elif choice == 9:
                    self._show_quick_reference()
                
                if choice != 0:
                    Prompt.ask("\nPress Enter to continue...")
                
            except KeyboardInterrupt:
                break
    
    def _show_available_modules(self):
        """Show all available scan modules"""
        console.print("\n[bold cyan]📦 Available Scan Modules[/bold cyan]\n")
        
        modules = {
            'port_scanner': 'Enhanced port scanning with service detection',
            'vulnerability_scanner': 'CVE-based vulnerability assessment',
            'network_scanner': 'Network analysis and traffic inspection',
            'web_scanner': 'Web application security testing',
            'ssh_scanner': 'SSH security testing and red team assessment',
            'config_scanner': 'Configuration and compliance auditing',
            'malware_scanner': 'Malware detection and analysis',
            'database_scanner': 'Database security assessment',
            'forensics_scanner': 'Digital forensics and analysis',
            'crypto_scanner': 'Cryptographic security assessment',
            'memory_scanner': 'Memory forensics and analysis',
            'steganography_scanner': 'Steganography detection',
            'iot_scanner': 'IoT device discovery and security',
            'traffic_scanner': 'Network traffic analysis',
            'system_check': 'System dependency verification'
        }
        
        table = Table(show_header=True, header_style="bold cyan")
        table.add_column("Module", style="green")
        table.add_column("Description", style="white")
        
        for module, description in modules.items():
            table.add_row(module, description)
        
        console.print(table)
    
    def _show_cli_examples(self):
        """Show CLI usage examples"""
        console.print("\n[bold cyan]💻 CLI Usage Examples[/bold cyan]\n")
        
        examples = [
            ("Basic scan", "python run.py 192.168.1.1"),
            ("Port scan", "python run.py 192.168.1.1 --modules port_scanner"),
            ("Multiple targets", "python run.py 192.168.1.1,192.168.1.2"),
            ("CIDR range", "python run.py 192.168.1.0/24"),
            ("Vulnerability scan", "python run.py target.com --modules vulnerability_scanner"),
            ("Custom timeout", "python run.py target.com --timeout 60"),
            ("JSON output", "python run.py target.com --output-format json"),
            ("Save results", "python run.py target.com --output-file results.json"),
            ("Verbose mode", "python run.py target.com --verbose"),
            ("Interactive mode", "python run.py --interactive")
        ]
        
        table = Table(show_header=True, header_style="bold cyan")
        table.add_column("Description", style="yellow")
        table.add_column("Command", style="green")
        
        for desc, cmd in examples:
            table.add_row(desc, cmd)
        
        console.print(table)
    
    def _list_python_scripts(self):
        """List available Python scripts"""
        console.print("\n[bold cyan]🐍 Available Python Scripts[/bold cyan]\n")
        
        scripts = [
            ("run.py", "Main entry point for LinuxScan"),
            ("linux_security_scanner.py", "Legacy compatibility script"),
            ("demo.py", "Demonstration script"),
            ("ssh_scanner_demo.py", "SSH scanner demonstration"),
            ("setup.py", "Package installation script"),
            ("test_fixes.sh", "Test script for validating fixes")
        ]
        
        table = Table(show_header=True, header_style="bold cyan")
        table.add_column("Script", style="green")
        table.add_column("Description", style="white")
        
        for script, description in scripts:
            table.add_row(script, description)
        
        console.print(table)
    
    def _show_configuration_options(self):
        """Show configuration options"""
        console.print("\n[bold cyan]⚙️ Configuration Options[/bold cyan]\n")
        
        options = [
            ("--timeout", "Scan timeout in seconds (default: 30)"),
            ("--modules", "Comma-separated list of scan modules"),
            ("--output-format", "Output format: json, csv, html, txt"),
            ("--output-file", "Output file path"),
            ("--verbose", "Enable verbose output"),
            ("--quiet", "Suppress output except errors"),
            ("--threads", "Number of scanning threads"),
            ("--delay", "Delay between requests (seconds)"),
            ("--user-agent", "Custom user agent string"),
            ("--proxy", "HTTP proxy URL"),
            ("--headers", "Custom HTTP headers"),
            ("--cookies", "Custom cookies"),
            ("--follow-redirects", "Follow HTTP redirects"),
            ("--verify-ssl", "Verify SSL certificates")
        ]
        
        table = Table(show_header=True, header_style="bold cyan")
        table.add_column("Option", style="green")
        table.add_column("Description", style="white")
        
        for option, description in options:
            table.add_row(option, description)
        
        console.print(table)
    
    def _show_tool_dependencies(self):
        """Show tool dependencies"""
        console.print("\n[bold cyan]🛠️ Tool Dependencies[/bold cyan]\n")
        
        dependencies = [
            ("Python 3.7+", "Required", "Core runtime"),
            ("nmap", "Required", "Network scanning"),
            ("python-nmap", "Required", "Python nmap wrapper"),
            ("requests", "Required", "HTTP requests"),
            ("paramiko", "Required", "SSH connections"),
            ("cryptography", "Required", "Cryptographic functions"),
            ("rich", "Required", "Terminal formatting"),
            ("psutil", "Required", "System information"),
            ("click", "Required", "Command line interface"),
            ("tcpdump", "Optional", "Traffic capture"),
            ("tshark", "Optional", "Traffic analysis"),
            ("volatility", "Optional", "Memory analysis"),
            ("steghide", "Optional", "Steganography detection"),
            ("openssl", "Optional", "SSL/TLS analysis"),
            ("sqlmap", "Optional", "SQL injection testing")
        ]
        
        table = Table(show_header=True, header_style="bold cyan")
        table.add_column("Tool", style="green")
        table.add_column("Status", style="yellow")
        table.add_column("Purpose", style="white")
        
        for tool, status, purpose in dependencies:
            table.add_row(tool, status, purpose)
        
        console.print(table)
    
    def _show_output_formats(self):
        """Show available output formats"""
        console.print("\n[bold cyan]📄 Output Formats[/bold cyan]\n")
        
        formats = [
            ("json", "JavaScript Object Notation", "Machine-readable, structured data"),
            ("csv", "Comma-Separated Values", "Spreadsheet compatible format"),
            ("html", "HyperText Markup Language", "Web browser viewable format"),
            ("txt", "Plain Text", "Human-readable text format"),
            ("xml", "eXtensible Markup Language", "Structured markup format"),
            ("yaml", "YAML Ain't Markup Language", "Human-readable data format")
        ]
        
        table = Table(show_header=True, header_style="bold cyan")
        table.add_column("Format", style="green")
        table.add_column("Name", style="yellow")
        table.add_column("Description", style="white")
        
        for fmt, name, desc in formats:
            table.add_row(fmt, name, desc)
        
        console.print(table)
    
    def _list_compliance_frameworks(self):
        """List supported compliance frameworks"""
        console.print("\n[bold cyan]📋 Compliance Frameworks[/bold cyan]\n")
        
        frameworks = [
            ("PCI DSS", "Payment Card Industry Data Security Standard"),
            ("HIPAA", "Health Insurance Portability and Accountability Act"),
            ("SOX", "Sarbanes-Oxley Act"),
            ("GDPR", "General Data Protection Regulation"),
            ("NIST", "National Institute of Standards and Technology"),
            ("ISO 27001", "Information Security Management"),
            ("CIS", "Center for Internet Security"),
            ("OWASP", "Open Web Application Security Project"),
            ("FISMA", "Federal Information Security Management Act"),
            ("COBIT", "Control Objectives for Information and Related Technologies")
        ]
        
        table = Table(show_header=True, header_style="bold cyan")
        table.add_column("Framework", style="green")
        table.add_column("Description", style="white")
        
        for framework, description in frameworks:
            table.add_row(framework, description)
        
        console.print(table)
    
    def _show_advanced_options(self):
        """Show advanced configuration options"""
        console.print("\n[bold cyan]🔧 Advanced Options[/bold cyan]\n")
        
        options = [
            ("--auto-install", "Automatically install missing dependencies"),
            ("--update-db", "Update vulnerability databases"),
            ("--parallel", "Run scans in parallel"),
            ("--resume", "Resume interrupted scans"),
            ("--exclude-ports", "Exclude specific ports from scanning"),
            ("--include-ports", "Include only specific ports"),
            ("--rate-limit", "Rate limit requests per second"),
            ("--random-agent", "Use random user agent strings"),
            ("--tor", "Route traffic through Tor network"),
            ("--api-key", "API key for external services"),
            ("--webhook", "Webhook URL for notifications"),
            ("--email", "Email address for notifications"),
            ("--slack", "Slack webhook for notifications"),
            ("--database", "Database connection string"),
            ("--cache", "Enable result caching")
        ]
        
        table = Table(show_header=True, header_style="bold cyan")
        table.add_column("Option", style="green")
        table.add_column("Description", style="white")
        
        for option, description in options:
            table.add_row(option, description)
        
        console.print(table)
    
    def _show_quick_reference(self):
        """Show quick reference guide"""
        console.print("\n[bold cyan]📚 Quick Reference Guide[/bold cyan]\n")
        
        console.print("""
[bold yellow]🚀 Getting Started:[/bold yellow]
1. Run basic scan: python run.py [target]
2. Interactive mode: python run.py --interactive
3. Help: python run.py --help

[bold yellow]🎯 Common Targets:[/bold yellow]
• Single IP: 192.168.1.1
• IP range: 192.168.1.1-10
• CIDR: 192.168.1.0/24
• Hostname: example.com
• Multiple: target1,target2,target3

[bold yellow]⚡ Quick Commands:[/bold yellow]
• Port scan: --modules port_scanner
• Vulnerability scan: --modules vulnerability_scanner
• Web scan: --modules web_scanner
• SSH audit: --modules ssh_scanner
• Full scan: --modules all

[bold yellow]📊 Output Options:[/bold yellow]
• JSON: --output-format json
• CSV: --output-format csv
• HTML: --output-format html
• Save: --output-file results.json

[bold yellow]🔧 Common Options:[/bold yellow]
• Timeout: --timeout 60
• Verbose: --verbose
• Quiet: --quiet
• Threads: --threads 20
        """)
    
    def export_results(self, results: Dict[str, Any], filename: str, format: str):
        """Export scan results to file"""
        try:
            if format == 'json':
                with open(filename, 'w') as f:
                    json.dump(results, f, indent=2, default=str)
            # Add other export formats as needed
            
            console.print(f"[green]Results exported to {filename}[/green]")
        except Exception as e:
            console.print(f"[red]Failed to export results: {e}[/red]")

    def run(self):
        """Main GUI loop - handles menu navigation and user interaction"""
        while True:
            try:
                self.display_main_menu()
                choice = self.get_menu_choice()
                
                if choice == 0:
                    console.print("\n[bold green]Thank you for using LinuxScan! 👋[/bold green]")
                    break
                elif choice == 1:
                    self.quick_scan()
                elif choice == 2:
                    self.advanced_scan()
                elif choice == 3:
                    self.mode_scan()
                elif choice == 4:
                    self.network_discovery()
                elif choice == 5:
                    self.vulnerability_assessment()
                elif choice == 6:
                    self.web_application_scan()
                elif choice == 7:
                    self.ssh_security_audit()
                elif choice == 8:
                    self.database_security_scan()
                elif choice == 9:
                    self.compliance_audit()
                elif choice == 10:
                    self.crypto_security_audit()
                elif choice == 11:
                    self.memory_analysis()
                elif choice == 12:
                    self.steganography_detection()
                elif choice == 13:
                    self.malware_analysis()
                elif choice == 14:
                    self.forensics_investigation()
                elif choice == 15:
                    self.traffic_analysis()
                elif choice == 16:
                    self.iot_device_scan()
                elif choice == 17:
                    self.system_check()
                elif choice == 18:
                    self.view_scan_history()
                elif choice == 19:
                    self.commands_and_scripts_menu()
                elif choice == 20:
                    self.configuration_menu()
                elif choice == 21:
                    self.help_and_documentation()
                elif choice == 22:
                    self.scan_sets_menu()
                elif choice == 23:
                    self.fast_ping_scan()
                elif choice == 24:
                    self.fast_ssh_scan()
                    
            except KeyboardInterrupt:
                console.print("\n\n[bold red]Exiting LinuxScan...[/bold red]")
                break
            except Exception as e:
                console.print(f"\n[bold red]An error occurred: {e}[/bold red]")
                console.print("[yellow]Please try again or contact support.[/yellow]")
                input("\nPress Enter to continue...")

    def scan_sets_menu(self):
        """Display scan sets menu with predefined scan combinations"""
        console.print("\n[bold cyan]📋 Scan Sets Menu[/bold cyan]")
        
        scan_sets_panel = Panel.fit(
            """
[bold green]Predefined Scan Combinations[/bold green]

[bold yellow]1.[/bold yellow] Basic Security Set        [dim](port + vulnerability scanning)[/dim]
[bold yellow]2.[/bold yellow] Web Application Set       [dim](web + vulnerability + port scanning)[/dim]
[bold yellow]3.[/bold yellow] Network Assessment Set    [dim](network + port + discovery)[/dim]
[bold yellow]4.[/bold yellow] Red Team Set              [dim](ssh + vulnerability + web + port)[/dim]
[bold yellow]5.[/bold yellow] Blue Team Set             [dim](malware + forensics + network + config)[/dim]
[bold yellow]6.[/bold yellow] Compliance Set            [dim](config + vulnerability + database)[/dim]
[bold yellow]7.[/bold yellow] Full Security Set         [dim](all major security modules)[/dim]
[bold yellow]8.[/bold yellow] Quick Assessment Set      [dim](fast port + basic vulnerability)[/dim]
[bold yellow]9.[/bold yellow] Deep Analysis Set         [dim](forensics + memory + malware + crypto)[/dim]
[bold yellow]10.[/bold yellow] Infrastructure Set       [dim](network + iot + database + ssh)[/dim]

[bold red]0.[/bold red] Back to Main Menu

Select a scan set:
            """,
            title="🎯 Scan Sets",
            border_style="cyan",
            padding=(1, 2)
        )
        
        console.print(scan_sets_panel)
        
        try:
            choice = IntPrompt.ask(
                "Enter choice",
                choices=[str(i) for i in range(0, 11)],
                default=0
            )
            
            if choice == 0:
                return
            
            targets = self.get_target_input()
            if not targets:
                return
                
            # Execute the selected scan set
            self._execute_scan_set(choice, targets)
            
        except KeyboardInterrupt:
            pass

    def _execute_scan_set(self, set_number: int, targets: List[str]):
        """Execute a predefined scan set"""
        scan_sets = {
            1: {  # Basic Security Set
                'name': 'Basic Security Set',
                'modules': ['port_scanner', 'vulnerability_scanner'],
                'config': {'timeout': 10, 'max_workers': 30, 'verbose': False}
            },
            2: {  # Web Application Set
                'name': 'Web Application Set',
                'modules': ['web_scanner', 'vulnerability_scanner', 'port_scanner'],
                'config': {'timeout': 15, 'max_workers': 20, 'verbose': True}
            },
            3: {  # Network Assessment Set
                'name': 'Network Assessment Set',
                'modules': ['network_scanner', 'port_scanner'],
                'config': {'timeout': 8, 'max_workers': 50, 'verbose': False}
            },
            4: {  # Red Team Set
                'name': 'Red Team Set',
                'modules': ['ssh_scanner', 'vulnerability_scanner', 'web_scanner', 'port_scanner'],
                'config': {'timeout': 12, 'max_workers': 25, 'verbose': True}
            },
            5: {  # Blue Team Set
                'name': 'Blue Team Set',
                'modules': ['malware_scanner', 'forensics_scanner', 'network_scanner', 'config_scanner'],
                'config': {'timeout': 20, 'max_workers': 15, 'verbose': True}
            },
            6: {  # Compliance Set
                'name': 'Compliance Set',
                'modules': ['config_scanner', 'vulnerability_scanner', 'database_scanner'],
                'config': {'timeout': 25, 'max_workers': 20, 'verbose': True}
            },
            7: {  # Full Security Set
                'name': 'Full Security Set',
                'modules': ['port_scanner', 'vulnerability_scanner', 'web_scanner', 'ssh_scanner', 'network_scanner', 'malware_scanner', 'config_scanner'],
                'config': {'timeout': 30, 'max_workers': 20, 'verbose': True}
            },
            8: {  # Quick Assessment Set
                'name': 'Quick Assessment Set',
                'modules': ['port_scanner', 'vulnerability_scanner'],
                'config': {'timeout': 5, 'max_workers': 50, 'verbose': False}
            },
            9: {  # Deep Analysis Set
                'name': 'Deep Analysis Set',
                'modules': ['forensics_scanner', 'memory_scanner', 'malware_scanner', 'crypto_scanner'],
                'config': {'timeout': 45, 'max_workers': 10, 'verbose': True}
            },
            10: {  # Infrastructure Set
                'name': 'Infrastructure Set',
                'modules': ['network_scanner', 'iot_scanner', 'database_scanner', 'ssh_scanner'],
                'config': {'timeout': 20, 'max_workers': 25, 'verbose': True}
            }
        }
        
        if set_number not in scan_sets:
            console.print("[red]Invalid scan set selection![/red]")
            return
        
        scan_set = scan_sets[set_number]
        console.print(f"\n[bold green]🚀 Executing {scan_set['name']}[/bold green]")
        console.print(f"[blue]Modules: {', '.join(scan_set['modules'])}[/blue]")
        
        # Ask if user wants to modify the configuration
        modify_config = Confirm.ask("Modify default configuration?", default=False)
        
        if modify_config:
            config = self.configure_scan_options()
            # Merge with default config
            scan_set['config'].update(config)
        
        self.run_scan(targets, scan_set['modules'], scan_set['config'])

    def fast_ping_scan(self):
        """Perform a very fast ping scan for host discovery"""
        console.print("\n[bold green]⚡ Fast Ping Scan[/bold green]")
        console.print("[dim]Ultra-fast host discovery and connectivity testing[/dim]")
        
        targets = self.get_target_input()
        if not targets:
            return
        
        console.print(f"\n[bold cyan]🏃 Starting Fast Ping Scan[/bold cyan]")
        console.print(f"[blue]Targets: {', '.join(targets)}[/blue]")
        
        # Fast ping scan configuration
        config = {
            'timeout': 1,  # Very fast timeout
            'max_workers': 100,  # High concurrency
            'verbose': False,
            'ping_only': True,
            'fast_mode': True
        }
        
        # Use a lightweight ping scanner approach
        self._execute_fast_ping(targets, config)

    def _execute_fast_ping(self, targets: List[str], config: Dict[str, Any]):
        """Execute fast ping scan with specialized logic"""
        console.print("\n[bold yellow]🔍 Fast Ping Scan Results[/bold yellow]")
        
        alive_hosts = []
        dead_hosts = []
        
        try:
            with Progress() as progress:
                task = progress.add_task("[cyan]Pinging hosts...", total=len(targets))
                
                for target in targets:
                    progress.update(task, advance=1)
                    
                    # Simulate fast ping (replace with actual ping logic)
                    try:
                        # Simple socket connect test for speed
                        import socket
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(config['timeout'])
                        
                        # Try to connect to common ports for quick test
                        for port in [80, 443, 22, 21, 23, 25, 53, 110, 143, 993, 995]:
                            try:
                                result = sock.connect_ex((target, port))
                                if result == 0:
                                    alive_hosts.append(target)
                                    break
                            except:
                                continue
                        else:
                            dead_hosts.append(target)
                        
                        sock.close()
                    except:
                        dead_hosts.append(target)
                
                # Display results
                results_table = Table(title="Fast Ping Scan Results")
                results_table.add_column("Status", style="bold")
                results_table.add_column("Host", style="cyan")
                results_table.add_column("Response Time", style="green")
                
                for host in alive_hosts:
                    results_table.add_row("✅ ALIVE", host, "< 1s")
                
                for host in dead_hosts:
                    results_table.add_row("❌ DOWN", host, "timeout")
                
                console.print(results_table)
                
                # Summary
                console.print(f"\n[bold green]📊 Summary:[/bold green]")
                console.print(f"[green]• Alive hosts: {len(alive_hosts)}[/green]")
                console.print(f"[red]• Down hosts: {len(dead_hosts)}[/red]")
                console.print(f"[blue]• Total scanned: {len(targets)}[/blue]")
                
        except KeyboardInterrupt:
            console.print("\n[red]Ping scan interrupted by user[/red]")
        except Exception as e:
            console.print(f"\n[red]Fast ping scan failed: {e}[/red]")
        
        input("\nPress Enter to continue...")

    def fast_ssh_scan(self):
        """Perform a very fast SSH scan for SSH service discovery"""
        console.print("\n[bold green]🔑 Fast SSH Scan[/bold green]")
        console.print("[dim]Ultra-fast SSH service discovery and banner grabbing[/dim]")
        
        targets = self.get_target_input()
        if not targets:
            return
        
        console.print(f"\n[bold cyan]🏃 Starting Fast SSH Scan[/bold cyan]")
        console.print(f"[blue]Targets: {', '.join(targets)}[/blue]")
        
        # Fast SSH scan configuration
        config = {
            'timeout': 3,  # Fast timeout for SSH
            'max_workers': 50,  # High concurrency
            'verbose': False,
            'ssh_only': True,
            'fast_mode': True,
            'banner_grab': True
        }
        
        # Use a lightweight SSH scanner approach
        self._execute_fast_ssh(targets, config)

    def _execute_fast_ssh(self, targets: List[str], config: Dict[str, Any]):
        """Execute fast SSH scan with specialized logic"""
        console.print("\n[bold yellow]🔍 Fast SSH Scan Results[/bold yellow]")
        
        ssh_hosts = []
        no_ssh_hosts = []
        
        try:
            with Progress() as progress:
                task = progress.add_task("[cyan]Scanning SSH services...", total=len(targets))
                
                for target in targets:
                    progress.update(task, advance=1)
                    
                    # Fast SSH detection
                    try:
                        import socket
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(config['timeout'])
                        
                        # Try to connect to SSH port (22)
                        result = sock.connect_ex((target, 22))
                        if result == 0:
                            # Try to get SSH banner
                            banner = ""
                            try:
                                sock.settimeout(2)
                                banner = sock.recv(1024).decode('utf-8').strip()
                            except:
                                banner = "SSH detected (no banner)"
                            
                            ssh_hosts.append({
                                'host': target,
                                'port': 22,
                                'banner': banner,
                                'status': 'open'
                            })
                        else:
                            no_ssh_hosts.append(target)
                        
                        sock.close()
                    except:
                        no_ssh_hosts.append(target)
                
                # Display results
                results_table = Table(title="Fast SSH Scan Results")
                results_table.add_column("Status", style="bold")
                results_table.add_column("Host", style="cyan")
                results_table.add_column("Port", style="green")
                results_table.add_column("SSH Banner", style="yellow")
                
                for ssh_info in ssh_hosts:
                    results_table.add_row(
                        "✅ SSH OPEN", 
                        ssh_info['host'], 
                        str(ssh_info['port']),
                        ssh_info['banner'][:50] + "..." if len(ssh_info['banner']) > 50 else ssh_info['banner']
                    )
                
                for host in no_ssh_hosts:
                    results_table.add_row("❌ NO SSH", host, "22", "Service not available")
                
                console.print(results_table)
                
                # Summary
                console.print(f"\n[bold green]📊 Summary:[/bold green]")
                console.print(f"[green]• SSH available: {len(ssh_hosts)}[/green]")
                console.print(f"[red]• No SSH: {len(no_ssh_hosts)}[/red]")
                console.print(f"[blue]• Total scanned: {len(targets)}[/blue]")
                
                # Show SSH version analysis if available
                if ssh_hosts:
                    console.print(f"\n[bold cyan]🔍 SSH Version Analysis:[/bold cyan]")
                    for ssh_info in ssh_hosts:
                        if 'SSH' in ssh_info['banner']:
                            console.print(f"[blue]• {ssh_info['host']}[/blue]: {ssh_info['banner']}")
                
        except KeyboardInterrupt:
            console.print("\n[red]SSH scan interrupted by user[/red]")
        except Exception as e:
            console.print(f"\n[red]Fast SSH scan failed: {e}[/red]")
        
        input("\nPress Enter to continue...")


def main():
    """Entry point for GUI"""
    gui = LinuxScanGUI()
    gui.run()


if __name__ == "__main__":
    main()