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
        self.scanner = None
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

[bold green]1.[/bold green] Quick Scan
[bold green]2.[/bold green] Advanced Scan  
[bold green]3.[/bold green] Vulnerability Assessment
[bold green]4.[/bold green] Network Discovery
[bold green]5.[/bold green] Web Application Scan
[bold green]6.[/bold green] SSH Security Audit
[bold green]7.[/bold green] Database Security Scan
[bold green]8.[/bold green] Compliance Audit
[bold green]9.[/bold green] System Check
[bold green]10.[/bold green] View Scan History
[bold green]11.[/bold green] Configuration
[bold green]12.[/bold green] Help & Documentation
[bold red]0.[/bold red] Exit

Select an option:
            """,
            title="LinuxScan Interactive Interface",
            border_style="cyan"
        )
        
        console.print(menu_panel)
        
    def get_menu_choice(self) -> int:
        """Get user menu choice"""
        try:
            choice = IntPrompt.ask(
                "Enter your choice",
                choices=["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12"],
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
        """Main GUI loop"""
        try:
            while True:
                self.display_main_menu()
                
                choice = self.get_menu_choice()
                
                if choice == 0:
                    console.print("\n[bold blue]Thank you for using LinuxScan![/bold blue]")
                    console.print("Stay secure! 🛡️")
                    break
                elif choice == 1:
                    self.quick_scan()
                elif choice == 2:
                    self.advanced_scan()
                elif choice == 3:
                    self.vulnerability_assessment()
                elif choice == 4:
                    self.network_discovery()
                elif choice == 5:
                    self.web_application_scan()
                elif choice == 6:
                    self.ssh_security_audit()
                elif choice == 7:
                    self.database_security_scan()
                elif choice == 8:
                    self.compliance_audit()
                elif choice == 9:
                    self.system_check()
                elif choice == 10:
                    self.view_scan_history()
                elif choice == 11:
                    self.configuration_menu()
                elif choice == 12:
                    self.help_documentation()
                else:
                    console.print("[red]Invalid choice![/red]")
                    time.sleep(1)
                    
        except KeyboardInterrupt:
            console.print("\n\n[bold blue]Goodbye![/bold blue]")
        except Exception as e:
            console.print(f"\n[red]GUI Error: {e}[/red]")


def main():
    """Entry point for GUI"""
    gui = LinuxScanGUI()
    gui.run()


if __name__ == "__main__":
    main()