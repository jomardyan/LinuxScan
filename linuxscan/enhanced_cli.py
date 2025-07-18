#!/usr/bin/env python3
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
LinuxScan CLI - Command Line Interface
Professional Linux Security Scanner CLI
Version: 1.0.0
"""

import asyncio
import click
import json
import sys
import os
from pathlib import Path
from typing import List, Optional, Dict, Any

from rich.console import Console
from rich.progress import Progress
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

try:
    from .enhanced_scanner import SecurityScanner, display_banner, display_help
    from .config import ConfigManager
except ImportError:
    # Handle relative imports when running as script
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent))
    from enhanced_scanner import SecurityScanner, display_banner, display_help
    from config import ConfigManager

console = Console()

# Available scan modules
SCAN_MODULES = {
    'port_scanner': 'Enhanced port scanning with service detection',
    'vulnerability_scanner': 'CVE-based vulnerability assessment',
    'network_scanner': 'Network analysis and traffic inspection',
    'web_scanner': 'Web application security testing',
    'config_scanner': 'Configuration and compliance auditing',
    'malware_scanner': 'Malware detection and analysis',
    'database_scanner': 'Database security assessment',
    'forensics_scanner': 'Digital forensics and analysis',
    'ssh_scanner': 'SSH security testing and red team assessment',
    'crypto_scanner': 'Cryptographic security assessment',
    'memory_scanner': 'Memory forensics and analysis',
    'steganography_scanner': 'Steganography detection and analysis',
    'iot_scanner': 'IoT device discovery and security assessment',
    'traffic_scanner': 'Network traffic analysis and monitoring',
    'system_check': 'System dependency and component verification'
}

# Output formats
OUTPUT_FORMATS = ['json', 'csv', 'html', 'txt']

# Compliance frameworks
COMPLIANCE_FRAMEWORKS = ['cis', 'stig', 'pci', 'hipaa', 'gdpr']


def validate_targets(targets: str) -> List[str]:
    """Validate and parse target list"""
    target_list = []
    
    for target in targets.split(','):
        target = target.strip()
        if target:
            target_list.append(target)
    
    if not target_list:
        raise click.BadParameter("No valid targets provided")
    
    return target_list


def validate_modules(modules: str) -> List[str]:
    """Validate and parse module list"""
    if modules.lower() == 'all':
        return list(SCAN_MODULES.keys())
    
    module_list = []
    for module in modules.split(','):
        module = module.strip()
        if module in SCAN_MODULES:
            module_list.append(module)
        else:
            available = ', '.join(SCAN_MODULES.keys())
            raise click.BadParameter(f"Invalid module '{module}'. Available: {available}")
    
    return module_list or ['port_scanner', 'vulnerability_scanner']


def display_scan_modules():
    """Display available scan modules"""
    table = Table(title="Available Scan Modules")
    table.add_column("Module", style="cyan")
    table.add_column("Description", style="white")
    
    for module, description in SCAN_MODULES.items():
        table.add_row(module, description)
    
    console.print(table)


def display_results_summary(results: Dict[str, Any]):
    """Display scan results summary"""
    summary = results.get('summary', {})
    
    # Summary panel
    summary_text = f"""
    [bold green]Scan Completed Successfully[/bold green]
    
    Total Hosts: {summary.get('total_hosts', 0)}
    Scanned Hosts: {summary.get('scanned_hosts', 0)}
    Vulnerable Hosts: {summary.get('vulnerable_hosts', 0)}
    Scan Duration: {summary.get('scan_duration', 0):.2f} seconds
    
    [bold yellow]Vulnerability Summary:[/bold yellow]
    Critical: {summary.get('vulnerability_summary', {}).get('critical', 0)}
    High: {summary.get('vulnerability_summary', {}).get('high', 0)}
    Medium: {summary.get('vulnerability_summary', {}).get('medium', 0)}
    Low: {summary.get('vulnerability_summary', {}).get('low', 0)}
    """
    
    console.print(Panel(summary_text, title="Scan Summary", expand=False))
    
    # Security score distribution
    score_dist = summary.get('security_score_distribution', {})
    if score_dist:
        score_text = f"""
        Average Score: {score_dist.get('average', 0):.1f}
        Best Score: {score_dist.get('maximum', 0)}
        Worst Score: {score_dist.get('minimum', 0)}
        Median Score: {score_dist.get('median', 0)}
        """
        console.print(Panel(score_text, title="Security Score Distribution", expand=False))
    
    # Top vulnerabilities
    top_vulns = summary.get('top_vulnerabilities', [])
    if top_vulns:
        table = Table(title="Top Vulnerabilities")
        table.add_column("Vulnerability Type", style="red")
        table.add_column("Count", style="yellow")
        
        for vuln_type, count in top_vulns[:5]:  # Top 5
            table.add_row(vuln_type, str(count))
        
        console.print(table)


def display_detailed_results(results: Dict[str, Any], show_details: bool = False):
    """Display detailed scan results"""
    host_results = results.get('results', {})
    
    # Host summary table
    table = Table(title="Host Scan Results")
    table.add_column("Host", style="cyan")
    table.add_column("Security Score", style="green")
    table.add_column("Vulnerabilities", style="red")
    table.add_column("Modules", style="yellow")
    table.add_column("Status", style="bold")
    
    for host, result in host_results.items():
        security_score = result.get('security_score', 0)
        vulnerabilities = len(result.get('vulnerabilities', []))
        modules = ', '.join(result.get('scan_modules', []))
        
        if security_score >= 80:
            status = "[green]Good[/green]"
        elif security_score >= 60:
            status = "[yellow]Fair[/yellow]"
        else:
            status = "[red]Poor[/red]"
        
        table.add_row(
            host,
            str(security_score),
            str(vulnerabilities),
            modules,
            status
        )
    
    console.print(table)
    
    # Detailed results if requested
    if show_details:
        for host, result in host_results.items():
            console.print(f"\n[bold cyan]Detailed Results for {host}[/bold cyan]")
            
            # Vulnerabilities
            vulnerabilities = result.get('vulnerabilities', [])
            if vulnerabilities:
                vuln_table = Table(title=f"Vulnerabilities for {host}")
                vuln_table.add_column("Type", style="red")
                vuln_table.add_column("Severity", style="yellow")
                vuln_table.add_column("Description", style="white")
                vuln_table.add_column("Module", style="cyan")
                
                for vuln in vulnerabilities[:10]:  # Show top 10
                    vuln_table.add_row(
                        vuln.get('type', 'Unknown'),
                        vuln.get('severity', 'Unknown'),
                        vuln.get('description', 'No description')[:50] + "...",
                        vuln.get('source_module', 'Unknown')
                    )
                
                console.print(vuln_table)
            
            # Recommendations
            recommendations = result.get('recommendations', [])
            if recommendations:
                rec_text = "\n".join(f"• {rec}" for rec in recommendations[:5])
                console.print(Panel(rec_text, title=f"Recommendations for {host}", expand=False))


@click.command()
@click.argument('targets', required=False)
@click.option('--modules', '-m', default='port_scanner,vulnerability_scanner',
              help='Comma-separated list of scan modules to use (or "all")')
@click.option('--timeout', '-t', default=5, type=int,
              help='Connection timeout in seconds (default: 5)')
@click.option('--max-workers', '-w', default=50, type=int,
              help='Maximum concurrent workers (default: 50)')
@click.option('--output', '-o', type=str,
              help='Output file name')
@click.option('--format', '-f', 'output_format', default='json',
              type=click.Choice(OUTPUT_FORMATS),
              help='Output format (default: json)')
@click.option('--config', '-c', type=click.Path(exists=True),
              help='Configuration file path')
@click.option('--compliance', type=click.Choice(COMPLIANCE_FRAMEWORKS),
              help='Compliance framework for configuration scanning')
@click.option('--verbose', '-v', is_flag=True,
              help='Verbose output')
@click.option('--quiet', '-q', is_flag=True,
              help='Quiet mode (minimal output)')
@click.option('--details', '-d', is_flag=True,
              help='Show detailed results')
@click.option('--interactive', '-i', is_flag=True,
              help='Interactive mode')
@click.option('--version', is_flag=True,
              help='Show version information')
@click.option('--list-modules', is_flag=True,
              help='List available scan modules')
@click.option('--help-extended', is_flag=True,
              help='Show extended help with examples')
@click.option('--system-check', is_flag=True,
              help='Run system dependency check')
@click.option('--auto-install', is_flag=True,
              help='Automatically install missing dependencies')
@click.option('--ssh-brute-force', is_flag=True,
              help='Enable SSH brute force testing (red team mode)')
@click.option('--ssh-usernames', type=str, 
              help='Comma-separated list of SSH usernames to test')
@click.option('--ssh-passwords', type=str,
              help='Comma-separated list of SSH passwords to test')
@click.option('--ssh-max-attempts', type=int, default=100,
              help='Maximum SSH brute force attempts (default: 100)')
@click.option('--ssh-delay', type=float, default=1.0,
              help='Delay between SSH attempts in seconds (default: 1.0)')
@click.option('--ssh-config-audit', is_flag=True,
              help='Enable SSH configuration audit (requires credentials)')
@click.option('--ssh-credentials', type=str,
              help='SSH credentials in format "username:password" for config audit')
@click.option('--enable-service-detection', is_flag=True,
              help='Enable detailed service detection (slower but more thorough)')
@click.option('--enable-os-detection', is_flag=True,
              help='Enable OS detection (requires root privileges)')
@click.option('--enable-banner-grabbing', is_flag=True,
              help='Enable banner grabbing for open ports')
@click.option('--advanced-scan', is_flag=True,
              help='Enable all advanced features (service detection, OS detection, banner grabbing)')
def main(targets: Optional[str], modules: str, timeout: int, max_workers: int,
         output: Optional[str], output_format: str, config: Optional[str],
         compliance: Optional[str], verbose: bool, quiet: bool, details: bool,
         interactive: bool, version: bool, list_modules: bool, help_extended: bool,
         system_check: bool, auto_install: bool,
         ssh_brute_force: bool, ssh_usernames: Optional[str], ssh_passwords: Optional[str],
         ssh_max_attempts: int, ssh_delay: float, ssh_config_audit: bool,
         ssh_credentials: Optional[str], enable_service_detection: bool,
         enable_os_detection: bool, enable_banner_grabbing: bool, advanced_scan: bool):
    """
    LinuxScan - Comprehensive Linux Security Scanner
    
    TARGETS: IP addresses, CIDR ranges, or hostnames (comma-separated)
    Optional when using --system-check, --version, --list-modules, or --help-extended
    
    Examples:
        linuxscan 192.168.1.1
        linuxscan 192.168.1.0/24 --modules all
        linuxscan example.com --output report.json
        linuxscan --system-check
        linuxscan --system-check --auto-install
    """
    
    # Handle special options
    if version:
        console.print("[bold blue]LinuxScan v1.0.0[/bold blue]")
        console.print("Comprehensive Linux Security Scanner")
        console.print("Professional Security Assessment Tool")
        return
    
    if list_modules:
        display_scan_modules()
        return
    
    if help_extended:
        display_help()
        return
    
    # Handle system check
    if system_check:
        from .modules.system_check import SystemCheckModule
        
        console.print(Panel.fit("🔍 [bold cyan]LinuxScan System Check[/bold cyan]", 
                               border_style="cyan"))
        
        # Initialize system check module
        system_checker = SystemCheckModule()
        
        # Get modules to check
        modules_to_check = None
        if modules != 'port_scanner,vulnerability_scanner':
            modules_to_check = validate_modules(modules)
        
        # Run system check
        results = asyncio.run(system_checker.scan(modules=modules_to_check, auto_install=auto_install))
        
        # Display results and exit
        if results.get('missing_system') or results.get('missing_python'):
            console.print(f"[red]⚠️  Missing dependencies detected![/red]")
            
            if auto_install:
                console.print("[yellow]Dependencies installation attempted[/yellow]")
            else:
                console.print("[yellow]Run with --auto-install to install missing dependencies[/yellow]")
                console.print("[yellow]Or run: ./setup.sh --system-deps[/yellow]")
            sys.exit(1)
        else:
            console.print("[green]✅ All dependencies are installed![/green]")
            sys.exit(0)
    
    if not quiet:
        display_banner()
    
    # Handle interactive mode without targets
    if interactive and not targets and not system_check and not version and not list_modules and not help_extended:
        console.print("[cyan]🚀 Launching LinuxScan Interactive Interface...[/cyan]")
        try:
            from .gui import LinuxScanGUI
            gui = LinuxScanGUI()
            gui.run()
            return
        except ImportError as e:
            console.print(f"[red]Error loading GUI: {e}[/red]")
            console.print("[yellow]GUI mode requires all dependencies to be installed[/yellow]")
            sys.exit(1)
    
    # Check if targets are required
    if not targets and not system_check and not version and not list_modules and not help_extended and not interactive:
        console.print("[red]Error: TARGETS argument is required unless using --interactive, --system-check, --version, --list-modules, or --help-extended[/red]")
        sys.exit(1)

    try:
        # Load configuration
        config_manager = ConfigManager()
        if config:
            config_manager.load_config(config)
        
        # Update configuration with command line options
        config_manager.update_config(
            timeout=timeout,
            max_workers=max_workers,
            verbose=verbose,
            quiet=quiet
        )
        
        # Validate inputs
        if targets:
            target_list = validate_targets(targets)
            module_list = validate_modules(modules)
            
            if verbose:
                console.print(f"[blue]Targets: {target_list}[/blue]")
                console.print(f"[blue]Modules: {module_list}[/blue]")
                console.print(f"[blue]Configuration: {config_manager.get_config()}[/blue]")
        else:
            target_list = []
            module_list = []
        
        # Interactive mode
        if interactive and targets:
            console.print("[yellow]Interactive mode enabled[/yellow]")
            
            # Allow user to modify targets
            new_targets = click.prompt("Enter targets (comma-separated)", 
                                     default=','.join(target_list))
            target_list = validate_targets(new_targets)
            
            # Allow user to select modules
            display_scan_modules()
            new_modules = click.prompt("Select modules (comma-separated or 'all')",
                                     default=','.join(module_list))
            module_list = validate_modules(new_modules)
            
            # Confirm scan
            if not click.confirm(f"Start scan of {len(target_list)} targets with {len(module_list)} modules?"):
                console.print("[red]Scan cancelled[/red]")
                return
        
        # Skip scanning if no targets
        if not target_list:
            return
        
        # Initialize scanner
        scanner = SecurityScanner(timeout=timeout, max_workers=max_workers)
        
        if not quiet:
            console.print(f"[green]Starting scan of {len(target_list)} targets[/green]")
            console.print(f"[blue]Using modules: {', '.join(module_list)}[/blue]")
        
        # Enable advanced features if requested
        if advanced_scan:
            enable_service_detection = True
            enable_os_detection = True
            enable_banner_grabbing = True
        
        # Build scan options
        scan_options = {
            'enable_service_detection': enable_service_detection,
            'enable_os_detection': enable_os_detection,
            'enable_banner_grabbing': enable_banner_grabbing
        }
        
        # Build SSH scanning options
        ssh_kwargs = {}
        if ssh_brute_force:
            ssh_kwargs['brute_force'] = True
            ssh_kwargs['max_attempts'] = ssh_max_attempts
            ssh_kwargs['delay'] = ssh_delay
            
            if ssh_usernames:
                ssh_kwargs['usernames'] = ssh_usernames.split(',')
            if ssh_passwords:
                ssh_kwargs['passwords'] = ssh_passwords.split(',')
        
        if ssh_config_audit:
            ssh_kwargs['config_audit'] = True
            if ssh_credentials:
                username, password = ssh_credentials.split(':', 1)
                ssh_kwargs['credentials'] = {'username': username, 'password': password}
        
        # Add scan options to kwargs
        ssh_kwargs.update(scan_options)
        
        # Run scan
        results = asyncio.run(scanner.scan_network(target_list, module_list, **ssh_kwargs))
        
        # Display results
        if not quiet:
            display_results_summary(results)
            
            if details or verbose:
                display_detailed_results(results, show_details=details)
            else:
                display_detailed_results(results, show_details=False)
        
        # Export results
        if output:
            if output_format == 'json':
                with open(output, 'w') as f:
                    json.dump(results, f, indent=2, default=str)
            elif output_format == 'csv':
                scanner.export_csv(output)
            elif output_format == 'html':
                scanner.export_html(output)
            elif output_format == 'txt':
                with open(output, 'w') as f:
                    f.write("LinuxScan Security Report\n")
                    f.write("=" * 50 + "\n\n")
                    
                    summary = results.get('summary', {})
                    f.write(f"Total Hosts: {summary.get('total_hosts', 0)}\n")
                    f.write(f"Scanned Hosts: {summary.get('scanned_hosts', 0)}\n")
                    f.write(f"Vulnerable Hosts: {summary.get('vulnerable_hosts', 0)}\n")
                    f.write(f"Scan Duration: {summary.get('scan_duration', 0):.2f} seconds\n\n")
                    
                    for host, result in results.get('results', {}).items():
                        f.write(f"Host: {host}\n")
                        f.write(f"Security Score: {result.get('security_score', 0)}\n")
                        f.write(f"Vulnerabilities: {len(result.get('vulnerabilities', []))}\n")
                        f.write("-" * 30 + "\n")
            
            if not quiet:
                console.print(f"[green]Results exported to {output}[/green]")
        
        # Exit with appropriate code
        vulnerable_hosts = results.get('vulnerable_hosts', 0)
        if vulnerable_hosts > 0:
            console.print(f"[yellow]Warning: {vulnerable_hosts} vulnerable hosts found[/yellow]")
            sys.exit(1)
        else:
            if not quiet:
                console.print("[green]No critical vulnerabilities found[/green]")
            sys.exit(0)
    
    except click.BadParameter as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)
    except KeyboardInterrupt:
        console.print("\n[red]Scan interrupted by user[/red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Unexpected error: {e}[/red]")
        if verbose:
            import traceback
            console.print(traceback.format_exc())
        sys.exit(1)


@click.group()
def cli():
    """LinuxScan CLI tools"""
    pass


@cli.command()
@click.argument('config_file', type=click.Path())
def generate_config(config_file: str):
    """Generate a sample configuration file"""
    config_manager = ConfigManager()
    config_manager.generate_sample_config(config_file)
    console.print(f"[green]Sample configuration generated: {config_file}[/green]")


@cli.command()
@click.argument('target')
@click.option('--port', '-p', type=int, help='Specific port to scan')
@click.option('--service', '-s', help='Service type (http, https, ssh, etc.)')
def quick_scan(target: str, port: Optional[int], service: Optional[str]):
    """Quick scan of a single target"""
    scanner = SecurityScanner()
    
    if port and service:
        console.print(f"[blue]Quick scan of {target}:{port} ({service})[/blue]")
    else:
        console.print(f"[blue]Quick scan of {target}[/blue]")
    
    # Run basic port scan
    results = asyncio.run(scanner.scan_network([target], ['port_scanner']))
    
    # Display results
    host_results = results.get('results', {}).get(target, {})
    scan_results = host_results.get('scan_results', {}).get('port_scan', {})
    open_ports = scan_results.get('open_ports', {})
    
    if open_ports:
        table = Table(title=f"Open Ports on {target}")
        table.add_column("Port", style="cyan")
        table.add_column("Service", style="green")
        table.add_column("State", style="yellow")
        
        for port_num, port_info in open_ports.items():
            table.add_row(
                str(port_num),
                port_info.get('service', 'Unknown'),
                port_info.get('state', 'Unknown')
            )
        
        console.print(table)
    else:
        console.print(f"[yellow]No open ports found on {target}[/yellow]")


@cli.command()
@click.argument('target')
@click.option('--compliance', '-c', type=click.Choice(COMPLIANCE_FRAMEWORKS),
              default='cis', help='Compliance framework')
def compliance_scan(target: str, compliance: str):
    """Run compliance scan against a target"""
    scanner = SecurityScanner()
    
    console.print(f"[blue]Running {compliance.upper()} compliance scan on {target}[/blue]")
    
    # Run configuration scanner
    results = asyncio.run(scanner.scan_network([target], ['config_scanner']))
    
    # Display compliance results
    host_results = results.get('results', {}).get(target, {})
    config_results = host_results.get('scan_results', {}).get('config_scan', {})
    compliance_score = config_results.get('compliance_score', 0)
    
    console.print(f"[green]Compliance Score: {compliance_score}/100[/green]")
    
    # Show failed checks
    failed_checks = config_results.get('failed_checks', [])
    if failed_checks:
        table = Table(title="Failed Compliance Checks")
        table.add_column("Check ID", style="red")
        table.add_column("Description", style="white")
        
        for check in failed_checks[:10]:  # Show top 10
            table.add_row(
                check.get('id', 'Unknown'),
                check.get('description', 'No description')[:60] + "..."
            )
        
        console.print(table)


@cli.command()
@click.option('--modules', '-m', multiple=True, help='Specific modules to check')
@click.option('--auto-install', '-a', is_flag=True, help='Automatically install missing dependencies')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
def system_check(modules: List[str], auto_install: bool, verbose: bool):
    """Check system dependencies and install missing components"""
    from .modules.system_check import SystemCheckModule
    
    console.print(Panel.fit("🔍 [bold cyan]LinuxScan System Check[/bold cyan]", 
                           border_style="cyan"))
    
    # Initialize system check module
    system_checker = SystemCheckModule()
    
    # Convert modules to list
    modules_list = list(modules) if modules else None
    
    # Run system check
    results = asyncio.run(system_checker.scan(modules=modules_list, auto_install=auto_install))
    
    # Display summary
    if results.get('missing_system') or results.get('missing_python'):
        console.print(f"[red]⚠️  Missing dependencies detected![/red]")
        
        if auto_install:
            console.print("[yellow]Attempting to install missing dependencies...[/yellow]")
        else:
            console.print("[yellow]Run with --auto-install to install missing dependencies[/yellow]")
            console.print("[yellow]Or run: ./setup.sh --system-deps[/yellow]")
    else:
        console.print("[green]✅ All dependencies are installed![/green]")


@cli.command()
@click.argument('url')
@click.option('--scan-type', '-s', type=click.Choice(['basic', 'comprehensive', 'vulnerability']),
              default='basic', help='Scan type')
def web_scan(url: str, scan_type: str):
    """Scan a web application"""
    scanner = SecurityScanner()
    
    console.print(f"[blue]Web application scan of {url} (type: {scan_type})[/blue]")
    
    # Run web scanner
    results = asyncio.run(scanner.scan_network([url], ['web_scanner']))
    
    # Display web scan results
    host_results = results.get('results', {}).get(url, {})
    web_results = host_results.get('scan_results', {}).get('web_scan_80', {}) or \
                  host_results.get('scan_results', {}).get('web_scan_443', {})
    
    if web_results:
        # Security headers
        security_headers = web_results.get('security_headers', {})
        if security_headers:
            console.print(f"[green]Security Score: {security_headers.get('security_score', 0)}/100[/green]")
            
            missing_headers = security_headers.get('missing_headers', [])
            if missing_headers:
                console.print(f"[yellow]Missing Security Headers: {', '.join(missing_headers)}[/yellow]")
        
        # Vulnerabilities
        vulnerabilities = web_results.get('vulnerabilities', [])
        if vulnerabilities:
            table = Table(title="Web Vulnerabilities")
            table.add_column("Type", style="red")
            table.add_column("Severity", style="yellow")
            table.add_column("Description", style="white")
            
            for vuln in vulnerabilities:
                table.add_row(
                    vuln.get('type', 'Unknown'),
                    vuln.get('severity', 'Unknown'),
                    vuln.get('description', 'No description')[:50] + "..."
                )
            
            console.print(table)
    else:
        console.print(f"[yellow]No web scan results found for {url}[/yellow]")


def cli_main():
    """Entry point for setuptools console script"""
    main()


if __name__ == '__main__':
    main()