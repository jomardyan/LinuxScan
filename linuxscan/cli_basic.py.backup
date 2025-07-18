#!/usr/bin/env python3
"""
Command Line Interface for Linux Security Scanner
"""

import argparse
import asyncio
import json
import sys
import os
from pathlib import Path
from typing import List, Optional

from rich.console import Console
from rich.prompt import Confirm
try:
    from .scanner import SecurityScanner, display_banner, display_help
except ImportError:
    # Handle relative imports when running as script
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent))
    from scanner import SecurityScanner, display_banner, display_help

console = Console()

def create_parser() -> argparse.ArgumentParser:
    """Create command line argument parser"""
    parser = argparse.ArgumentParser(
        description="Linux Security Scanner - High-performance security scanning tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  linuxscan 192.168.1.1                    # Scan single IP
  linuxscan 192.168.1.0/24                 # Scan CIDR range
  linuxscan -t 192.168.1.1,10.0.0.1        # Scan multiple targets
  linuxscan -f targets.txt                  # Scan targets from file
  linuxscan -c config.json 192.168.1.1     # Use configuration file
  linuxscan --interactive                   # Interactive mode (default)
        """
    )
    
    parser.add_argument(
        'targets',
        nargs='*',
        help='Target IP addresses or CIDR ranges to scan'
    )
    
    parser.add_argument(
        '-t', '--targets',
        dest='target_list',
        help='Comma-separated list of targets'
    )
    
    parser.add_argument(
        '-f', '--file',
        dest='target_file',
        help='File containing targets (one per line)'
    )
    
    parser.add_argument(
        '-c', '--config',
        dest='config_file',
        help='Configuration file (JSON format)'
    )
    
    parser.add_argument(
        '-o', '--output',
        dest='output_file',
        help='Output file for results'
    )
    
    parser.add_argument(
        '--format',
        choices=['json', 'csv', 'html'],
        default='json',
        help='Output format (default: json)'
    )
    
    parser.add_argument(
        '--timeout',
        type=int,
        default=5,
        help='Connection timeout in seconds (default: 5)'
    )
    
    parser.add_argument(
        '--max-workers',
        type=int,
        default=50,
        help='Maximum number of concurrent workers (default: 50)'
    )
    
    parser.add_argument(
        '--interactive',
        action='store_true',
        help='Run in interactive mode'
    )
    
    parser.add_argument(
        '--no-banner',
        action='store_true',
        help='Suppress banner display'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version='%(prog)s 1.0.0'
    )
    
    return parser

def load_config(config_file: str) -> dict:
    """Load configuration from JSON file"""
    try:
        with open(config_file, 'r') as f:
            return json.load(f)
    except Exception as e:
        console.print(f"[red]Error loading config file: {e}[/red]")
        sys.exit(1)

def load_targets_from_file(target_file: str) -> List[str]:
    """Load targets from file"""
    try:
        with open(target_file, 'r') as f:
            targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        return targets
    except Exception as e:
        console.print(f"[red]Error loading targets file: {e}[/red]")
        sys.exit(1)

def parse_targets(args) -> List[str]:
    """Parse targets from various sources"""
    targets = []
    
    # From positional arguments
    if args.targets:
        targets.extend(args.targets)
    
    # From --targets argument
    if args.target_list:
        targets.extend([t.strip() for t in args.target_list.split(',')])
    
    # From file
    if args.target_file:
        targets.extend(load_targets_from_file(args.target_file))
    
    return targets

async def run_scan(targets: List[str], args, config: dict = None) -> None:
    """Run the security scan"""
    scanner = SecurityScanner()
    
    # Apply configuration
    if config:
        if hasattr(scanner, 'timeout'):
            scanner.timeout = config.get('timeout', args.timeout)
        if hasattr(scanner, 'max_workers'):
            scanner.max_workers = config.get('max_workers', args.max_workers)
    else:
        if hasattr(scanner, 'timeout'):
            scanner.timeout = args.timeout
        if hasattr(scanner, 'max_workers'):
            scanner.max_workers = args.max_workers
    
    console.print(f"\n[cyan]Preparing to scan {len(targets)} target(s)...[/cyan]")
    
    if args.verbose:
        console.print(f"[dim]Targets: {', '.join(targets)}[/dim]")
        console.print(f"[dim]Timeout: {scanner.timeout}s, Workers: {scanner.max_workers}[/dim]")
    
    # Run scan
    console.print("\n[bold yellow]Starting security scan...[/bold yellow]\n")
    await scanner.scan_network(targets)
    
    # Display results
    console.print("\n" + "="*80 + "\n")
    console.print(scanner.generate_summary_table())
    
    # Export results if requested
    if args.output_file:
        try:
            if args.format == 'json':
                scanner.export_json(args.output_file)
            elif args.format == 'csv':
                scanner.export_csv(args.output_file)
            elif args.format == 'html':
                scanner.export_html(args.output_file)
            
            console.print(f"\n[green]Results exported to {args.output_file}[/green]")
        except Exception as e:
            console.print(f"[red]Error exporting results: {e}[/red]")

async def interactive_mode():
    """Run in interactive mode (original behavior)"""
    try:
        from .scanner import main as scanner_main
    except ImportError:
        from scanner import main as scanner_main
    await scanner_main()

async def main():
    """Main CLI entry point"""
    parser = create_parser()
    args = parser.parse_args()
    
    # Load configuration if provided
    config = None
    if args.config_file:
        config = load_config(args.config_file)
    
    # Display banner unless suppressed
    if not args.no_banner:
        display_banner()
    
    # Check for interactive mode or no targets
    targets = parse_targets(args)
    
    if args.interactive or not targets:
        await interactive_mode()
        return
    
    # Validate targets
    if not targets:
        console.print("[red]No targets specified. Use --help for usage information.[/red]")
        sys.exit(1)
    
    # Run scan
    try:
        await run_scan(targets, args, config)
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user[/yellow]")
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")
        if args.verbose:
            import traceback
            traceback.print_exc()

def cli_main():
    """Entry point for setuptools console script"""
    asyncio.run(main())

if __name__ == "__main__":
    cli_main()