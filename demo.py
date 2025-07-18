#!/usr/bin/env python3
"""
Demo script to showcase Linux Security Scanner functionality
"""

import asyncio
import json
import tempfile
from pathlib import Path
from linuxscan import SecurityScanner
from linuxscan.config import ConfigManager
from rich.console import Console

console = Console()

async def demo_scanner():
    """Demonstrate scanner functionality"""
    console.print("[bold cyan]Linux Security Scanner Demo[/bold cyan]\n")
    
    # Initialize scanner
    scanner = SecurityScanner()
    
    # Demo 1: Basic localhost scan
    console.print("[bold yellow]Demo 1: Basic localhost scan[/bold yellow]")
    targets = ["127.0.0.1"]
    await scanner.scan_network(targets)
    
    # Show results
    table = scanner.generate_summary_table()
    console.print(table)
    
    # Demo 2: Export functionality
    console.print("\n[bold yellow]Demo 2: Export functionality[/bold yellow]")
    
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        
        # Export to JSON
        json_file = temp_path / "scan_results.json"
        scanner.export_json(str(json_file))
        console.print(f"✓ Exported to JSON: {json_file}")
        
        # Export to CSV
        csv_file = temp_path / "scan_results.csv"
        scanner.export_csv(str(csv_file))
        console.print(f"✓ Exported to CSV: {csv_file}")
        
        # Export to HTML
        html_file = temp_path / "scan_results.html"
        scanner.export_html(str(html_file))
        console.print(f"✓ Exported to HTML: {html_file}")
        
        # Show file contents
        console.print(f"\nJSON file size: {json_file.stat().st_size} bytes")
        console.print(f"CSV file size: {csv_file.stat().st_size} bytes")
        console.print(f"HTML file size: {html_file.stat().st_size} bytes")

def demo_config():
    """Demonstrate configuration functionality"""
    console.print("\n[bold yellow]Demo 3: Configuration management[/bold yellow]")
    
    # Create config manager
    config_manager = ConfigManager()
    
    # Show default config
    config = config_manager.get_config()
    console.print(f"Default timeout: {config.timeout}s")
    console.print(f"Default max workers: {config.max_workers}")
    
    # Update config
    config_manager.update_config(timeout=10, max_workers=100, verbose=True)
    updated_config = config_manager.get_config()
    console.print(f"Updated timeout: {updated_config.timeout}s")
    console.print(f"Updated max workers: {updated_config.max_workers}")
    console.print(f"Verbose mode: {updated_config.verbose}")
    
    # Create sample config
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        sample_file = f.name
    
    try:
        config_manager.create_sample_config(sample_file)
        console.print(f"✓ Created sample config: {sample_file}")
        
        # Load and display sample config
        with open(sample_file, 'r') as f:
            sample_data = json.load(f)
        console.print("Sample config contents:")
        console.print(json.dumps(sample_data, indent=2)[:200] + "...")
        
    finally:
        Path(sample_file).unlink(missing_ok=True)

def demo_cli_features():
    """Demonstrate CLI features"""
    console.print("\n[bold yellow]Demo 4: CLI features[/bold yellow]")
    
    console.print("Available CLI commands:")
    console.print("• linuxscan 192.168.1.1                    # Scan single IP")
    console.print("• linuxscan 192.168.1.0/24                 # Scan CIDR range")
    console.print("• linuxscan -t 192.168.1.1,10.0.0.1        # Scan multiple targets")
    console.print("• linuxscan -f targets.txt                  # Scan targets from file")
    console.print("• linuxscan -c config.json 192.168.1.1     # Use configuration file")
    console.print("• linuxscan --interactive                   # Interactive mode")
    console.print("• linuxscan -o results.json --format json  # Export results")
    console.print("• linuxscan --timeout 10 --max-workers 100 # Custom settings")

def main():
    """Main demo function"""
    try:
        console.print("[bold green]Starting Linux Security Scanner Demo...[/bold green]\n")
        
        # Run async demo
        asyncio.run(demo_scanner())
        
        # Run sync demos
        demo_config()
        demo_cli_features()
        
        console.print("\n[bold green]Demo completed successfully![/bold green]")
        console.print("\nKey features demonstrated:")
        console.print("✓ Security scanning with port detection")
        console.print("✓ Multiple export formats (JSON, CSV, HTML)")
        console.print("✓ Configuration management")
        console.print("✓ Command-line interface")
        console.print("✓ Package structure ready for PyPI")
        
    except Exception as e:
        console.print(f"[red]Demo error: {e}[/red]")

if __name__ == "__main__":
    main()