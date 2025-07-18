#!/usr/bin/env python3
"""
Test multi-host async scanning functionality
"""

import asyncio
import sys
import os
sys.path.insert(0, '.')

from linuxscan.enhanced_port_scanner import EnhancedPortScanner
from rich.console import Console

console = Console()

async def test_multi_host_scanning():
    """Test multi-host async scanning"""
    console.print("🔍 [bold cyan]Testing Multi-Host Async Port Scanning[/bold cyan]")
    
    # Create scanner
    scanner = EnhancedPortScanner(timeout=2, max_workers=50)
    
    # Test hosts (use safe hosts that won't cause issues)
    hosts = ['127.0.0.1', '8.8.8.8', '1.1.1.1']
    
    # Test with common ports
    ports = [22, 53, 80, 443, 8080, 8443, 25, 110, 143, 993, 995]
    
    console.print(f"[blue]Testing {len(hosts)} hosts with {len(ports)} ports each[/blue]")
    console.print(f"[blue]Total port checks: {len(hosts) * len(ports)}[/blue]")
    
    try:
        # Run the scan
        results = await scanner.scan_multiple_hosts(hosts, ports)
        
        if not results.get('interrupted'):
            console.print("\n[green]✅ Multi-host scanning completed successfully![/green]")
            scanner.display_final_results(results)
        else:
            console.print("\n[yellow]⚠️  Scan was interrupted[/yellow]")
            
    except Exception as e:
        console.print(f"\n[red]❌ Error during scanning: {e}[/red]")
        import traceback
        traceback.print_exc()

async def test_cli_multi_host():
    """Test CLI multi-host functionality"""
    console.print("\n🖥️ [bold cyan]Testing CLI Multi-Host Functionality[/bold cyan]")
    
    # Import the enhanced scanner
    from linuxscan.enhanced_scanner import SecurityScanner
    
    # Create scanner
    scanner = SecurityScanner(timeout=3, max_workers=30)
    
    # Test multiple hosts
    hosts = ['127.0.0.1', '8.8.8.8']
    modules = ['port_scanner']
    
    console.print(f"[blue]Testing {len(hosts)} hosts with modules: {modules}[/blue]")
    
    try:
        # Run the scan
        results = await scanner.scan_network(hosts, modules)
        
        console.print("\n[green]✅ CLI multi-host scanning completed successfully![/green]")
        
        # Display summary
        summary = results.get('summary', {})
        console.print(f"[blue]Total hosts scanned: {summary.get('scanned_hosts', 0)}[/blue]")
        console.print(f"[blue]Scan duration: {summary.get('scan_duration', 0):.2f} seconds[/blue]")
        
        # Show results for each host
        for host, result in results.get('results', {}).items():
            open_ports = result.get('scan_results', {}).get('port_scan', {}).get('open_ports', {})
            console.print(f"[green]Host {host}: {len(open_ports)} open ports[/green]")
            
    except Exception as e:
        console.print(f"\n[red]❌ Error during CLI scanning: {e}[/red]")
        import traceback
        traceback.print_exc()

async def main():
    """Main test function"""
    console.print("🧪 [bold yellow]LinuxScan Multi-Host Async Testing[/bold yellow]")
    console.print("=" * 50)
    
    # Test 1: Enhanced port scanner
    await test_multi_host_scanning()
    
    # Test 2: CLI multi-host
    await test_cli_multi_host()
    
    console.print("\n🎉 [bold green]All tests completed![/bold green]")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print("\n[red]Tests interrupted by user[/red]")
    except Exception as e:
        console.print(f"\n[red]Test failed: {e}[/red]")
        import traceback
        traceback.print_exc()