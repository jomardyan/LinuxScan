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
Enhanced Port Scanner with Live Progress Tracking
Multi-host async scanning with real-time updates
"""

import asyncio
import time
import socket
import ipaddress
from typing import List, Dict, Any, Optional, Tuple
# Removed unused imports: ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeRemainingColumn, MofNCompleteColumn
from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich.text import Text
# Removed unused import: Align
from rich import box
import threading
# Removed unused import: queue

console = Console()

class PortScanStatus:
    """Track port scanning status for multiple hosts"""
    
    def __init__(self):
        self.hosts_status = {}
        self.lock = threading.Lock()
        self.total_hosts = 0
        self.completed_hosts = 0
        self.total_ports = 0
        self.scanned_ports = 0
        self.open_ports = 0
        self.closed_ports = 0
        self.filtered_ports = 0
        self.start_time = time.time()
        self.results = {}
        
    def add_host(self, host: str, port_count: int):
        """Add a host to track"""
        with self.lock:
            self.hosts_status[host] = {
                'total_ports': port_count,
                'scanned_ports': 0,
                'open_ports': [],
                'closed_ports': 0,
                'filtered_ports': 0,
                'status': 'pending',
                'start_time': None,
                'end_time': None,
                'current_port': None
            }
            self.total_hosts += 1
            self.total_ports += port_count
    
    def update_host_status(self, host: str, status: str, current_port: int = None):
        """Update host scanning status"""
        with self.lock:
            if host in self.hosts_status:
                self.hosts_status[host]['status'] = status
                if current_port:
                    self.hosts_status[host]['current_port'] = current_port
                if status == 'scanning' and self.hosts_status[host]['start_time'] is None:
                    self.hosts_status[host]['start_time'] = time.time()
                elif status == 'completed':
                    self.hosts_status[host]['end_time'] = time.time()
                    self.completed_hosts += 1
    
    def add_port_result(self, host: str, port: int, state: str, service: str = None):
        """Add port scan result"""
        with self.lock:
            if host in self.hosts_status:
                self.hosts_status[host]['scanned_ports'] += 1
                self.scanned_ports += 1
                
                if state == 'open':
                    self.hosts_status[host]['open_ports'].append({
                        'port': port,
                        'service': service or 'unknown',
                        'state': state
                    })
                    self.open_ports += 1
                elif state == 'closed':
                    self.hosts_status[host]['closed_ports'] += 1
                    self.closed_ports += 1
                else:
                    self.hosts_status[host]['filtered_ports'] += 1
                    self.filtered_ports += 1
    
    def get_status_summary(self) -> Dict[str, Any]:
        """Get current status summary"""
        with self.lock:
            elapsed = time.time() - self.start_time
            
            return {
                'total_hosts': self.total_hosts,
                'completed_hosts': self.completed_hosts,
                'pending_hosts': self.total_hosts - self.completed_hosts,
                'total_ports': self.total_ports,
                'scanned_ports': self.scanned_ports,
                'remaining_ports': self.total_ports - self.scanned_ports,
                'open_ports': self.open_ports,
                'closed_ports': self.closed_ports,
                'filtered_ports': self.filtered_ports,
                'elapsed_time': elapsed,
                'scan_rate': self.scanned_ports / elapsed if elapsed > 0 else 0,
                'eta': (self.total_ports - self.scanned_ports) / (self.scanned_ports / elapsed) if self.scanned_ports > 0 and elapsed > 0 else 0,
                'completion_percentage': (self.scanned_ports / self.total_ports * 100) if self.total_ports > 0 else 0
            }
    
    def get_host_details(self) -> List[Dict[str, Any]]:
        """Get detailed host information"""
        with self.lock:
            details = []
            for host, status in self.hosts_status.items():
                host_info = {
                    'host': host,
                    'status': status['status'],
                    'progress': (status['scanned_ports'] / status['total_ports'] * 100) if status['total_ports'] > 0 else 0,
                    'scanned_ports': status['scanned_ports'],
                    'total_ports': status['total_ports'],
                    'open_ports': len(status['open_ports']),
                    'closed_ports': status['closed_ports'],
                    'filtered_ports': status['filtered_ports'],
                    'current_port': status['current_port'],
                    'open_port_list': status['open_ports']
                }
                
                if status['start_time']:
                    elapsed = (status['end_time'] or time.time()) - status['start_time']
                    host_info['elapsed_time'] = elapsed
                    host_info['scan_rate'] = status['scanned_ports'] / elapsed if elapsed > 0 else 0
                
                details.append(host_info)
            
            return sorted(details, key=lambda x: x['host'])


class EnhancedPortScanner:
    """Enhanced port scanner with live progress tracking"""
    
    COMMON_PORTS = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
        80: "HTTP", 110: "POP3", 111: "RPC", 135: "MSRPC", 139: "NetBIOS",
        143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
        1433: "MSSQL", 1521: "Oracle", 1723: "PPTP", 3306: "MySQL",
        3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
        8080: "HTTP-Alt", 8443: "HTTPS-Alt", 9200: "Elasticsearch",
        27017: "MongoDB", 11211: "Memcached", 50000: "DB2"
    }
    
    def __init__(self, timeout: int = 3, max_workers: int = 100):
        self.timeout = timeout
        self.max_workers = max_workers
        self.status = PortScanStatus()
        self.stop_event = asyncio.Event()
        
    async def scan_port(self, host: str, port: int) -> Tuple[int, str, str]:
        """Scan a single port"""
        try:
            # Update current port being scanned
            self.status.update_host_status(host, 'scanning', port)
            
            # Attempt connection
            future = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(future, timeout=self.timeout)
            
            # Close connection
            writer.close()
            await writer.wait_closed()
            
            # Get service name
            service = self.COMMON_PORTS.get(port, 'unknown')
            
            return port, 'open', service
            
        except asyncio.TimeoutError:
            return port, 'filtered', 'unknown'
        except ConnectionRefusedError:
            return port, 'closed', 'unknown'
        except Exception:
            return port, 'filtered', 'unknown'
    
    async def scan_host(self, host: str, ports: List[int]) -> Dict[str, Any]:
        """Scan all ports for a single host"""
        self.status.add_host(host, len(ports))
        self.status.update_host_status(host, 'scanning')
        
        host_results = {
            'host': host,
            'open_ports': {},
            'closed_ports': 0,
            'filtered_ports': 0,
            'total_ports': len(ports),
            'scan_time': 0
        }
        
        start_time = time.time()
        
        # Create semaphore to limit concurrent connections per host
        semaphore = asyncio.Semaphore(min(self.max_workers, 50))
        
        async def scan_port_with_semaphore(port: int):
            async with semaphore:
                if self.stop_event.is_set():
                    return None
                return await self.scan_port(host, port)
        
        # Scan all ports concurrently
        tasks = [scan_port_with_semaphore(port) for port in ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        for result in results:
            if result is None or isinstance(result, Exception):
                continue
                
            port, state, service = result
            self.status.add_port_result(host, port, state, service)
            
            if state == 'open':
                host_results['open_ports'][port] = {
                    'service': service,
                    'state': state
                }
            elif state == 'closed':
                host_results['closed_ports'] += 1
            else:
                host_results['filtered_ports'] += 1
        
        host_results['scan_time'] = time.time() - start_time
        self.status.update_host_status(host, 'completed')
        
        return host_results
    
    async def scan_multiple_hosts(self, hosts: List[str], ports: List[int]) -> Dict[str, Any]:
        """Scan multiple hosts concurrently"""
        console.print(f"[cyan]Starting enhanced port scan of {len(hosts)} hosts[/cyan]")
        console.print(f"[blue]Scanning {len(ports)} ports per host with {self.max_workers} workers[/blue]")
        
        # Create progress display
        layout = Layout()
        
        # Start scanning tasks
        tasks = [self.scan_host(host, ports) for host in hosts]
        
        # Display progress
        with Live(self.generate_progress_display(), refresh_per_second=2) as live:
            # Update display in background
            async def update_display():
                while not self.stop_event.is_set():
                    live.update(self.generate_progress_display())
                    await asyncio.sleep(0.5)
            
            display_task = asyncio.create_task(update_display())
            
            try:
                # Wait for all scans to complete
                results = await asyncio.gather(*tasks, return_exceptions=True)
                
                # Stop display updates
                self.stop_event.set()
                await display_task
                
                # Final update
                live.update(self.generate_progress_display())
                
                # Process results
                scan_results = {}
                for result in results:
                    if not isinstance(result, Exception):
                        scan_results[result['host']] = result
                
                # Generate summary
                summary = self.generate_summary(scan_results)
                
                return {
                    'results': scan_results,
                    'summary': summary,
                    'scan_status': self.status.get_status_summary()
                }
                
            except KeyboardInterrupt:
                console.print("\n[red]Scan interrupted by user[/red]")
                self.stop_event.set()
                await display_task
                return {'results': {}, 'summary': {}, 'interrupted': True}
    
    def generate_progress_display(self) -> Panel:
        """Generate live progress display"""
        summary = self.status.get_status_summary()
        host_details = self.status.get_host_details()
        
        # Main progress bar
        progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            MofNCompleteColumn(),
            TimeRemainingColumn(),
            expand=True
        )
        
        # Add main progress task
        task_id = progress.add_task(
            "Scanning ports...",
            total=summary['total_ports'],
            completed=summary['scanned_ports']
        )
        
        # Create layout
        layout = Layout()
        layout.split_column(
            Layout(Panel(progress, title="📊 Overall Progress", border_style="blue"), size=3),
            Layout(self.generate_stats_table(summary), size=8),
            Layout(self.generate_host_table(host_details), size=15)
        )
        
        return Panel(layout, title="🔍 Enhanced Port Scanner", border_style="cyan")
    
    def generate_stats_table(self, summary: Dict[str, Any]) -> Panel:
        """Generate statistics table"""
        table = Table(show_header=True, header_style="bold magenta", box=box.ROUNDED)
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green")
        table.add_column("Rate", style="yellow")
        
        table.add_row("Total Hosts", str(summary['total_hosts']), "")
        table.add_row("Completed Hosts", str(summary['completed_hosts']), "")
        table.add_row("Total Ports", str(summary['total_ports']), "")
        table.add_row("Scanned Ports", str(summary['scanned_ports']), f"{summary['scan_rate']:.1f} ports/sec")
        table.add_row("Open Ports", str(summary['open_ports']), "")
        table.add_row("Closed Ports", str(summary['closed_ports']), "")
        table.add_row("Filtered Ports", str(summary['filtered_ports']), "")
        table.add_row("Elapsed Time", f"{summary['elapsed_time']:.1f}s", "")
        table.add_row("ETA", f"{summary['eta']:.1f}s", "")
        table.add_row("Completion", f"{summary['completion_percentage']:.1f}%", "")
        
        return Panel(table, title="📈 Scan Statistics", border_style="green")
    
    def generate_host_table(self, host_details: List[Dict[str, Any]]) -> Panel:
        """Generate host details table"""
        table = Table(show_header=True, header_style="bold magenta", box=box.ROUNDED)
        table.add_column("Host", style="cyan")
        table.add_column("Status", style="white")
        table.add_column("Progress", style="green")
        table.add_column("Open", style="red")
        table.add_column("Closed", style="yellow")
        table.add_column("Filtered", style="blue")
        table.add_column("Current Port", style="magenta")
        table.add_column("Rate", style="white")
        
        for host_info in host_details:
            # Status with color
            status = host_info['status']
            if status == 'completed':
                status_text = Text("✅ Done", style="green")
            elif status == 'scanning':
                status_text = Text("🔄 Scanning", style="yellow")
            else:
                status_text = Text("⏳ Pending", style="blue")
            
            # Progress bar
            progress = host_info['progress']
            progress_text = f"{progress:.1f}%"
            
            # Current port
            current_port = host_info.get('current_port', '')
            current_port_text = str(current_port) if current_port else '-'
            
            # Scan rate
            scan_rate = host_info.get('scan_rate', 0)
            rate_text = f"{scan_rate:.1f} p/s" if scan_rate > 0 else '-'
            
            table.add_row(
                host_info['host'],
                status_text,
                progress_text,
                str(host_info['open_ports']),
                str(host_info['closed_ports']),
                str(host_info['filtered_ports']),
                current_port_text,
                rate_text
            )
        
        return Panel(table, title="🖥️ Host Details", border_style="yellow")
    
    def generate_summary(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate scan summary"""
        total_hosts = len(scan_results)
        total_open_ports = sum(len(result['open_ports']) for result in scan_results.values())
        total_closed_ports = sum(result['closed_ports'] for result in scan_results.values())
        total_filtered_ports = sum(result['filtered_ports'] for result in scan_results.values())
        
        # Find hosts with open ports
        vulnerable_hosts = [host for host, result in scan_results.items() if result['open_ports']]
        
        # Most common services
        service_counts = {}
        for result in scan_results.values():
            for port_info in result['open_ports'].values():
                service = port_info['service']
                service_counts[service] = service_counts.get(service, 0) + 1
        
        top_services = sorted(service_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        
        return {
            'total_hosts': total_hosts,
            'hosts_with_open_ports': len(vulnerable_hosts),
            'total_open_ports': total_open_ports,
            'total_closed_ports': total_closed_ports,
            'total_filtered_ports': total_filtered_ports,
            'vulnerable_hosts': vulnerable_hosts,
            'top_services': top_services,
            'scan_duration': self.status.get_status_summary()['elapsed_time']
        }
    
    def display_final_results(self, results: Dict[str, Any]):
        """Display final scan results"""
        console.print(Panel.fit("🎉 [bold green]Scan Complete![/bold green]", border_style="green"))
        
        summary = results['summary']
        
        # Summary table
        summary_table = Table(title="📊 Scan Summary", show_header=True, header_style="bold magenta")
        summary_table.add_column("Metric", style="cyan")
        summary_table.add_column("Value", style="green")
        
        summary_table.add_row("Total Hosts", str(summary['total_hosts']))
        summary_table.add_row("Hosts with Open Ports", str(summary['hosts_with_open_ports']))
        summary_table.add_row("Total Open Ports", str(summary['total_open_ports']))
        summary_table.add_row("Total Closed Ports", str(summary['total_closed_ports']))
        summary_table.add_row("Total Filtered Ports", str(summary['total_filtered_ports']))
        summary_table.add_row("Scan Duration", f"{summary['scan_duration']:.2f} seconds")
        
        console.print(summary_table)
        
        # Top services
        if summary['top_services']:
            services_table = Table(title="🔝 Top Services", show_header=True, header_style="bold magenta")
            services_table.add_column("Service", style="cyan")
            services_table.add_column("Count", style="green")
            
            for service, count in summary['top_services']:
                services_table.add_row(service, str(count))
            
            console.print(services_table)
        
        # Detailed results for each host
        for host, result in results['results'].items():
            if result['open_ports']:
                host_table = Table(title=f"🖥️ {host} - Open Ports", show_header=True, header_style="bold magenta")
                host_table.add_column("Port", style="cyan")
                host_table.add_column("Service", style="green")
                host_table.add_column("State", style="yellow")
                
                for port, port_info in result['open_ports'].items():
                    host_table.add_row(
                        str(port),
                        port_info['service'],
                        port_info['state']
                    )
                
                console.print(host_table)


async def main():
    """Test the enhanced port scanner"""
    scanner = EnhancedPortScanner(timeout=2, max_workers=100)
    
    # Test with multiple hosts
    hosts = ['127.0.0.1', '8.8.8.8', 'google.com']
    ports = [22, 80, 443, 8080, 21, 25, 53, 110, 143, 993, 995, 3389, 5432, 3306, 6379, 9200, 27017]
    
    try:
        results = await scanner.scan_multiple_hosts(hosts, ports)
        
        if not results.get('interrupted'):
            scanner.display_final_results(results)
        
    except KeyboardInterrupt:
        console.print("\n[red]Scan interrupted by user[/red]")


if __name__ == "__main__":
    asyncio.run(main())