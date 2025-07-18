#!/usr/bin/env python3
"""
Professional Linux Security Scanner
A high-performance security scanning tool for remote Linux servers
Author: Security Scanner Team
Version: 1.0.0
"""

import asyncio
import aiohttp
import socket
import ssl
import json
import csv
import ipaddress
import time
import sys
import os
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Optional, Tuple
import subprocess
import platform
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeRemainingColumn
from rich.panel import Panel
from rich.layout import Layout
from rich.live import Live
from rich.text import Text
from rich import box
from rich.prompt import Prompt, Confirm
import click
import nmap
import paramiko
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import warnings
warnings.filterwarnings("ignore")

# Console instance for rich output
console = Console()

class SecurityScanner:
    """High-performance security scanner for Linux servers"""
    
    COMMON_PORTS = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        111: "RPC",
        135: "MSRPC",
        139: "NetBIOS",
        143: "IMAP",
        443: "HTTPS",
        445: "SMB",
        993: "IMAPS",
        995: "POP3S",
        1723: "PPTP",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        5900: "VNC",
        8080: "HTTP-Proxy",
        8443: "HTTPS-Alt",
        27017: "MongoDB",
        6379: "Redis",
        9200: "Elasticsearch"
    }
    
    def __init__(self):
        self.results = {}
        self.scan_start_time = None
        self.scan_end_time = None
        self.total_hosts = 0
        self.scanned_hosts = 0
        self.vulnerable_hosts = 0
        
    def expand_cidr(self, cidr: str) -> List[str]:
        """Expand CIDR notation to list of IP addresses"""
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            return [str(ip) for ip in network.hosts()]
        except ValueError:
            return [cidr]  # Single IP
    
    async def check_port(self, host: str, port: int, timeout: float = 1.0) -> Tuple[int, bool, str]:
        """Asynchronously check if a port is open"""
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout
            )
            writer.close()
            await writer.wait_closed()
            return port, True, self.COMMON_PORTS.get(port, "Unknown")
        except:
            return port, False, ""
    
    async def scan_ports_async(self, host: str, ports: List[int]) -> Dict[int, Dict[str, Any]]:
        """Asynchronously scan multiple ports"""
        tasks = [self.check_port(host, port) for port in ports]
        results = await asyncio.gather(*tasks)
        
        open_ports = {}
        for port, is_open, service in results:
            if is_open:
                open_ports[port] = {
                    "state": "open",
                    "service": service,
                    "vulnerabilities": []
                }
        return open_ports
    
    def check_ssl_certificate(self, host: str, port: int = 443) -> Dict[str, Any]:
        """Check SSL certificate details and vulnerabilities"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((host, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    der_cert = ssock.getpeercert_binary()
                    cert = x509.load_der_x509_certificate(der_cert, default_backend())
                    
                    # Check expiration
                    now = datetime.utcnow()
                    expires = cert.not_valid_after
                    days_until_expiry = (expires - now).days
                    
                    return {
                        "issuer": cert.issuer.rfc4514_string(),
                        "subject": cert.subject.rfc4514_string(),
                        "expires": expires.isoformat(),
                        "days_until_expiry": days_until_expiry,
                        "expired": days_until_expiry < 0,
                        "expires_soon": 0 <= days_until_expiry <= 30,
                        "version": cert.version.name,
                        "serial_number": str(cert.serial_number)
                    }
        except Exception as e:
            return {"error": str(e)}
    
    def check_ssh_security(self, host: str, port: int = 22) -> Dict[str, Any]:
        """Check SSH configuration and vulnerabilities"""
        results = {
            "weak_algorithms": [],
            "version": None,
            "authentication_methods": [],
            "vulnerabilities": []
        }
        
        try:
            # Get SSH banner
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((host, port))
            banner = sock.recv(1024).decode('utf-8').strip()
            sock.close()
            
            results["version"] = banner
            
            # Check for old SSH versions
            if "SSH-1" in banner:
                results["vulnerabilities"].append("SSH Protocol 1 is deprecated and insecure")
            
            # Try to connect with paramiko to check authentication methods
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            try:
                transport = paramiko.Transport((host, port))
                transport.connect()
                results["authentication_methods"] = transport.get_security_options().key_types
                transport.close()
            except:
                pass
                
        except Exception as e:
            results["error"] = str(e)
            
        return results
    
    def run_nmap_scan(self, host: str) -> Dict[str, Any]:
        """Run comprehensive nmap scan"""
        try:
            nm = nmap.PortScanner()
            # Run OS detection, service version detection, and script scanning
            nm.scan(hosts=host, arguments='-sV -sC -O --script vuln')
            
            if host in nm.all_hosts():
                host_info = nm[host]
                
                result = {
                    "os": host_info.get('osmatch', [{}])[0].get('name', 'Unknown') if host_info.get('osmatch') else 'Unknown',
                    "services": {},
                    "vulnerabilities": []
                }
                
                # Process each protocol
                for proto in host_info.all_protocols():
                    ports = host_info[proto].keys()
                    for port in ports:
                        service_info = host_info[proto][port]
                        result["services"][port] = {
                            "name": service_info.get('name', 'unknown'),
                            "product": service_info.get('product', ''),
                            "version": service_info.get('version', ''),
                            "state": service_info.get('state', 'unknown')
                        }
                        
                        # Check for vulnerabilities in scripts output
                        if 'script' in service_info:
                            for script_name, script_output in service_info['script'].items():
                                if 'vuln' in script_name or 'VULNERABLE' in script_output:
                                    result["vulnerabilities"].append({
                                        "port": port,
                                        "script": script_name,
                                        "details": script_output
                                    })
                
                return result
        except Exception as e:
            return {"error": str(e)}
    
    def analyze_security(self, host_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze scan results and generate security score"""
        vulnerabilities = []
        security_score = 100
        
        # Check open ports
        if "open_ports" in host_data:
            dangerous_ports = [23, 135, 139, 445, 3389]  # Telnet, RPC, NetBIOS, SMB, RDP
            for port in host_data["open_ports"]:
                if port in dangerous_ports:
                    vulnerabilities.append(f"Dangerous port {port} ({self.COMMON_PORTS.get(port, 'Unknown')}) is open")
                    security_score -= 10
        
        # Check SSL certificate
        if "ssl_info" in host_data and host_data["ssl_info"]:
            ssl_info = host_data["ssl_info"]
            if ssl_info.get("expired"):
                vulnerabilities.append("SSL certificate has expired")
                security_score -= 20
            elif ssl_info.get("expires_soon"):
                vulnerabilities.append(f"SSL certificate expires in {ssl_info['days_until_expiry']} days")
                security_score -= 5
        
        # Check SSH
        if "ssh_info" in host_data and host_data["ssh_info"]:
            ssh_info = host_data["ssh_info"]
            if ssh_info.get("vulnerabilities"):
                vulnerabilities.extend(ssh_info["vulnerabilities"])
                security_score -= 15 * len(ssh_info["vulnerabilities"])
        
        # Nmap vulnerabilities
        if "nmap_scan" in host_data and host_data["nmap_scan"].get("vulnerabilities"):
            vulnerabilities.extend([v["details"] for v in host_data["nmap_scan"]["vulnerabilities"]])
            security_score -= 10 * len(host_data["nmap_scan"]["vulnerabilities"])
        
        security_score = max(0, security_score)
        
        return {
            "score": security_score,
            "rating": self.get_security_rating(security_score),
            "vulnerabilities": vulnerabilities,
            "recommendations": self.generate_recommendations(vulnerabilities)
        }
    
    def get_security_rating(self, score: int) -> str:
        """Get security rating based on score"""
        if score >= 90:
            return "Excellent"
        elif score >= 70:
            return "Good"
        elif score >= 50:
            return "Fair"
        elif score >= 30:
            return "Poor"
        else:
            return "Critical"
    
    def generate_recommendations(self, vulnerabilities: List[str]) -> List[str]:
        """Generate security recommendations based on vulnerabilities"""
        recommendations = []
        
        vuln_text = " ".join(vulnerabilities).lower()
        
        if "ssl certificate" in vuln_text:
            recommendations.append("Renew SSL certificate immediately")
        if "dangerous port" in vuln_text:
            recommendations.append("Close unnecessary dangerous ports or restrict access with firewall rules")
        if "ssh protocol 1" in vuln_text:
            recommendations.append("Upgrade to SSH Protocol 2 and disable Protocol 1")
        if "telnet" in vuln_text:
            recommendations.append("Disable Telnet and use SSH instead")
        if "smb" in vuln_text or "netbios" in vuln_text:
            recommendations.append("Disable SMB/NetBIOS if not needed, or restrict access")
        
        if not recommendations:
            recommendations.append("Continue monitoring and keep systems updated")
        
        return recommendations
    
    async def scan_host(self, host: str, progress) -> Dict[str, Any]:
        """Scan a single host"""
        task_id = progress.add_task(f"Scanning {host}", total=5)
        
        result = {
            "host": host,
            "scan_time": datetime.utcnow().isoformat(),
            "alive": False,
            "open_ports": {},
            "ssl_info": None,
            "ssh_info": None,
            "nmap_scan": None,
            "security_analysis": None
        }
        
        try:
            # Check if host is alive
            progress.update(task_id, advance=1, description=f"[cyan]Checking if {host} is alive...")
            if platform.system() == "Windows":
                ping_cmd = ["ping", "-n", "1", "-w", "1000", host]
            else:
                ping_cmd = ["ping", "-c", "1", "-W", "1", host]
            
            ping_result = subprocess.run(ping_cmd, capture_output=True, text=True)
            result["alive"] = ping_result.returncode == 0
            
            if result["alive"]:
                # Port scanning
                progress.update(task_id, advance=1, description=f"[yellow]Port scanning {host}...")
                ports_to_scan = list(self.COMMON_PORTS.keys())
                result["open_ports"] = await self.scan_ports_async(host, ports_to_scan)
                
                # SSL certificate check
                if 443 in result["open_ports"]:
                    progress.update(task_id, advance=1, description=f"[green]Checking SSL certificate on {host}...")
                    result["ssl_info"] = self.check_ssl_certificate(host)
                else:
                    progress.update(task_id, advance=1)
                
                # SSH security check
                if 22 in result["open_ports"]:
                    progress.update(task_id, advance=1, description=f"[blue]Checking SSH security on {host}...")
                    result["ssh_info"] = self.check_ssh_security(host)
                else:
                    progress.update(task_id, advance=1)
                
                # Nmap comprehensive scan
                progress.update(task_id, advance=1, description=f"[magenta]Running vulnerability scan on {host}...")
                result["nmap_scan"] = self.run_nmap_scan(host)
                
                # Security analysis
                result["security_analysis"] = self.analyze_security(result)
                
                if result["security_analysis"]["vulnerabilities"]:
                    self.vulnerable_hosts += 1
            else:
                progress.update(task_id, advance=5, description=f"[red]Host {host} is not responding")
                
        except Exception as e:
            result["error"] = str(e)
            progress.update(task_id, advance=5, description=f"[red]Error scanning {host}: {str(e)}")
        
        progress.remove_task(task_id)
        self.scanned_hosts += 1
        return result
    
    async def scan_network(self, targets: List[str]):
        """Scan multiple targets"""
        self.scan_start_time = datetime.utcnow()
        self.results = {}
        self.scanned_hosts = 0
        self.vulnerable_hosts = 0
        
        # Expand all targets
        all_hosts = []
        for target in targets:
            all_hosts.extend(self.expand_cidr(target))
        
        self.total_hosts = len(all_hosts)
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeRemainingColumn(),
            console=console
        ) as progress:
            
            # Create tasks for all hosts
            tasks = []
            for host in all_hosts:
                task = self.scan_host(host, progress)
                tasks.append(task)
            
            # Run scans concurrently
            results = await asyncio.gather(*tasks)
            
            # Store results
            for result in results:
                self.results[result["host"]] = result
        
        self.scan_end_time = datetime.utcnow()
    
    def generate_summary_table(self) -> Table:
        """Generate summary table of scan results"""
        table = Table(title="Security Scan Summary", box=box.ROUNDED)
        
        table.add_column("Host", style="cyan", no_wrap=True)
        table.add_column("Status", style="green")
        table.add_column("Open Ports", style="yellow")
        table.add_column("Security Score", style="magenta")
        table.add_column("Rating", style="white")
        table.add_column("Vulnerabilities", style="red")
        
        for host, data in self.results.items():
            if data.get("alive"):
                open_ports = len(data.get("open_ports", {}))
                security_score = data.get("security_analysis", {}).get("score", 0)
                rating = data.get("security_analysis", {}).get("rating", "Unknown")
                vuln_count = len(data.get("security_analysis", {}).get("vulnerabilities", []))
                
                # Color code based on score
                if security_score >= 70:
                    score_style = "green"
                elif security_score >= 50:
                    score_style = "yellow"
                else:
                    score_style = "red"
                
                table.add_row(
                    host,
                    "Online",
                    str(open_ports),
                    f"[{score_style}]{security_score}%[/{score_style}]",
                    rating,
                    str(vuln_count)
                )
            else:
                table.add_row(
                    host,
                    "[red]Offline[/red]",
                    "-",
                    "-",
                    "-",
                    "-"
                )
        
        return table
    
    def export_json(self, filename: str):
        """Export results to JSON"""
        export_data = {
            "scan_info": {
                "start_time": self.scan_start_time.isoformat(),
                "end_time": self.scan_end_time.isoformat(),
                "total_hosts": self.total_hosts,
                "hosts_scanned": self.scanned_hosts,
                "vulnerable_hosts": self.vulnerable_hosts
            },
            "results": self.results
        }
        
        with open(filename, 'w') as f:
            json.dump(export_data, f, indent=2)
        
        console.print(f"[green]Results exported to {filename}[/green]")
    
    def export_csv(self, filename: str):
        """Export results to CSV"""
        with open(filename, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                "Host", "Status", "Open Ports", "Security Score", 
                "Rating", "Vulnerabilities", "Recommendations"
            ])
            
            for host, data in self.results.items():
                if data.get("alive"):
                    open_ports = ",".join([str(p) for p in data.get("open_ports", {})])
                    security_score = data.get("security_analysis", {}).get("score", 0)
                    rating = data.get("security_analysis", {}).get("rating", "Unknown")
                    vulnerabilities = "; ".join(data.get("security_analysis", {}).get("vulnerabilities", []))
                    recommendations = "; ".join(data.get("security_analysis", {}).get("recommendations", []))
                    
                    writer.writerow([
                        host, "Online", open_ports, security_score,
                        rating, vulnerabilities, recommendations
                    ])
                else:
                    writer.writerow([host, "Offline", "", "", "", "", ""])
        
        console.print(f"[green]Results exported to {filename}[/green]")
    
    def export_html(self, filename: str):
        """Export results to HTML"""
        html_template = """
<!DOCTYPE html>
<html>
<head>
    <title>Security Scan Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: auto; background-color: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        h1 { color: #333; text-align: center; }
        .summary { background-color: #f0f0f0; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #4CAF50; color: white; }
        tr:hover { background-color: #f5f5f5; }
        .online { color: green; font-weight: bold; }
        .offline { color: red; font-weight: bold; }
        .score-excellent { color: green; font-weight: bold; }
        .score-good { color: #4CAF50; font-weight: bold; }
        .score-fair { color: orange; font-weight: bold; }
        .score-poor { color: #ff6b6b; font-weight: bold; }
        .score-critical { color: red; font-weight: bold; }
        .vulnerability { color: red; }
        .recommendation { color: blue; font-style: italic; }
        .details { margin-top: 30px; }
        .host-detail { background-color: #f9f9f9; padding: 15px; margin-bottom: 20px; border-radius: 5px; border-left: 4px solid #4CAF50; }
        .host-detail h3 { margin-top: 0; color: #333; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Linux Security Scan Report</h1>
        <div class="summary">
            <h2>Scan Summary</h2>
            <p><strong>Scan Start:</strong> {start_time}</p>
            <p><strong>Scan End:</strong> {end_time}</p>
            <p><strong>Total Hosts:</strong> {total_hosts}</p>
            <p><strong>Hosts Scanned:</strong> {scanned_hosts}</p>
            <p><strong>Vulnerable Hosts:</strong> {vulnerable_hosts}</p>
        </div>
        
        <h2>Results Overview</h2>
        <table>
            <tr>
                <th>Host</th>
                <th>Status</th>
                <th>Open Ports</th>
                <th>Security Score</th>
                <th>Rating</th>
                <th>Vulnerabilities</th>
            </tr>
            {table_rows}
        </table>
        
        <div class="details">
            <h2>Detailed Results</h2>
            {detailed_results}
        </div>
    </div>
</body>
</html>
"""
        
        # Generate table rows
        table_rows = ""
        detailed_results = ""
        
        for host, data in self.results.items():
            if data.get("alive"):
                open_ports = len(data.get("open_ports", {}))
                security_score = data.get("security_analysis", {}).get("score", 0)
                rating = data.get("security_analysis", {}).get("rating", "Unknown")
                vuln_count = len(data.get("security_analysis", {}).get("vulnerabilities", []))
                
                # Determine score class
                score_class = f"score-{rating.lower()}"
                
                table_rows += f"""
                <tr>
                    <td>{host}</td>
                    <td class="online">Online</td>
                    <td>{open_ports}</td>
                    <td class="{score_class}">{security_score}%</td>
                    <td>{rating}</td>
                    <td class="vulnerability">{vuln_count}</td>
                </tr>
                """
                
                # Detailed results
                vulnerabilities = data.get("security_analysis", {}).get("vulnerabilities", [])
                recommendations = data.get("security_analysis", {}).get("recommendations", [])
                open_ports_list = data.get("open_ports", {})
                
                detailed_results += f"""
                <div class="host-detail">
                    <h3>{host}</h3>
                    <p><strong>Security Score:</strong> <span class="{score_class}">{security_score}% ({rating})</span></p>
                    <p><strong>Open Ports:</strong> {', '.join([f"{port} ({self.COMMON_PORTS.get(port, 'Unknown')})" for port in open_ports_list])}</p>
                    """
                
                if vulnerabilities:
                    detailed_results += "<p><strong>Vulnerabilities:</strong></p><ul>"
                    for vuln in vulnerabilities:
                        detailed_results += f"<li class='vulnerability'>{vuln}</li>"
                    detailed_results += "</ul>"
                
                if recommendations:
                    detailed_results += "<p><strong>Recommendations:</strong></p><ul>"
                    for rec in recommendations:
                        detailed_results += f"<li class='recommendation'>{rec}</li>"
                    detailed_results += "</ul>"
                
                detailed_results += "</div>"
            else:
                table_rows += f"""
                <tr>
                    <td>{host}</td>
                    <td class="offline">Offline</td>
                    <td>-</td>
                    <td>-</td>
                    <td>-</td>
                    <td>-</td>
                </tr>
                """
        
        # Fill template
        html_content = html_template.format(
            start_time=self.scan_start_time.strftime("%Y-%m-%d %H:%M:%S UTC"),
            end_time=self.scan_end_time.strftime("%Y-%m-%d %H:%M:%S UTC"),
            total_hosts=self.total_hosts,
            scanned_hosts=self.scanned_hosts,
            vulnerable_hosts=self.vulnerable_hosts,
            table_rows=table_rows,
            detailed_results=detailed_results
        )
        
        with open(filename, 'w') as f:
            f.write(html_content)
        
        console.print(f"[green]Results exported to {filename}[/green]")

def display_banner():
    """Display application banner"""
    banner = """
[bold cyan]╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║           [bold white]Linux Security Scanner v1.0[/bold white]                      ║
║                                                              ║
║     High-Performance Remote Security Assessment Tool         ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝[/bold cyan]
"""
    console.print(banner)

def display_help():
    """Display help information"""
    help_text = """
[bold yellow]Usage:[/bold yellow]
  Enter IP addresses or CIDR ranges separated by commas
  Example: 192.168.1.1, 10.0.0.0/24, 172.16.0.1

[bold yellow]Features:[/bold yellow]
  • High-performance asynchronous scanning
  • Port scanning and service detection
  • SSL certificate validation
  • SSH security assessment
  • Vulnerability detection
  • Security scoring and recommendations
  • Export to JSON/CSV/HTML

[bold yellow]Commands:[/bold yellow]
  scan <targets>  - Start security scan
  help           - Show this help
  exit           - Exit application
"""
    console.print(help_text)

async def main():
    """Main application entry point"""
    display_banner()
    
    scanner = SecurityScanner()
    
    while True:
        try:
            console.print("\n[bold green]Enter target(s) to scan (IP/CIDR)[/bold green] or 'help' for usage:")
            user_input = Prompt.ask("λ")
            
            if user_input.lower() == 'exit':
                console.print("[yellow]Exiting...[/yellow]")
                break
            elif user_input.lower() == 'help':
                display_help()
                continue
            elif not user_input.strip():
                continue
            
            # Parse targets
            targets = [t.strip() for t in user_input.split(',')]
            
            console.print(f"\n[cyan]Preparing to scan {len(targets)} target(s)...[/cyan]")
            
            # Confirm scan
            if not Confirm.ask("Do you want to proceed with the scan?"):
                continue
            
            # Run scan
            console.print("\n[bold yellow]Starting security scan...[/bold yellow]\n")
            await scanner.scan_network(targets)
            
            # Display results
            console.print("\n" + "="*80 + "\n")
            console.print(scanner.generate_summary_table())
            
            # Scan statistics
            scan_duration = (scanner.scan_end_time - scanner.scan_start_time).total_seconds()
            console.print(f"\n[green]Scan completed in {scan_duration:.2f} seconds[/green]")
            console.print(f"[cyan]Hosts scanned: {scanner.scanned_hosts}/{scanner.total_hosts}[/cyan]")
            console.print(f"[red]Vulnerable hosts: {scanner.vulnerable_hosts}[/red]")
            
            # Export options
            if Confirm.ask("\nDo you want to export the results?"):
                export_format = Prompt.ask(
                    "Select export format",
                    choices=["json", "csv", "html", "all"],
                    default="json"
                )
                
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                
                if export_format in ["json", "all"]:
                    scanner.export_json(f"security_scan_{timestamp}.json")
                if export_format in ["csv", "all"]:
                    scanner.export_csv(f"security_scan_{timestamp}.csv")
                if export_format in ["html", "all"]:
                    scanner.export_html(f"security_scan_{timestamp}.html")
            
            # Show detailed results
            if Confirm.ask("\nDo you want to see detailed results?"):
                for host, data in scanner.results.items():
                    if data.get("alive"):
                        console.print(f"\n[bold cyan]Host: {host}[/bold cyan]")
                        
                        # Security analysis
                        if "security_analysis" in data:
                            analysis = data["security_analysis"]
                            score = analysis.get("score", 0)
                            rating = analysis.get("rating", "Unknown")
                            
                            # Color based on score
                            if score >= 70:
                                score_color = "green"
                            elif score >= 50:
                                score_color = "yellow"
                            else:
                                score_color = "red"
                            
                            console.print(f"Security Score: [{score_color}]{score}% ({rating})[/{score_color}]")
                            
                            # Vulnerabilities
                            vulnerabilities = analysis.get("vulnerabilities", [])
                            if vulnerabilities:
                                console.print("\n[red]Vulnerabilities:[/red]")
                                for vuln in vulnerabilities:
                                    console.print(f"  • {vuln}")
                            
                            # Recommendations
                            recommendations = analysis.get("recommendations", [])
                            if recommendations:
                                console.print("\n[yellow]Recommendations:[/yellow]")
                                for rec in recommendations:
                                    console.print(f"  • {rec}")
                        
                        # Open ports
                        if "open_ports" in data and data["open_ports"]:
                            console.print("\n[cyan]Open Ports:[/cyan]")
                            for port, info in data["open_ports"].items():
                                console.print(f"  • {port} ({info.get('service', 'Unknown')})")
                        
                        console.print("-" * 40)
            
        except KeyboardInterrupt:
            console.print("\n[yellow]Scan interrupted by user[/yellow]")
        except Exception as e:
            console.print(f"[red]Error: {str(e)}[/red]")

if __name__ == "__main__":
    # Check for required permissions
    if platform.system() != "Windows" and os.geteuid() != 0:
        console.print("[red]Warning: Some features require root privileges for accurate results[/red]")
        if not Confirm.ask("Continue anyway?"):
            sys.exit(1)
    
    # Run the application
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print("\n[yellow]Application terminated[/yellow]")
        sys.exit(0)