#!/usr/bin/env python3

import argparse
import socket
import sys
import concurrent.futures
from datetime import datetime
from pathlib import Path
import logging
import time
import dns.resolver  # for DNS verification
from cryptography.fernet import Fernet  # for encryption
import json
from typing import List, Tuple, Dict, Optional, Any
from utils.banner import display_banner, display_scan_start, display_scan_complete
from utils.report_compare import ReportComparer, find_latest_reports
from utils.port_behavior import PortBehaviorAnalyzer
from utils.scan_policy import get_policy_manager
from utils.target_groups import get_target_groups
import asyncio
from tqdm import tqdm
from colorama import init, Fore, Style
import ipaddress
import re
import os
import requests
import csv
import html
import yaml
import shutil
import py_cui
import threading
import queue

# Initialize colorama
init(autoreset=True)  # Automatically reset colors after each print

class GateKeeper:
    def __init__(self):
        self.logger = self._setup_logging()
        self.start_time = None
        self.target = None
        self.ports = []
        self.threads = 100
        self.timeout = 1
        self.rate_limit = 0.1
        self.max_scan_rate = 1000  # maximum ports per second
        self.encryption_key = self._generate_encryption_key()
        self.reports_dir = Path('reports')
        
    def _generate_encryption_key(self) -> bytes:
        """Generate encryption key for results."""
        try:
            key = Fernet.generate_key()
            if not isinstance(key, bytes) or len(key) != 44:  # Fernet keys are 44 bytes when base64 encoded
                raise ValueError("Invalid key format generated")
            return key
        except ValueError as e:
            # Re-raise ValueError directly
            raise e
        except Exception as e:
            raise RuntimeError(f"Failed to generate encryption key: {e}")

    def _setup_logging(self) -> logging.Logger:
        """Set up logging configuration."""
        logger = logging.getLogger('GateKeeper')
        logger.setLevel(logging.INFO)
        
        # Create logs directory if it doesn't exist
        log_file = Path('logs/gatekeeper.log')
        log_file.parent.mkdir(exist_ok=True)
        
        # Add handlers
        logger.addHandler(
            logging.FileHandler(log_file),
        )
        logger.addHandler(
            logging.StreamHandler()
        )
        
        return logger

    def verify_dns(self, target: str) -> bool:
        """Verify DNS resolution for target."""
        try:
            socket.gethostbyname(target)
            return True
        except socket.gaierror as e:
            self.logger.error(f"DNS verification failed for {target}: {e}")
            return False  # Return False instead of raising exception

    async def scan_port(self, port: int) -> Optional[Dict]:
        """Scan a single port with rate limiting and timeout"""
        if not 0 <= port <= 65535:
            raise ValueError(f"Port number must be between 0 and 65535, got {port}")
        
        try:
            # Implement rate limiting
            time.sleep(self.rate_limit)
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            result = sock.connect_ex((self.target, port))
            
            if result == 0:
                service = await self._identify_service(port)
                self.logger.info(f"Port {port} is open ({service})")
                return {
                    'port': port,
                    'status': 'open',
                    'service': service,
                    'timestamp': datetime.now().isoformat()
                }
            
            sock.close()
            return None
            
        except Exception as e:
            self.logger.error(f"Error scanning port {port}: {str(e)}")
            return None

    async def _identify_service(self, port: int) -> Optional[str]:
        """
        Identify the service running on a specific port.
        Returns the service name and version if detected.
        """
        try:
            reader, writer = await asyncio.open_connection(
                self.target, port, timeout=self.timeout
            )
            
            # Send appropriate probes based on common port numbers
            probe_data = b""
            if port == 80 or port == 443 or port == 8080:
                # HTTP probe
                probe_data = b"GET / HTTP/1.1\r\nHost: " + self.target.encode() + b"\r\n\r\n"
            elif port == 21:
                # FTP probe - just connect, no need to send data
                pass
            elif port == 22:
                # SSH probe - just connect, no need to send data
                pass
            elif port == 25 or port == 587:
                # SMTP probe
                probe_data = b"EHLO gatekeeper.scan\r\n"
            elif port == 110:
                # POP3 probe
                pass
            elif port == 143:
                # IMAP probe
                pass
            elif port == 3306:
                # MySQL probe
                pass
            
            # Send probe if we have one
            if probe_data:
                writer.write(probe_data)
                await writer.drain()
            
            # Read response with timeout
            response = await asyncio.wait_for(reader.read(1024), timeout=self.timeout)
            
            # Close the connection
            writer.close()
            await writer.wait_closed()
            
            # Decode response if possible
            try:
                response_str = response.decode('utf-8', errors='ignore')
            except:
                response_str = str(response)
            
            # Identify service and version based on response
            service_info = {"name": "Unknown", "version": ""}
            
            # HTTP detection
            if b"HTTP/" in response:
                service_info["name"] = "HTTP"
                # Try to extract server info
                server_match = re.search(r"Server: ([^\r\n]+)", response_str)
                if server_match:
                    service_info["version"] = server_match.group(1)
            
            # SSH detection
            elif b"SSH-" in response:
                service_info["name"] = "SSH"
                # Extract SSH version
                ssh_match = re.search(r"SSH-\d+\.\d+-([^\r\n]+)", response_str)
                if ssh_match:
                    service_info["version"] = ssh_match.group(1)
            
            # FTP detection
            elif b"FTP" in response or b"220" in response and (b"ftp" in response.lower() or port == 21):
                service_info["name"] = "FTP"
                # Extract FTP server version
                ftp_match = re.search(r"220[- ]([^\r\n]+)", response_str)
                if ftp_match:
                    service_info["version"] = ftp_match.group(1)
            
            # SMTP detection
            elif b"SMTP" in response or b"220" in response and b"mail" in response.lower():
                service_info["name"] = "SMTP"
                # Extract SMTP server version
                smtp_match = re.search(r"220[- ]([^\r\n]+)", response_str)
                if smtp_match:
                    service_info["version"] = smtp_match.group(1)
            
            # MySQL detection
            elif b"mysql" in response.lower() or port == 3306:
                service_info["name"] = "MySQL"
                # Extract MySQL version if possible
                mysql_match = re.search(r"([0-9]+\.[0-9]+\.[0-9]+)", response_str)
                if mysql_match:
                    service_info["version"] = mysql_match.group(1)
            
            # If no specific service detected, use port number as a hint
            if service_info["name"] == "Unknown":
                common_ports = {
                    21: "FTP",
                    22: "SSH",
                    23: "Telnet",
                    25: "SMTP",
                    53: "DNS",
                    80: "HTTP",
                    110: "POP3",
                    143: "IMAP",
                    443: "HTTPS",
                    465: "SMTPS",
                    587: "SMTP",
                    993: "IMAPS",
                    995: "POP3S",
                    3306: "MySQL",
                    3389: "RDP",
                    5432: "PostgreSQL",
                    8080: "HTTP-Proxy"
                }
                service_info["name"] = common_ports.get(port, f"Unknown-{port}")
            
            return service_info
        
        except asyncio.TimeoutError:
            # Connection timed out, but port is open
            common_ports = {
                21: "FTP",
                22: "SSH",
                23: "Telnet",
                25: "SMTP",
                53: "DNS",
                80: "HTTP",
                110: "POP3",
                143: "IMAP",
                443: "HTTPS",
                465: "SMTPS",
                587: "SMTP",
                993: "IMAPS",
                995: "POP3S",
                3306: "MySQL",
                3389: "RDP",
                5432: "PostgreSQL",
                8080: "HTTP-Proxy"
            }
            return {"name": common_ports.get(port, f"Unknown-{port}"), "version": ""}
        
        except Exception as e:
            self.logger.error(f"Service identification failed for port {port}: {e}")
            return {"name": f"Unknown-{port}", "version": ""}

    def encrypt_results(self, results: List[Dict]) -> bytes:
        """Encrypt scan results"""
        f = Fernet(self.encryption_key)
        data = json.dumps(results).encode()
        return f.encrypt(data)

    def decrypt_results(self, encrypted_data: bytes) -> List[Dict]:
        """Decrypt scan results."""
        if not encrypted_data:
            raise ValueError("Cannot decrypt empty data")
            
        try:
            f = Fernet(self.encryption_key)
            decrypted_data = f.decrypt(encrypted_data)
            return json.loads(decrypted_data.decode())
        except Exception as e:
            raise ValueError(f"Failed to decrypt results: {e}")

    def save_results(self, results, filename=None, encrypt=True, format='json'):
        """
        Save scan results to a file in the specified format.
        Supports JSON, CSV, and HTML formats.
        """
        if not results:
            self.logger.warning("No results to save")
            return False
        
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"gatekeeper_scan_{timestamp}"
        
        # Remove any extension from the filename
        filename = os.path.splitext(filename)[0]
        
        try:
            # Save in JSON format
            if format in ['json', 'all']:
                json_file = f"{filename}.json"
                with open(json_file, 'w') as f:
                    json_data = {
                        "scan_info": {
                            "target": self.target,
                            "timestamp": datetime.now().isoformat(),
                            "ports_scanned": len(self.ports),
                            "open_ports_found": len(results)
                        },
                        "results": results
                    }
                    json.dump(json_data, f, indent=2)
                
                if encrypt:
                    self._encrypt_file(json_file)
                    self.logger.info(f"Results saved and encrypted to {json_file}.enc")
                    print(f"{Fore.GREEN}Results saved and encrypted to {json_file}.enc{Style.RESET_ALL}")
                else:
                    self.logger.info(f"Results saved to {json_file}")
                    print(f"{Fore.GREEN}Results saved to {json_file}{Style.RESET_ALL}")
            
            # Save in CSV format
            if format in ['csv', 'all']:
                csv_file = f"{filename}.csv"
                with open(csv_file, 'w', newline='') as f:
                    # Determine all possible fields from results
                    fieldnames = ['port', 'state', 'service', 'version']
                    
                    # Check if we have vulnerability data
                    has_vulns = any('vulnerabilities' in result for result in results)
                    if has_vulns:
                        fieldnames.extend(['vuln_id', 'severity', 'description'])
                    
                    writer = csv.DictWriter(f, fieldnames=fieldnames)
                    writer.writeheader()
                    
                    for result in results:
                        # Base row with port information
                        row = {
                            'port': result.get('port', ''),
                            'state': result.get('state', ''),
                            'service': result.get('service', ''),
                            'version': result.get('version', '')
                        }
                        
                        # If no vulnerabilities, write the row as is
                        if not has_vulns or 'vulnerabilities' not in result or not result['vulnerabilities']:
                            writer.writerow(row)
                        else:
                            # Write a row for each vulnerability
                            for vuln in result['vulnerabilities']:
                                vuln_row = row.copy()
                                vuln_row['vuln_id'] = vuln.get('id', '')
                                vuln_row['severity'] = vuln.get('severity', '')
                                vuln_row['description'] = vuln.get('description', '')
                                writer.writerow(vuln_row)
                
                self.logger.info(f"Results saved to {csv_file}")
                print(f"{Fore.GREEN}Results saved to {csv_file}{Style.RESET_ALL}")
            
            # Save in HTML format
            if format in ['html', 'all']:
                html_file = f"{filename}.html"
                with open(html_file, 'w') as f:
                    # Create a simple HTML report
                    html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>GateKeeper Scan Report - {html.escape(self.target)}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1, h2 {{ color: #2c3e50; }}
        table {{ border-collapse: collapse; width: 100%; margin-bottom: 20px; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
        tr:nth-child(even) {{ background-color: #f9f9f9; }}
        .critical {{ color: #e74c3c; font-weight: bold; }}
        .high {{ color: #e67e22; font-weight: bold; }}
        .medium {{ color: #f1c40f; }}
        .low {{ color: #27ae60; }}
        .footer {{ margin-top: 30px; font-size: 0.8em; color: #7f8c8d; }}
    </style>
</head>
<body>
    <h1>GateKeeper Scan Report</h1>
    <p><strong>Target:</strong> {html.escape(self.target)}</p>
    <p><strong>Scan Date:</strong> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
    <p><strong>Open Ports:</strong> {len(results)} out of {len(self.ports)} scanned</p>
    
    <h2>Open Ports</h2>
    <table>
        <tr>
            <th>Port</th>
            <th>State</th>
            <th>Service</th>
            <th>Version</th>
        </tr>
"""
                    
                    # Add rows for each open port
                    for result in results:
                        port = result.get('port', '')
                        state = result.get('state', '')
                        service = result.get('service', '')
                        version = result.get('version', '')
                        
                        html_content += f"""        <tr>
            <td>{port}</td>
            <td>{state}</td>
            <td>{service}</td>
            <td>{html.escape(version)}</td>
        </tr>
"""
                    
                    # Check if we have vulnerability data
                    has_vulns = any('vulnerabilities' in result and result['vulnerabilities'] for result in results)
                    if has_vulns:
                        html_content += """    </table>
    
    <h2>Potential Vulnerabilities</h2>
    <table>
        <tr>
            <th>Port</th>
            <th>Service</th>
            <th>Severity</th>
            <th>CVE ID</th>
            <th>Description</th>
        </tr>
"""
                        
                        # Add rows for each vulnerability
                        for result in results:
                            if 'vulnerabilities' in result and result['vulnerabilities']:
                                port = result.get('port', '')
                                service = result.get('service', '')
                                
                                for vuln in result['vulnerabilities']:
                                    severity = vuln.get('severity', '')
                                    vuln_id = vuln.get('id', '')
                                    description = vuln.get('description', '')
                                    
                                    # Add CSS class based on severity
                                    severity_class = severity.lower() if severity.lower() in ['critical', 'high', 'medium', 'low'] else ''
                                    
                                    html_content += f"""        <tr>
            <td>{port}</td>
            <td>{service}</td>
            <td class="{severity_class}">{severity}</td>
            <td>{vuln_id}</td>
            <td>{html.escape(description)}</td>
        </tr>
"""
                    
                    # Close the HTML document
                    html_content += """    </table>
    
    <div class="footer">
        <p>Generated by GateKeeper Network Security Scanner</p>
    </div>
</body>
</html>
"""
                    
                    f.write(html_content)
                
                self.logger.info(f"Results saved to {html_file}")
                print(f"{Fore.GREEN}Results saved to {html_file}{Style.RESET_ALL}")
            
            return True
        
        except Exception as e:
            self.logger.error(f"Error saving results: {e}")
            print(f"{Fore.RED}Error saving results: {e}{Style.RESET_ALL}")
            return False

    def compare_reports(self, report1_path: str, report2_path: str, output_path: Optional[str] = None) -> str:
        """
        Compare two scan reports and identify differences.
        
        Args:
            report1_path: Path to first (baseline) report
            report2_path: Path to second (comparison) report
            output_path: Path to save comparison results (optional)
            
        Returns:
            str: Path to the generated comparison report
        """
        self.logger.info(f"Comparing reports: {report1_path} and {report2_path}")
        
        try:
            from utils.report_compare import ReportComparer
            
            # Create a report comparer
            comparer = ReportComparer(report1_path, report2_path)
            
            # Load the reports
            if not comparer.load_reports():
                error_msg = "Failed to load reports"
                self.logger.error(error_msg)
                print(f"{Fore.RED}Error: {error_msg}{Style.RESET_ALL}")
                return None
            
            # Print comparison summary
            comparer.print_comparison_summary()
            
            # Generate comparison report
            output = comparer.generate_comparison_report(output_path)
            
            self.logger.info(f"Generated comparison report: {output}")
            return output
            
        except Exception as e:
            self.logger.error(f"Error comparing reports: {e}")
            print(f"{Fore.RED}Error comparing reports: {e}{Style.RESET_ALL}")
            return None
    
    def list_available_reports(self, limit: int = 10) -> None:
        """
        List available scan reports.
        
        Args:
            limit: Maximum number of reports to list
        """
        try:
            from utils.report_compare import find_latest_reports
            
            # Get the latest reports
            reports = find_latest_reports(limit=limit)
            
            if not reports:
                print(f"{Fore.YELLOW}No reports found in the reports directory.{Style.RESET_ALL}")
                return
            
            print(f"\n{Fore.CYAN}Available scan reports (most recent first):{Style.RESET_ALL}")
            for i, report in enumerate(reports, 1):
                report_path = Path(report)
                mod_time = datetime.fromtimestamp(report_path.stat().st_mtime)
                print(f"{i}. {report_path.name} - {mod_time.strftime('%Y-%m-%d %H:%M:%S')}")
            
            print(f"\nTo compare reports, use: gatekeeper.py --compare --report1 <path1> --report2 <path2>\n")
            
        except Exception as e:
            self.logger.error(f"Error listing reports: {e}")
            print(f"{Fore.RED}Error listing reports: {e}{Style.RESET_ALL}")

    def parse_arguments(self):
        """Parse command-line arguments."""
        parser = argparse.ArgumentParser(
            description="GateKeeper - Network Security Scanner",
            formatter_class=argparse.ArgumentDefaultsHelpFormatter
        )
        
        # Create subparsers for different commands
        subparsers = parser.add_subparsers(dest='command', help='Command to execute')
        
        # Scan command
        scan_parser = subparsers.add_parser('scan', help='Perform a port scan')
        scan_parser.add_argument('-t', '--target', help='Target IP address, hostname, or CIDR range')
        scan_parser.add_argument('-p', '--ports', default='1-1000', help='Port(s) to scan (e.g., 80,443 or 1-1000)')
        scan_parser.add_argument('--timeout', type=float, default=1.0, help='Timeout for connection attempts')
        scan_parser.add_argument('--threads', type=int, default=100, help='Number of concurrent threads')
        scan_parser.add_argument('-o', '--output', help='Output file for results (without extension)')
        scan_parser.add_argument('-f', '--format', choices=['json', 'csv', 'html', 'all'], default='json',
                            help='Output format for results')
        scan_parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
        scan_parser.add_argument('--no-vuln-check', action='store_true', help='Disable vulnerability checking')
        scan_parser.add_argument('--profile', help='Load settings from a saved profile')
        scan_parser.add_argument('--save-profile', help='Save current settings as a profile')
        scan_parser.add_argument('--description', help='Description for the saved profile')
        
        # Profile commands
        profile_parser = subparsers.add_parser('profile', help='Manage configuration profiles')
        profile_subparsers = profile_parser.add_subparsers(dest='profile_command', help='Profile command')
        
        # List profiles
        list_parser = profile_subparsers.add_parser('list', help='List available profiles')
        
        # Show profile details
        show_parser = profile_subparsers.add_parser('show', help='Show profile details')
        show_parser.add_argument('name', help='Profile name')
        
        # Delete profile
        delete_parser = profile_subparsers.add_parser('delete', help='Delete a profile')
        delete_parser.add_argument('name', help='Profile name')
        
        # Interactive mode
        interactive_parser = subparsers.add_parser('interactive', help='Start interactive TUI mode')
        
        # Add report comparison command
        compare_parser = subparsers.add_parser('compare', help='Compare scan reports')
        compare_parser.add_argument('--report1', required=True, help='Path to first (baseline) report')
        compare_parser.add_argument('--report2', required=True, help='Path to second (comparison) report')
        compare_parser.add_argument('-o', '--output', help='Output file for comparison results')
        
        # Add report listing command
        list_reports_parser = subparsers.add_parser('reports', help='List available scan reports')
        list_reports_parser.add_argument('-n', '--limit', type=int, default=10, help='Maximum number of reports to list')
        
        # Add port behavior analysis command
        behavior_parser = subparsers.add_parser('behavior', help='Analyze port behavior over time')
        behavior_parser.add_argument('-t', '--target', help='Target host to analyze (analyze all targets if not specified)')
        behavior_parser.add_argument('-n', '--max-reports', type=int, default=10, help='Maximum number of reports to analyze')
        behavior_parser.add_argument('-o', '--output', help='Output file for analysis results')
        
        # Add scan policy commands
        policy_parser = subparsers.add_parser('policies', help='Manage scan policies')
        policy_parser.add_argument('--list-policies', action='store_true', help='List available scan policies')
        
        # Add groups command
        groups_parser = subparsers.add_parser("groups", help="Manage target groups")
        groups_parser.add_argument("--list", action="store_true", help="List available target groups")
        groups_parser.add_argument("--show", help="Show details of a specific group")
        
        # For backward compatibility, if no command is specified, default to 'scan'
        args = parser.parse_args()
        if not args.command:
            args.command = 'scan'
            # Re-parse with default command
            args = parser.parse_args(['scan'] + sys.argv[1:])
        
        return args

    def analyze_port_behavior(self, target: Optional[str] = None, max_reports: int = 10, output_path: Optional[str] = None) -> str:
        """
        Analyze port behavior over time to detect anomalies.
        
        Args:
            target: Target host to analyze (None means all targets)
            max_reports: Maximum number of reports to analyze
            output_path: Path to save the analysis report
            
        Returns:
            str: Path to the generated analysis report
        """
        try:
            from utils.port_behavior import PortBehaviorAnalyzer
            
            print(f"{Fore.CYAN}Initializing port behavior analysis...{Style.RESET_ALL}")
            
            # Initialize analyzer
            analyzer = PortBehaviorAnalyzer(
                target=target,
                report_dir="reports",
                max_reports=max_reports
            )
            
            # Load reports
            print(f"{Fore.CYAN}Loading scan reports...{Style.RESET_ALL}")
            if not analyzer.load_reports():
                print(f"{Fore.RED}Failed to load reports. Please ensure you have scan reports in the reports directory.{Style.RESET_ALL}")
                return None
            
            # Build port history
            print(f"{Fore.CYAN}Building port history...{Style.RESET_ALL}")
            analyzer.build_port_history()
            
            # Detect anomalies
            print(f"{Fore.CYAN}Detecting anomalous behavior...{Style.RESET_ALL}")
            analyzer.detect_anomalies()
            
            # Print analysis summary
            analyzer.print_analysis_summary()
            
            # Generate report
            output = analyzer.generate_report(output_path)
            print(f"\n{Fore.GREEN}Analysis report saved to: {output}{Style.RESET_ALL}")
            
            self.logger.info(f"Port behavior analysis completed, report saved to {output}")
            return output
            
        except Exception as e:
            self.logger.error(f"Error analyzing port behavior: {e}")
            print(f"{Fore.RED}Error analyzing port behavior: {e}{Style.RESET_ALL}")
            return None

    def main(self):
        """Main execution function."""
        args = self.parse_arguments()
        
        # Handle interactive mode
        if args.command == 'interactive':
            self.start_interactive_mode()
            return
        
        # Handle profile commands
        elif args.command == 'profile':
            if args.profile_command == 'list':
                self.list_config_profiles()
                return
            elif args.profile_command == 'show':
                self.show_config_profile(args.name)
                return
            elif args.profile_command == 'delete':
                self.delete_config_profile(args.name)
                return
        
        # Handle report comparison
        elif args.command == 'compare':
            self.compare_reports(args.report1, args.report2, args.output)
            return
        
        # Handle report listing
        elif args.command == 'reports':
            self.list_available_reports(args.limit)
            return
            
        # Handle port behavior analysis
        elif args.command == 'behavior':
            self.analyze_port_behavior(args.target, args.max_reports, args.output)
            return
        
        # Handle scan command (default)
        elif args.command == 'scan':
            # Load profile if specified
            if args.profile:
                profile_args = self.load_config_profile(args.profile)
                if not profile_args:
                    sys.exit(1)

                # Override profile settings with command line arguments
                for key, value in vars(args).items():
                    if key not in ['command', 'profile'] and value is not None:
                        setattr(profile_args, key, value)
                
                args = profile_args
            
            # Check if target is specified
            if not args.target:
                print(f"{Fore.RED}Error: Target is required{Style.RESET_ALL}")
                sys.exit(1)
            
            self.target = args.target
            self.ports = self.validate_ports(args.ports)
            self.timeout = args.timeout
            self.threads = args.threads
            self.verbose = args.verbose

            # Display disclaimer and get user acceptance
            if not self.display_disclaimer():
                sys.exit(0)
            
            # Save profile if requested
            if args.save_profile:
                self.save_config_profile(args.save_profile, args)

            # Expand targets if CIDR notation is used
            targets = self.expand_targets(self.target)
            
            all_results = {}
            total_start_time = time.time()
            
            # Scan each target
            for i, target in enumerate(targets):
                if len(targets) > 1:
                    print(f"\n{Fore.CYAN}Scanning target {i+1}/{len(targets)}: {target}{Style.RESET_ALL}")
                
                self.target = target  # Update current target
                self.logger.info(f"Starting scan of {self.target}")
                
                # Scan ports
                results = asyncio.run(self.scan_ports())
                
                # Check for vulnerabilities if not disabled
                if not args.no_vuln_check:
                    print(f"\n{Fore.CYAN}Checking for vulnerabilities...{Style.RESET_ALL}")
                    results = self.check_vulnerabilities(results)
                
                all_results[target] = results
                
                # Display results for this target
                self.display_results(results)
                
                # Save results for this target
                if args.output:
                    output_file = f"{args.output}_{target.replace('.', '_')}" if len(targets) > 1 else args.output
                    self.save_results(results, filename=output_file, encrypt=False, format=args.format)
            
            total_duration = time.time() - total_start_time
            
            # Display summary if multiple targets were scanned
            if len(targets) > 1:
                print(f"\n{Fore.CYAN}=== Scan Summary ==={Style.RESET_ALL}")
                print(f"Scanned {len(targets)} targets in {total_duration:.2f} seconds")
                
                total_open = sum(len(results) for results in all_results.values())
                print(f"{Fore.GREEN}Found {total_open} open ports across all targets{Style.RESET_ALL}")
            
            self.logger.info("Scan complete")
            return

        # Handle scan policy commands
        elif args.command == 'policies':
            # New subcommand for managing policies
            # Use the standalone script for now
            os.system(f"python manage_policies.py {' '.join(sys.argv[2:])}")
            return

        # Handle groups command
        elif args.command == 'groups':
            self.handle_groups_command(args)
            return

        # If no valid command was found, print help
        else:
            self.parse_arguments().print_help()

    def handle_groups_command(self, args):
        """Handle the groups command."""
        groups_manager = get_target_groups()
        
        if args.list:
            groups_manager.print_groups()
        elif args.show:
            groups_manager.print_group_details(args.show)
        else:
            print(f"{Fore.YELLOW}Use --list to list all groups or --show GROUP_ID to show details of a specific group{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}For full group management, use the manage_groups.py script{Style.RESET_ALL}")

    def setup_argparse(self):
        """Set up command-line argument parsing."""
        parser = argparse.ArgumentParser(
            description="GateKeeper Network Scanner",
            epilog="A security tool for scanning networks and detecting changes"
        )
        
        subparsers = parser.add_subparsers(dest="command", help="Command to execute")
        
        # Scan command
        scan_parser = subparsers.add_parser("scan", help="Scan targets for open ports")
        scan_parser.add_argument("-t", "--target", help="Target host(s) to scan (comma-separated)")
        scan_parser.add_argument("-f", "--target-file", help="File containing target hosts (one per line)")
        scan_parser.add_argument("-g", "--group", help="Target group to scan")
        scan_parser.add_argument("-p", "--ports", help="Port(s) to scan (e.g., '80,443' or '1-1024')")
        scan_parser.add_argument("--threads", type=int, default=100, help="Number of threads to use")
        scan_parser.add_argument("--timeout", type=float, default=1.0, help="Connection timeout in seconds")
        scan_parser.add_argument("--rate-limit", type=float, default=0.1, help="Rate limiting between connection attempts")
        scan_parser.add_argument("--no-vuln-check", action="store_true", help="Skip vulnerability checking")
        scan_parser.add_argument("--output", "-o", help="Output file for scan results")
        scan_parser.add_argument("--format", default="json", choices=["json", "csv", "html", "all"], help="Output format")
        scan_parser.add_argument("--encrypt", action="store_true", help="Encrypt scan results")
        scan_parser.add_argument("--verbose", "-v", action="store_true", help="Show verbose output")
        scan_parser.add_argument("--profile", help="Load settings from a saved profile")
        scan_parser.add_argument("--save-profile", help="Save current settings to a profile")
        scan_parser.add_argument("--policy", help="Use a saved scan policy")
        scan_parser.add_argument("--list-policies", action="store_true", help="List available scan policies")
        scan_parser.add_argument("--list-groups", action="store_true", help="List available target groups")

    def get_targets(self, args):
        """
        Get a list of targets from command-line arguments, file, or target group.
        
        Args:
            args: Command-line arguments
            
        Returns:
            list: List of targets to scan
        """
        targets = []
        
        # Get targets from command line
        if args.target:
            targets.extend([t.strip() for t in args.target.split(',') if t.strip()])
        
        # Get targets from file
        if hasattr(args, 'target_file') and args.target_file:
            try:
                target_file = Path(args.target_file)
                if target_file.exists():
                    with open(target_file, 'r') as f:
                        file_targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                        targets.extend(file_targets)
                        self.logger.info(f"Loaded {len(file_targets)} targets from {args.target_file}")
                else:
                    self.logger.error(f"Target file {args.target_file} not found")
                    print(f"{Fore.RED}Error: Target file {args.target_file} not found{Style.RESET_ALL}")
            except Exception as e:
                self.logger.error(f"Failed to read target file {args.target_file}: {e}")
                print(f"{Fore.RED}Error reading target file: {str(e)}{Style.RESET_ALL}")
        
        # Get targets from group
        if hasattr(args, 'group') and args.group:
            try:
                from utils.target_groups import get_target_groups
                groups_manager = get_target_groups()
                group_targets = groups_manager.get_targets(args.group)
                
                if group_targets:
                    targets.extend(group_targets)
                    self.logger.info(f"Loaded {len(group_targets)} targets from group {args.group}")
                    print(f"{Fore.CYAN}Loaded {len(group_targets)} targets from group '{args.group}'{Style.RESET_ALL}")
                else:
                    self.logger.warning(f"No targets found in group {args.group}")
                    print(f"{Fore.YELLOW}Warning: No targets found in group '{args.group}'{Style.RESET_ALL}")
            except Exception as e:
                self.logger.error(f"Failed to get targets from group {args.group}: {e}")
                print(f"{Fore.RED}Error getting targets from group: {str(e)}{Style.RESET_ALL}")
        
        # Remove duplicates while preserving order
        unique_targets = []
        for target in targets:
            if target not in unique_targets:
                unique_targets.append(target)
        
        return unique_targets

    def scan_targets(self, args):
        """Scan targets for open ports and services."""
        # If listing policies was requested, show them and exit
        if args.list_policies:
            from utils.scan_policy import get_policy_manager
            policy_manager = get_policy_manager()
            policy_manager.print_policies()
            return
        
        # If listing groups was requested, show them and exit
        if args.list_groups:
            from utils.target_groups import get_target_groups
            groups_manager = get_target_groups()
            groups_manager.print_groups()
            return
        
        # If a policy was specified, apply it to the arguments
        if args.policy:
            from utils.scan_policy import get_policy_manager
            policy_manager = get_policy_manager()
            args = policy_manager.apply_policy_to_args(args.policy, args)
        
        # Ensure we have targets to scan
        targets = self.get_targets(args)
        if not targets:
            print(f"{Fore.RED}Error: No targets specified. Use -t/--target, -f/--target-file, or -g/--group{Style.RESET_ALL}")
            return

        # ... rest of the function remains unchanged ...