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

    def save_results(self, results, filename=None, encrypt=False, format='json'):
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

    def display_disclaimer(self) -> bool:
        """
        Display legal disclaimer and require user acknowledgment.
        Returns True if user accepts, False if declined.
        """
        disclaimer = """
╔════════════════════ LEGAL DISCLAIMER ════════════════════╗
║                                                          ║
║  WARNING: This is a network security testing tool.       ║
║                                                          ║
║  By proceeding, you confirm that:                       ║
║                                                         ║
║  1. You have EXPLICIT PERMISSION to scan the target     ║
║     network/system                                      ║
║                                                         ║
║  2. You understand that unauthorized scanning may be     ║
║     ILLEGAL in your jurisdiction                        ║
║                                                         ║
║  3. You accept ALL RESPONSIBILITY for the use of this   ║
║     tool                                                ║
║                                                         ║
║  4. You will use this tool in accordance with all       ║
║     applicable laws and regulations                     ║
║                                                         ║
╚══════════════════════════════════════════════════════════╝
"""
        print(disclaimer)
        
        # Log the disclaimer display
        self.logger.info("Legal disclaimer displayed to user")
        
        try:
            # Ask for explicit confirmation
            confirmation = input("\nDo you accept these terms? (yes/no): ").lower().strip()
            
            if confirmation == 'yes':
                self.logger.info("User accepted legal disclaimer")
                print("\nDisclaimer accepted. Proceeding with scan...\n")
                return True
            else:
                self.logger.warning("User declined legal disclaimer")
                print("\nDisclaimer not accepted. Exiting program.")
                return False
            
        except KeyboardInterrupt:
            self.logger.warning("User interrupted disclaimer prompt")
            print("\nOperation cancelled by user.")
            return False

    def validate_ports(self, ports_str: str) -> List[int]:
        """Validate port numbers from string input."""
        try:
            ports = []
            for port in ports_str.split(','):
                port = int(port.strip())
                if not 1 <= port <= 65535:
                    raise ValueError(f"Port {port} is out of valid range (1-65535)")
                ports.append(port)
            return ports
        except ValueError as e:
            raise ValueError(f"Invalid port specification: {e}")

    def parse_arguments(self):
        """Parse command line arguments."""
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
        
        # For backward compatibility, if no command is specified, default to 'scan'
        args = parser.parse_args()
        if not args.command:
            args.command = 'scan'
            # Re-parse with default command
            args = parser.parse_args(['scan'] + sys.argv[1:])
        
        return args

    def expand_targets(self, target):
        """
        Expand target to a list of IP addresses if it's a CIDR range.
        Returns a list of target IP addresses.
        """
        try:
            # Check if the target is a CIDR range
            if '/' in target:
                network = ipaddress.ip_network(target, strict=False)
                # Convert to list of strings and limit to a reasonable number
                ip_list = [str(ip) for ip in network.hosts()]
                
                # If the range is large, warn the user
                if len(ip_list) > 256:
                    print(f"{Fore.YELLOW}Warning: Large IP range detected ({len(ip_list)} hosts). This may take a while.{Style.RESET_ALL}")
                    confirm = input("Do you want to continue? (y/n): ").lower()
                    if confirm != 'y':
                        self.logger.info("Scan cancelled by user due to large IP range")
                        sys.exit(0)
                
                return ip_list
            else:
                # Single target
                return [target]
        except ValueError:
            # Not a valid CIDR, assume it's a hostname
            self.logger.info(f"Target {target} is not a valid CIDR range, treating as hostname")
            return [target]

    async def scan_ports(self):
        """
        Scan the target for open ports using asyncio for concurrency.
        Returns a list of dictionaries with port and service information.
        """
        self.logger.info(f"Starting port scan on {self.target} for ports {self.ports}")
        
        start_time = time.time()
        open_ports = []
        semaphore = asyncio.Semaphore(self.threads)
        
        # Create tasks for all ports
        tasks = [self.scan_port(port) for port in self.ports]
        
        # Set up progress bar
        with tqdm(total=len(tasks), desc="Scanning ports", unit="port") as progress_bar:
            # Process tasks as they complete
            for future in asyncio.as_completed(tasks):
                result = await future
                if result:  # If port is open
                    open_ports.append(result)
                progress_bar.update(1)
        
        scan_duration = time.time() - start_time
        
        print(f"\n{Fore.CYAN}Scan completed in {scan_duration:.2f} seconds{Style.RESET_ALL}")
        self.logger.info(f"Scan complete. Found {len(open_ports)} open ports in {scan_duration:.2f} seconds")
        return open_ports

    def validate_target(self, target: str) -> str:
        """Validate target hostname or IP address."""
        if not target:
            raise ValueError("Target cannot be empty")
        
        # Remove any whitespace and protocol prefixes
        target = target.strip().lower()
        target = target.replace('http://', '').replace('https://', '')
        
        # Basic validation of hostname format
        if not all(c.isalnum() or c in '-._' for c in target.split('.')[0]):
            raise ValueError("Invalid target format")
            
        return target

    def display_results(self, results):
        """Display scan results in a formatted, colorized way."""
        if not results:
            print(f"{Fore.YELLOW}No open ports found on {self.target}{Style.RESET_ALL}")
            return
        
        print(f"\n{Fore.CYAN}=== Scan Results for {self.target} ==={Style.RESET_ALL}")
        print(f"{Fore.GREEN}Found {len(results)} open ports:{Style.RESET_ALL}")
        
        # Create a formatted table
        print(f"\n{Fore.CYAN}{'PORT':<10}{'STATE':<10}{'SERVICE':<15}{'VERSION':<30}{Style.RESET_ALL}")
        print("-" * 65)
        
        for result in results:
            port = result.get('port', 'N/A')
            service = result.get('service', 'Unknown')
            version = result.get('version', '')
            
            print(f"{Fore.GREEN}{port:<10}{'open':<10}{Style.RESET_ALL}{service:<15}{version:<30}")
        
        print(f"\n{Fore.CYAN}Scan completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}")

    def load_vulnerability_database(self):
        """
        Load vulnerability database from a local file or download from a remote source.
        Returns a dictionary of vulnerabilities indexed by service and version.
        """
        try:
            # First try to load from local file
            db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vuln_db.json")
            
            # Check if the database exists and is less than 7 days old
            update_db = True
            if os.path.exists(db_path):
                file_age = datetime.now().timestamp() - os.path.getmtime(db_path)
                if file_age < 7 * 24 * 60 * 60:  # 7 days in seconds
                    update_db = False
            
            if update_db:
                print(f"{Fore.CYAN}Updating vulnerability database...{Style.RESET_ALL}")
                # In a real implementation, you would download from a real vulnerability database
                # For this example, we'll create a simple database with some common vulnerabilities
                vuln_db = {
                    "HTTP": {
                        "Apache": [
                            {"id": "CVE-2021-41773", "severity": "HIGH", "description": "Path traversal vulnerability in Apache HTTP Server 2.4.49"},
                            {"id": "CVE-2021-42013", "severity": "HIGH", "description": "Path traversal vulnerability in Apache HTTP Server 2.4.50"}
                        ],
                        "nginx": [
                            {"id": "CVE-2021-23017", "severity": "MEDIUM", "description": "Nginx resolver vulnerability"}
                        ]
                    },
                    "SSH": {
                        "OpenSSH": [
                            {"id": "CVE-2020-14145", "severity": "LOW", "description": "OpenSSH client information leak"},
                            {"id": "CVE-2019-6111", "severity": "MEDIUM", "description": "OpenSSH SCP client arbitrary file write vulnerability"}
                        ]
                    },
                    "FTP": {
                        "vsftpd": [
                            {"id": "CVE-2011-2523", "severity": "HIGH", "description": "vsftpd 2.3.4 backdoor vulnerability"}
                        ]
                    },
                    "SMTP": {
                        "Exim": [
                            {"id": "CVE-2019-15846", "severity": "CRITICAL", "description": "Exim remote command execution vulnerability"}
                        ]
                    },
                    "MySQL": {
                        "MySQL": [
                            {"id": "CVE-2021-2307", "severity": "HIGH", "description": "MySQL Server privilege escalation vulnerability"}
                        ]
                    }
                }
                
                # Save the database to a local file
                with open(db_path, 'w') as f:
                    json.dump(vuln_db, f, indent=2)
                
                print(f"{Fore.GREEN}Vulnerability database updated successfully{Style.RESET_ALL}")
            else:
                # Load from local file
                with open(db_path, 'r') as f:
                    vuln_db = json.load(f)
                
                if self.verbose:
                    print(f"{Fore.CYAN}Using cached vulnerability database{Style.RESET_ALL}")
            
            return vuln_db
        
        except Exception as e:
            self.logger.error(f"Error loading vulnerability database: {e}")
            print(f"{Fore.YELLOW}Warning: Could not load vulnerability database. Vulnerability scanning will be limited.{Style.RESET_ALL}")
            return {}

    def check_vulnerabilities(self, results):
        """
        Check for known vulnerabilities based on service and version information.
        Returns the results with added vulnerability information.
        """
        vuln_db = self.load_vulnerability_database()
        
        if not vuln_db:
            return results
        
        for result in results:
            service = result.get('service', 'Unknown')
            version_full = result.get('version', '')
            
            # Initialize vulnerabilities list
            result['vulnerabilities'] = []
            
            # Skip if service is unknown or no version info
            if service == 'Unknown' or not version_full:
                continue
            
            # Check if the service exists in the vulnerability database
            if service in vuln_db:
                # Extract the software name from the version string
                # This is a simplified approach - in reality, you'd need more sophisticated parsing
                version_parts = version_full.split()
                software_candidates = []
                
                # Try to identify the software name
                for part in version_parts:
                    if part.lower() in [s.lower() for s in vuln_db[service].keys()]:
                        software_candidates.append(part)
                
                # If we couldn't identify the software, try common names
                if not software_candidates and service == "HTTP":
                    if "apache" in version_full.lower():
                        software_candidates.append("Apache")
                    elif "nginx" in version_full.lower():
                        software_candidates.append("nginx")
                
                # Check vulnerabilities for each potential software match
                for software in software_candidates:
                    for sw_name in vuln_db[service].keys():
                        if software.lower() == sw_name.lower():
                            # Add all vulnerabilities for this software
                            for vuln in vuln_db[service][sw_name]:
                                result['vulnerabilities'].append(vuln)
        
        return results

    def save_config_profile(self, profile_name, args):
        """
        Save the current scan configuration as a profile.
        """
        try:
            # Create config directory if it doesn't exist
            config_dir = Path.home() / '.gatekeeper' / 'profiles'
            config_dir.mkdir(parents=True, exist_ok=True)
            
            # Create the configuration dictionary
            config = {
                'target': args.target,
                'ports': args.ports,
                'timeout': args.timeout,
                'threads': args.threads,
                'format': args.format,
                'no_vuln_check': args.no_vuln_check,
                'verbose': args.verbose,
                'created_at': datetime.now().isoformat(),
                'description': args.description if hasattr(args, 'description') else ''
            }
            
            # Save the configuration to a YAML file
            config_file = config_dir / f"{profile_name}.yaml"
            with open(config_file, 'w') as f:
                yaml.dump(config, f, default_flow_style=False)
            
            print(f"{Fore.GREEN}Configuration profile '{profile_name}' saved successfully{Style.RESET_ALL}")
            self.logger.info(f"Configuration profile '{profile_name}' saved to {config_file}")
            return True
        
        except Exception as e:
            print(f"{Fore.RED}Error saving configuration profile: {e}{Style.RESET_ALL}")
            self.logger.error(f"Error saving configuration profile: {e}")
            return False

    def load_config_profile(self, profile_name):
        """
        Load a saved scan configuration profile.
        Returns a namespace object similar to what argparse would return.
        """
        try:
            # Find the profile file
            config_dir = Path.home() / '.gatekeeper' / 'profiles'
            config_file = config_dir / f"{profile_name}.yaml"
            
            if not config_file.exists():
                print(f"{Fore.RED}Profile '{profile_name}' not found{Style.RESET_ALL}")
                self.logger.error(f"Profile '{profile_name}' not found at {config_file}")
                return None
            
            # Load the configuration from the YAML file
            with open(config_file, 'r') as f:
                config = yaml.safe_load(f)
            
            # Convert to a namespace object
            args = argparse.Namespace()
            for key, value in config.items():
                setattr(args, key, value)
            
            print(f"{Fore.GREEN}Loaded configuration profile '{profile_name}'{Style.RESET_ALL}")
            if hasattr(args, 'description') and args.description:
                print(f"{Fore.CYAN}Description: {args.description}{Style.RESET_ALL}")
            
            self.logger.info(f"Loaded configuration profile '{profile_name}' from {config_file}")
            return args
        
        except Exception as e:
            print(f"{Fore.RED}Error loading configuration profile: {e}{Style.RESET_ALL}")
            self.logger.error(f"Error loading configuration profile: {e}")
            return None

    def list_config_profiles(self):
        """
        List all available configuration profiles.
        """
        try:
            # Find all profile files
            config_dir = Path.home() / '.gatekeeper' / 'profiles'
            
            if not config_dir.exists():
                print(f"{Fore.YELLOW}No configuration profiles found{Style.RESET_ALL}")
                return []
            
            profiles = list(config_dir.glob('*.yaml'))
            
            if not profiles:
                print(f"{Fore.YELLOW}No configuration profiles found{Style.RESET_ALL}")
                return []
            
            print(f"{Fore.CYAN}Available configuration profiles:{Style.RESET_ALL}")
            
            profile_info = []
            for profile_path in profiles:
                profile_name = profile_path.stem
                
                # Load the profile to get additional info
                try:
                    with open(profile_path, 'r') as f:
                        config = yaml.safe_load(f)
                    
                    created_at = config.get('created_at', 'Unknown')
                    if isinstance(created_at, str):
                        try:
                            created_at = datetime.fromisoformat(created_at).strftime('%Y-%m-%d %H:%M')
                        except:
                            pass
                    
                    target = config.get('target', 'Unknown')
                    description = config.get('description', '')
                    
                    profile_info.append({
                        'name': profile_name,
                        'target': target,
                        'created_at': created_at,
                        'description': description
                    })
                    
                    print(f"  {Fore.GREEN}{profile_name}{Style.RESET_ALL}")
                    print(f"    Target: {target}")
                    print(f"    Created: {created_at}")
                    if description:
                        print(f"    Description: {description}")
                    print()
                
        except Exception as e:
                    print(f"  {Fore.YELLOW}{profile_name} (Error: {e}){Style.RESET_ALL}")
                    profile_info.append({'name': profile_name, 'error': str(e)})
            
            return profile_info
        
        except Exception as e:
            print(f"{Fore.RED}Error listing configuration profiles: {e}{Style.RESET_ALL}")
            self.logger.error(f"Error listing configuration profiles: {e}")
            return []

    def delete_config_profile(self, profile_name):
        """
        Delete a saved configuration profile.
        """
        try:
            # Find the profile file
            config_dir = Path.home() / '.gatekeeper' / 'profiles'
            config_file = config_dir / f"{profile_name}.yaml"
            
            if not config_file.exists():
                print(f"{Fore.RED}Profile '{profile_name}' not found{Style.RESET_ALL}")
                return False
            
            # Delete the file
            config_file.unlink()
            
            print(f"{Fore.GREEN}Deleted configuration profile '{profile_name}'{Style.RESET_ALL}")
            self.logger.info(f"Deleted configuration profile '{profile_name}'")
            return True
        
        except Exception as e:
            print(f"{Fore.RED}Error deleting configuration profile: {e}{Style.RESET_ALL}")
            self.logger.error(f"Error deleting configuration profile: {e}")
            return False

    def main(self):
        """Main execution flow."""
        try:
            args = self.parse_arguments()
            
            # Handle profile commands
            if args.command == 'profile':
                if args.profile_command == 'list':
                    self.list_config_profiles()
                    return
                elif args.profile_command == 'show':
                    profile = self.load_config_profile(args.name)
                    if profile:
                        print(f"\n{Fore.CYAN}Profile details:{Style.RESET_ALL}")
                        for key, value in vars(profile).items():
                            if key != 'description':  # Already displayed
                                print(f"  {key}: {value}")
                    return
                elif args.profile_command == 'delete':
                    self.delete_config_profile(args.name)
                    return
            
            # Handle scan command
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

                self.display_disclaimer()
                if input("Do you accept these terms? (yes/no): ").lower().strip() != 'yes':
                    self.logger.info("Scan cancelled by user")
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

        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}Scan interrupted by user{Style.RESET_ALL}")
            self.logger.info("Scan interrupted by user")
            sys.exit(0)
        except Exception as e:
            self.logger.error(f"Error during execution: {e}")
            print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")
            sys.exit(1)

def main():
    # Display the banner first
    display_banner()
    
    scanner = GateKeeper()
    
    scanner.main()

if __name__ == "__main__":
    main() 