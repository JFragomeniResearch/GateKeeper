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
from utils.export import export_results
from utils.notifications import get_notification_manager
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
        # Define common ports as a class attribute to avoid duplication
        self.common_ports = {
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

    def _encrypt_file(self, file_path: str) -> bool:
        """
        Encrypt the contents of a file using Fernet symmetric encryption.
        
        Args:
            file_path: Path to the file to encrypt
            
        Returns:
            bool: True if encryption was successful, False otherwise
        """
        try:
            # Check if file exists
            if not os.path.exists(file_path):
                self.logger.error(f"File not found: {file_path}")
                return False
                
            # Read the file in binary mode
            with open(file_path, 'rb') as f:
                data = f.read()
                
            # Encrypt the data
            f = Fernet(self.encryption_key)
            encrypted_data = f.encrypt(data)
            
            # Write the encrypted data to a new file
            encrypted_file = f"{file_path}.enc"
            with open(encrypted_file, 'wb') as f:
                f.write(encrypted_data)
                
            # Delete the original file
            os.remove(file_path)
            
            self.logger.info(f"File encrypted successfully: {encrypted_file}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error encrypting file {file_path}: {e}")
            return False

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
                service_info["name"] = self.common_ports.get(port, f"Unknown-{port}")
            
            return service_info
        
        except asyncio.TimeoutError:
            # Connection timed out, but port is open
            return {"name": self.common_ports.get(port, f"Unknown-{port}"), "version": ""}
        
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

    def _log_and_print(self, message: str, level: str = 'info', color: str = Fore.GREEN) -> None:
        """
        Log a message and print it to the console with color.
        
        Args:
            message: The message to log and print
            level: The log level ('info', 'warning', 'error')
            color: The color to use for the console output
        """
        if level == 'info':
            self.logger.info(message)
        elif level == 'warning':
            self.logger.warning(message)
        elif level == 'error':
            self.logger.error(message)
        
        print(f"{color}{message}{Style.RESET_ALL}")

    def save_results(self, results, filename=None, encrypt=True, format='json', notify=False):
        """
        Save scan results to a file in the specified format.
        Supports JSON, CSV, and HTML formats.
        
        Args:
            results: Scan results to save
            filename: Output filename (without extension)
            encrypt: Whether to encrypt the results
            format: Output format (json, csv, html, all)
            notify: Whether to send notifications
            
        Returns:
            bool: True if successful, False otherwise
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
            json_file = f"{filename}.json"
            json_data = {
                "scan_info": {
                    "target": self.target,
                    "timestamp": datetime.now().isoformat(),
                    "ports_scanned": len(self.ports),
                    "open_ports_found": len(results),
                    "scan_duration": time.time() - self.start_time if self.start_time else 0
                },
                "results": results
            }
            
            if format in ['json', 'all']:
                with open(json_file, 'w') as f:
                    json.dump(json_data, f, indent=2)
                
                if encrypt:
                    self._encrypt_file(json_file)
                    self._log_and_print(f"Results saved and encrypted to {json_file}.enc")
                else:
                    self._log_and_print(f"Results saved to {json_file}")
            
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
                
                self._log_and_print(f"Results saved to {csv_file}")
            
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
            <td>{html.escape(str(version))}</td>
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
                
                self._log_and_print(f"Results saved to {html_file}")
            
            # Process notifications if enabled
            if notify:
                self.process_notifications(json_data)
            
            return True
        
        except Exception as e:
            self._log_and_print(f"Error saving results: {e}", level='error', color=Fore.RED)
            return False

    async def _scan_with_semaphore(self, semaphore: asyncio.Semaphore, port: int) -> Optional[Dict]:
        """
        Scan a single port with rate limiting and timeout, using a semaphore to limit concurrent connections.
        
        Args:
            semaphore: Semaphore to limit concurrent connections
            port: Port number to scan
            
        Returns:
            Optional[Dict]: Scan result if the port is open, None otherwise
        """
        async with semaphore:
            return await self.scan_port(port)

    async def scan_ports(self, ports: List[int]) -> List[Dict]:
        """
        Scan a list of ports using asyncio and rate limiting.
        
        Args:
            ports: List of port numbers to scan
            
        Returns:
            List[Dict]: List of scan results
        """
        semaphore = asyncio.Semaphore(self.threads)
        tasks = [self._scan_with_semaphore(semaphore, port) for port in ports]
        results = await asyncio.gather(*tasks)
        return [result for result in results if result is not None]

    def compare_reports(self, report1: str, report2: str) -> None:
        """
        Compare two scan reports and display the differences.
        
        Args:
            report1: Path to the first report file
            report2: Path to the second report file
        """
        comparer = ReportComparer(report1, report2)
        comparer.compare_reports()

    def list_available_reports(self) -> None:
        """
        List available scan reports in the reports directory.
        """
        reports = find_latest_reports(self.reports_dir)
        if not reports:
            self._log_and_print("No scan reports found in the reports directory.", color=Fore.YELLOW)
        else:
            self._log_and_print("Available scan reports:")
            for report in reports:
                print(f"  - {report}")

    def analyze_port_behavior(self, report_path: str) -> None:
        """
        Analyze port behavior from a scan report.
        
        Args:
            report_path: Path to the scan report file
        """
        analyzer = PortBehaviorAnalyzer(report_path)
        analyzer.analyze_port_behavior()

    def parse_ports(self, ports: str) -> List[int]:
        """
        Parse a string of port numbers and ranges into a list of integers.
        
        Args:
            ports: String of port numbers and ranges (e.g. "80,443,8000-8010")
            
        Returns:
            List[int]: List of unique port numbers
        """
        port_list = []
        for part in ports.split(','):
            if '-' in part:
                start, end = map(int, part.split('-'))
                port_list.extend(range(start, end + 1))
            else:
                port_list.append(int(part))
        return sorted(set(port_list))

    def scan(self, target: str, ports: List[int], policy: str = None, group: str = None, notify: bool = False) -> None:
        """
        Run a network scan on the specified target and ports.
        
        Args:
            target: Target IP address or hostname
            ports: List of port numbers to scan
            policy: Scan policy name (optional)
            group: Target group name (optional)
            notify: Whether to send notifications (optional)
        """
        self.target = target
        self.ports = ports
        
        # Load scan policy if provided
        if policy:
            policy_manager = get_policy_manager()
            policy_config = policy_manager.load_policy(policy)
            if policy_config:
                self.threads = policy_config.get('threads', self.threads)
                self.timeout = policy_config.get('timeout', self.timeout)
                self.rate_limit = policy_config.get('rate_limit', self.rate_limit)
                self.max_scan_rate = policy_config.get('max_scan_rate', self.max_scan_rate)
        
        # Load target group if provided
        if group:
            target_groups = get_target_groups()
            group_config = target_groups.load_group(group)
            if group_config:
                self.target = group_config.get('target', self.target)
                self.ports = group_config.get('ports', self.ports)
        
        # Verify DNS resolution
        if not self.verify_dns(self.target):
            self._log_and_print(f"DNS verification failed for {self.target}. Exiting.", level='error', color=Fore.RED)
            return
        
        # Display scan start banner
        display_scan_start(self.target, self.ports)
        
        # Run the scan
        self.start_time = time.time()
        results = asyncio.run(self.scan_ports(self.ports))
        
        # Display scan complete banner
        display_scan_complete(self.target, self.ports, results, time.time() - self.start_time)
        
        # Save results
        self.save_results(results, notify=notify)

    def process_notifications(self, scan_results: Dict[str, Any]) -> None:
        """
        Process scan results and send notifications based on configured rules.
        
        Args:
            scan_results: The scan results to process
        """
        try:
            notification_manager = get_notification_manager()
            if not notification_manager:
                self.logger.error("Failed to initialize notification manager")
                return
            
            self.logger.info("Processing notifications for scan results")
            
            # Process notifications - this will check rules and send notifications
            notification_results = notification_manager.process_scan_results(scan_results)
            
            # Log notification results
            if notification_results.get('notification_sent', False):
                self._log_and_print("Notifications sent for scan results")
                
                # Log triggered rules
                for rule in notification_results.get('rules_triggered', []):
                    rule_name = rule.get('rule_name', 'Unknown rule')
                    severity = rule.get('severity', 'info').upper()
                    severity_color = Fore.RED if severity == 'CRITICAL' else Fore.YELLOW if severity == 'WARNING' else Fore.CYAN
                    print(f"  {severity_color}[{severity}]{Style.RESET_ALL} Rule triggered: {rule_name}")
            else:
                self._log_and_print("No notifications were sent (no rules triggered or notifications disabled)", color=Fore.YELLOW)
        
        except Exception as e:
            self._log_and_print(f"Error processing notifications: {e}", level='error', color=Fore.RED)

    def main(self) -> None:
        """
        Main entry point for the GateKeeper application.
        """
        parser = argparse.ArgumentParser(description="GateKeeper Network Security Scanner")
        parser.add_argument("--target", help="Target IP address or hostname")
        parser.add_argument("--ports", help="Port numbers to scan (e.g. 80,443,8000-8010)")
        parser.add_argument("--policy", help="Scan policy name")
        parser.add_argument("--group", help="Target group name")
        parser.add_argument("--compare", nargs=2, metavar=("REPORT1", "REPORT2"), help="Compare two scan reports")
        parser.add_argument("--list-reports", action="store_true", help="List available scan reports")
        parser.add_argument("--analyze-behavior", metavar="REPORT", help="Analyze port behavior from a scan report")
        parser.add_argument("--export", metavar="REPORT", help="Export scan results to CSV and HTML")
        parser.add_argument("--notify", action="store_true", help="Send notifications based on scan results")
        
        args = parser.parse_args()
        
        if args.compare:
            self.compare_reports(*args.compare)
        elif args.list_reports:
            self.list_available_reports()
        elif args.analyze_behavior:
            self.analyze_port_behavior(args.analyze_behavior)
        elif args.export:
            export_results(args.export)
        else:
            if not args.target or not args.ports:
                parser.error("--target and --ports are required for a scan")
            
            ports = self.parse_ports(args.ports)
            self.scan(args.target, ports, args.policy, args.group, args.notify)

if __name__ == "__main__":
    gatekeeper = GateKeeper()
    gatekeeper.main()