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
        """
        Verify DNS resolution for target with enhanced error handling.
        
        Args:
            target: Target hostname or IP address
            
        Returns:
            bool: True if DNS resolution succeeds, False otherwise
        """
        # Check if target is already an IP address
        try:
            ipaddress.ip_address(target)
            self.logger.info(f"Target {target} is already an IP address, skipping DNS resolution")
            return True
        except ValueError:
            # Not an IP address, proceed with DNS resolution
            pass
            
        try:
            # First try simple hostname resolution
            ip_address = socket.gethostbyname(target)
            self.logger.info(f"DNS resolution successful for {target}: {ip_address}")
            return True
        except socket.gaierror as e:
            # More detailed error handling based on error code
            if e.errno == socket.EAI_NONAME:
                self.logger.error(f"DNS resolution failed for {target}: Host not found")
            elif e.errno == socket.EAI_AGAIN:
                self.logger.error(f"DNS resolution failed for {target}: Temporary DNS server failure")
            elif e.errno == socket.EAI_FAIL:
                self.logger.error(f"DNS resolution failed for {target}: Non-recoverable DNS server failure")
            else:
                self.logger.error(f"DNS resolution failed for {target}: {e}")
            
            # Try alternative DNS lookup with dnspython as fallback
            try:
                resolver = dns.resolver.Resolver()
                resolver.timeout = 2.0
                resolver.lifetime = 4.0
                answers = resolver.resolve(target, 'A')
                if answers:
                    ip_address = answers[0].address
                    self.logger.info(f"Alternative DNS resolution successful for {target}: {ip_address}")
                    return True
            except Exception as dns_error:
                self.logger.error(f"Alternative DNS resolution also failed: {dns_error}")
            
            return False
        except Exception as e:
            self.logger.error(f"Unexpected error during DNS verification for {target}: {e}")
            return False

    async def scan_port(self, port: int) -> Optional[Dict]:
        """
        Scan a single port with rate limiting and timeout.
        
        Args:
            port: Port number to scan
            
        Returns:
            Optional[Dict]: Scan result if the port is open, None otherwise
        """
        if not 0 <= port <= 65535:
            raise ValueError(f"Port number must be between 0 and 65535, got {port}")
        
        # Use asyncio.sleep instead of time.sleep for rate limiting in async functions
        await asyncio.sleep(self.rate_limit)
        
        # Create a socket for connection testing
        sock = None
        try:
            # Use low-level socket creation to control timing and options
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            # Attempt connection
            result = sock.connect_ex((self.target, port))
            
            if result == 0:
                # Connection successful - port is open
                service_info = await self._identify_service(port)
                self.logger.info(f"Port {port} is open ({service_info['name']})")
                
                return {
                    'port': port,
                    'status': 'open',
                    'service': service_info['name'],
                    'version': service_info['version'],
                    'timestamp': datetime.now().isoformat()
                }
            
            return None  # Port is closed or filtered
            
        except socket.timeout:
            self.logger.debug(f"Connection to port {port} timed out")
        except ConnectionRefusedError:
            self.logger.debug(f"Connection to port {port} refused")
        except (socket.gaierror, socket.error) as e:
            self.logger.error(f"Socket error scanning port {port}: {e}")
        except Exception as e:
            self.logger.error(f"Unexpected error scanning port {port}: {e}")
        finally:
            # Ensure socket is closed in all cases
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass
        
        return None  # Return None for all error cases

    def _get_service_probe(self, port: int) -> Optional[bytes]:
        """
        Get an appropriate probe for the given port.
        
        Args:
            port: The port number to get a probe for
            
        Returns:
            Optional[bytes]: The probe data as bytes, or None if no probe is needed
        """
        if port in [80, 443, 8080]:
            # HTTP probe
            return f"GET / HTTP/1.1\r\nHost: {self.target}\r\n\r\n".encode()
        elif port in [25, 587]:
            # SMTP probe
            return b"EHLO gatekeeper.scan\r\n"
        elif port == 21:
            # FTP probe - just connect, no need to send data
            return None
        elif port == 22:
            # SSH probe - just connect, no need to send data
            return None
        elif port == 3306:
            # MySQL probe
            return None
        
        # No specific probe for other ports
        return None

    async def _identify_service(self, port: int) -> Dict[str, str]:
        """
        Identify the service running on a specific port.
        
        Args:
            port: Port number to identify the service for
            
        Returns:
            Dict[str, str]: Dictionary containing service name and version
        """
        # Default service info if we can't identify it
        service_info = {"name": self.common_ports.get(port, f"Unknown-{port}"), "version": ""}
        
        try:
            reader, writer = await asyncio.open_connection(
                self.target, port, timeout=self.timeout
            )
            
            # Get appropriate probe based on port
            probe_data = self._get_service_probe(port)
            
            # Send probe if available
            if probe_data:
                writer.write(probe_data)
                await writer.drain()
            
            # Read response with timeout
            try:
                response = await asyncio.wait_for(reader.read(1024), timeout=self.timeout)
                
                # Decode response if possible
                response_str = response.decode('utf-8', errors='ignore')
                
                # Use a dictionary to map service detection patterns to handler functions
                service_detectors = {
                    (b"HTTP/" in response): 
                        lambda: self._extract_http_info(response_str),
                    (b"SSH-" in response): 
                        lambda: self._extract_ssh_info(response_str),
                    (b"FTP" in response or (b"220" in response and (b"ftp" in response.lower() or port == 21))): 
                        lambda: self._extract_ftp_info(response_str),
                    (b"SMTP" in response or (b"220" in response and b"mail" in response.lower())): 
                        lambda: self._extract_smtp_info(response_str),
                    (b"mysql" in response.lower() or port == 3306): 
                        lambda: self._extract_mysql_info(response_str)
                }
                
                # Apply the first matching detector
                for condition, handler in service_detectors.items():
                    if condition:
                        service_info = handler()
                        break
                
            except asyncio.TimeoutError:
                # Timeout reading response, but connection was established
                pass
                
            # Close the connection
            writer.close()
            await writer.wait_closed()
            
            return service_info
            
        except asyncio.TimeoutError:
            # Connection timed out
            return service_info
        
        except Exception as e:
            self.logger.error(f"Service identification failed for port {port}: {e}")
            return service_info
            
    def _extract_service_info(self, service_name: str, response_str: str, pattern: str) -> Dict[str, str]:
        """
        Extract service information using a regex pattern.
        
        Args:
            service_name: Name of the service
            response_str: Response string to extract info from
            pattern: Regex pattern to match the version information
            
        Returns:
            Dict[str, str]: Dictionary containing service name and version
        """
        match = re.search(pattern, response_str)
        return {
            "name": service_name,
            "version": match.group(1) if match else ""
        }
            
    def _extract_http_info(self, response_str: str) -> Dict[str, str]:
        """Extract HTTP server information from response."""
        return self._extract_service_info("HTTP", response_str, r"Server: ([^\r\n]+)")
        
    def _extract_ssh_info(self, response_str: str) -> Dict[str, str]:
        """Extract SSH server information from response."""
        return self._extract_service_info("SSH", response_str, r"SSH-\d+\.\d+-([^\r\n]+)")
        
    def _extract_ftp_info(self, response_str: str) -> Dict[str, str]:
        """Extract FTP server information from response."""
        return self._extract_service_info("FTP", response_str, r"220[- ]([^\r\n]+)")
        
    def _extract_smtp_info(self, response_str: str) -> Dict[str, str]:
        """Extract SMTP server information from response."""
        return self._extract_service_info("SMTP", response_str, r"220[- ]([^\r\n]+)")
        
    def _extract_mysql_info(self, response_str: str) -> Dict[str, str]:
        """Extract MySQL server information from response."""
        return self._extract_service_info("MySQL", response_str, r"([0-9]+\.[0-9]+\.[0-9]+)")

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

    def _save_json_results(self, results: List[Dict], filename: str, encrypt: bool) -> str:
        """
        Save scan results in JSON format.
        
        Args:
            results: Scan results to save
            filename: Base filename (without extension)
            encrypt: Whether to encrypt the results
            
        Returns:
            str: Path to the saved file
        """
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
        
        with open(json_file, 'w') as f:
            json.dump(json_data, f, indent=2)
        
        if encrypt:
            self._encrypt_file(json_file)
            self._log_and_print(f"Results saved and encrypted to {json_file}.enc")
            return f"{json_file}.enc"
        else:
            self._log_and_print(f"Results saved to {json_file}")
            return json_file
        
        return json_data  # Return the data for potential use by other formats
    
    def _save_csv_results(self, results: List[Dict], filename: str) -> str:
        """
        Save scan results in CSV format.
        
        Args:
            results: Scan results to save
            filename: Base filename (without extension)
            
        Returns:
            str: Path to the saved file
        """
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
        return csv_file
    
    def _save_html_results(self, results: List[Dict], filename: str) -> str:
        """
        Save scan results in HTML format.
        
        Args:
            results: Scan results to save
            filename: Base filename (without extension)
            
        Returns:
            str: Path to the saved file
        """
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
        return html_file

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
            json_data = None
            
            # Process each requested format
            if format in ['json', 'all']:
                json_data = self._save_json_results(results, filename, encrypt)
            
            if format in ['csv', 'all']:
                self._save_csv_results(results, filename)
            
            if format in ['html', 'all']:
                self._save_html_results(results, filename)
            
            # Process notifications if enabled
            if notify:
                if isinstance(json_data, dict):
                    self.process_notifications(json_data)
                else:
                    # Create the JSON data structure if we didn't already create it
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
        Scan a list of ports using asyncio and rate limiting with progress tracking.
        
        Args:
            ports: List of port numbers to scan
            
        Returns:
            List[Dict]: List of scan results
        """
        if not ports:
            self.logger.warning("No ports to scan")
            return []
            
        # Setup semaphore for concurrency control
        semaphore = asyncio.Semaphore(self.threads)
        
        # Setup progress display
        total_ports = len(ports)
        self.logger.info(f"Starting scan of {total_ports} ports with {self.threads} concurrent threads")
        
        # Create progress bar
        progress = tqdm(total=total_ports, desc="Scanning ports", unit="port")
        
        # Results collection
        results = []
        
        # Process ports in chunks to update progress bar
        chunk_size = min(500, total_ports)  # Process in reasonable chunks
        for i in range(0, total_ports, chunk_size):
            chunk = ports[i:i + chunk_size]
            
            # Create tasks for this chunk
            tasks = [self._scan_with_semaphore(semaphore, port) for port in chunk]
            
            # Process tasks concurrently
            chunk_results = await asyncio.gather(*tasks)
            
            # Filter valid results and add to results list
            valid_results = [result for result in chunk_results if result is not None]
            results.extend(valid_results)
            
            # Update progress bar
            progress.update(len(chunk))
            
        # Close progress bar
        progress.close()
        
        self.logger.info(f"Scan completed: {len(results)} open ports found out of {total_ports} ports scanned")
        return results

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

    def _validate_port(self, port: int, context: str = None) -> None:
        """
        Validate that a port number is within the valid range (0-65535).
        
        Args:
            port: The port number to validate
            context: Optional context for error message
            
        Raises:
            ValueError: If the port number is invalid
        """
        if port < 0:
            raise ValueError(f"Port number cannot be negative: {context or port}")
        if port > 65535:
            raise ValueError(f"Port number must be between 0 and 65535: {context or port}")

    def parse_ports(self, ports: str) -> List[int]:
        """
        Parse a string of port numbers and ranges into a list of integers.
        
        Args:
            ports: String of port numbers and ranges (e.g. "80,443,8000-8010")
            
        Returns:
            List[int]: List of unique port numbers
            
        Raises:
            ValueError: If the port specification is invalid
        """
        port_list = []
        
        if not ports or not ports.strip():
            raise ValueError("Port specification cannot be empty")
            
        for part in ports.split(','):
            part = part.strip()
            if not part:
                continue
                
            try:
                if '-' in part:
                    # Handle port range
                    start_str, end_str = part.split('-', 1)
                    start, end = int(start_str.strip()), int(end_str.strip())
                    
                    # Validate port range
                    self._validate_port(start, part)
                    self._validate_port(end, part)
                    
                    if start > end:
                        raise ValueError(f"Invalid port range (start > end): {part}")
                        
                    port_list.extend(range(start, end + 1))
                else:
                    # Handle single port
                    port = int(part)
                    self._validate_port(port)
                    port_list.append(port)
            except ValueError as e:
                # Check if this is our custom error message
                if str(e).startswith("Port ") or str(e).startswith("Invalid port"):
                    raise
                # Otherwise, it's likely a conversion error
                raise ValueError(f"Invalid port specification: {part}")
                
        if not port_list:
            raise ValueError("No valid ports specified")
            
        return sorted(set(port_list))

    def _load_scan_policy(self, policy_name: str) -> None:
        """
        Load and apply scan policy configuration.
        
        Args:
            policy_name: Name of the policy to load
        """
        if policy_name:
            policy_manager = get_policy_manager()
            policy_config = policy_manager.load_policy(policy_name)
            if policy_config:
                self.threads = policy_config.get('threads', self.threads)
                self.timeout = policy_config.get('timeout', self.timeout)
                self.rate_limit = policy_config.get('rate_limit', self.rate_limit)
                self.max_scan_rate = policy_config.get('max_scan_rate', self.max_scan_rate)

    def _load_target_group(self, group_name: str) -> Tuple[str, List[int]]:
        """
        Load target group configuration.
        
        Args:
            group_name: Name of the target group to load
            
        Returns:
            Tuple[str, List[int]]: Target and ports from group config
        """
        if group_name:
            target_groups = get_target_groups()
            group_config = target_groups.load_group(group_name)
            if group_config:
                return (
                    group_config.get('target', self.target),
                    group_config.get('ports', self.ports)
                )
        return self.target, self.ports

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
        
        # Load scan policy and target group configurations
        self._load_scan_policy(policy)
        self.target, self.ports = self._load_target_group(group)
        
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
        Uses argparse subcommands for better organization of different functionality.
        """
        parser = argparse.ArgumentParser(
            description="GateKeeper Network Security Scanner",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="Example usage:\n"
                   "  Scan a target:                 gatekeeper.py scan --target example.com --ports 80,443\n"
                   "  Use a scan policy:             gatekeeper.py scan --target example.com --policy quick\n"
                   "  Scan a target group:           gatekeeper.py scan --group web_servers\n"
                   "  Compare two reports:           gatekeeper.py compare report1.json report2.json\n"
                   "  Export a report:               gatekeeper.py export report.json\n"
                   "  Analyze port behavior:         gatekeeper.py analyze report.json\n"
                   "  List available reports:        gatekeeper.py reports list\n"
                   "  List available policies:       gatekeeper.py policies list\n"
                   "  List available target groups:  gatekeeper.py groups list\n"
        )
        
        # Create subparsers
        subparsers = parser.add_subparsers(dest="command", help="Command to execute")
        
        # Scan command
        scan_parser = subparsers.add_parser("scan", help="Perform a network scan")
        scan_parser.add_argument("-t", "--target", help="Target IP address or hostname")
        scan_parser.add_argument("-p", "--ports", help="Port numbers to scan (e.g. 80,443,8000-8010)")
        scan_parser.add_argument("--policy", help="Scan policy name")
        scan_parser.add_argument("-g", "--group", help="Target group name")
        scan_parser.add_argument("--notify", action="store_true", help="Send notifications based on scan results")
        scan_parser.add_argument("--output", help="Output filename (without extension)")
        scan_parser.add_argument("--format", choices=["json", "csv", "html", "all"], default="json", 
                               help="Output format (default: json)")
        scan_parser.add_argument("--no-encrypt", action="store_true", help="Disable encryption of JSON results")
        
        # Compare command
        compare_parser = subparsers.add_parser("compare", help="Compare two scan reports")
        compare_parser.add_argument("report1", help="First report file")
        compare_parser.add_argument("report2", help="Second report file")
        
        # Reports command
        reports_parser = subparsers.add_parser("reports", help="Manage scan reports")
        reports_subparsers = reports_parser.add_subparsers(dest="reports_command", help="Reports command")
        reports_list_parser = reports_subparsers.add_parser("list", help="List available scan reports")
        
        # Export command
        export_parser = subparsers.add_parser("export", help="Export scan results to different formats")
        export_parser.add_argument("report", help="Report file to export")
        export_parser.add_argument("--format", choices=["csv", "html", "all"], default="all", 
                                 help="Export format (default: all)")
        
        # Analyze command
        analyze_parser = subparsers.add_parser("analyze", help="Analyze port behavior from scan reports")
        analyze_parser.add_argument("report", help="Report file to analyze")
        
        # Policies command
        policies_parser = subparsers.add_parser("policies", help="Manage scan policies")
        policies_subparsers = policies_parser.add_subparsers(dest="policies_command", help="Policies command")
        policies_list_parser = policies_subparsers.add_parser("list", help="List available scan policies")
        
        # Groups command
        groups_parser = subparsers.add_parser("groups", help="Manage target groups")
        groups_subparsers = groups_parser.add_subparsers(dest="groups_command", help="Groups command")
        groups_list_parser = groups_subparsers.add_parser("list", help="List available target groups")
        
        args = parser.parse_args()
        
        # If no command specified, show help
        if not args.command:
            parser.print_help()
            return
        
        # Handle commands
        if args.command == "scan":
            # Validate scan arguments
            if not args.target and not args.group:
                scan_parser.error("Either --target or --group is required for a scan")
            
            if not args.ports and not args.group and not args.policy:
                scan_parser.error("Either --ports, --group, or --policy is required for a scan")
            
            ports = []
            if args.ports:
                ports = self.parse_ports(args.ports)
            
            self.scan(
                target=args.target, 
                ports=ports, 
                policy=args.policy, 
                group=args.group, 
                notify=args.notify
            )
            
        elif args.command == "compare":
            self.compare_reports(args.report1, args.report2)
            
        elif args.command == "reports":
            if args.reports_command == "list":
                self.list_available_reports()
            else:
                reports_parser.print_help()
                
        elif args.command == "export":
            export_results(args.report, args.format)
            
        elif args.command == "analyze":
            self.analyze_port_behavior(args.report)
            
        elif args.command == "policies":
            if args.policies_command == "list":
                policy_manager = get_policy_manager()
                policy_manager.list_policies()
            else:
                policies_parser.print_help()
                
        elif args.command == "groups":
            if args.groups_command == "list":
                target_groups = get_target_groups()
                target_groups.list_groups()
            else:
                groups_parser.print_help()

if __name__ == "__main__":
    gatekeeper = GateKeeper()
    gatekeeper.main()