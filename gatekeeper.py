#!/usr/bin/env python3

import argparse
import socket
import sys
import concurrent.futures
from datetime import datetime
from pathlib import Path
import logging
import logging.handlers
import time
import dns.resolver  # for DNS verification
from cryptography.fernet import Fernet  # for encryption
import json
from typing import List, Tuple, Dict, Optional, Any, TextIO, BinaryIO, Union, ContextManager
from utils.banner import display_banner, display_scan_start, display_scan_complete
from utils.report_compare import ReportComparer, find_latest_reports
from utils.port_behavior import PortBehaviorAnalyzer
from utils.scan_policy import get_policy_manager
from utils.target_groups import get_target_groups
from utils.export import export_results
from utils.notifications import get_notification_manager
from utils.config import ConfigManager, ScanConfig, ScanState
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
import contextlib
from typing import Iterator

# Initialize colorama
init(autoreset=True)  # Automatically reset colors after each print

class GateKeeper:
    def __init__(self):
        """Initialize the GateKeeper application."""
        # Set up logging
        self.logger = self._setup_logging()
        
        # Initialize configuration and state management
        self.config_manager = ConfigManager(self.logger)
        
        # Initialize managers
        self.policy_manager = get_policy_manager()
        self.target_groups = get_target_groups()
        self.notification_manager = get_notification_manager()
        self.port_analyzer = PortBehaviorAnalyzer()
        self.report_comparer = ReportComparer()
        
        # Generate encryption key if not already configured
        if not self.config_manager.config.encryption_key:
            self._generate_encryption_key()
        
        self.logger.info("GateKeeper initialized")
        
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
        """Generate a new encryption key."""
        config = self.config_manager.config
        state = self.config_manager.state
        
        try:
            # Generate a new key
            key = Fernet.generate_key()
            
            # Update configuration
            self.config_manager.update_config(encryption_key=key)
            
            self.logger.info("Generated new encryption key")
            return key
            
        except Exception as e:
            self.logger.error(f"Error generating encryption key: {str(e)}")
            self.config_manager.update_state(
                error_count=state.error_count + 1
            )
            raise

    def _encrypt_file(self, filepath: Union[str, Path]) -> bool:
        """Encrypt a file using the configured encryption key."""
        config = self.config_manager.config
        state = self.config_manager.state
        
        if not config.encryption_key:
            self.logger.error("No encryption key configured")
            self.config_manager.update_state(
                error_count=state.error_count + 1
            )
            return False
        
        try:
            # Read the file content
            content = self._read_file(filepath, binary=True)
            if content is None:
                return False
            
            # Encrypt the content
            fernet = Fernet(config.encryption_key)
            encrypted_content = fernet.encrypt(content)
            
            # Write the encrypted content
            encrypted_file = Path(f"{filepath}.enc")
            return self._write_file(encrypted_file, encrypted_content, binary=True)
            
        except Exception as e:
            self.logger.error(f"Error encrypting file {filepath}: {str(e)}")
            self.config_manager.update_state(
                error_count=state.error_count + 1
            )
            return False

    def _decrypt_file(self, filepath: Union[str, Path]) -> Optional[bytes]:
        """Decrypt a file using the configured encryption key."""
        config = self.config_manager.config
        state = self.config_manager.state
        
        if not config.encryption_key:
            self.logger.error("No encryption key configured")
            self.config_manager.update_state(
                error_count=state.error_count + 1
            )
            return None
        
        try:
            # Read the encrypted content
            encrypted_content = self._read_file(filepath, binary=True)
            if encrypted_content is None:
                return None
            
            # Decrypt the content
            fernet = Fernet(config.encryption_key)
            return fernet.decrypt(encrypted_content)
            
        except Exception as e:
            self.logger.error(f"Error decrypting file {filepath}: {str(e)}")
            self.config_manager.update_state(
                error_count=state.error_count + 1
            )
            return None

    def _setup_logging(self) -> logging.Logger:
        """Set up logging configuration."""
        logger = logging.getLogger('gatekeeper')
        logger.setLevel(logging.DEBUG)
        
        # Create logs directory if it doesn't exist
        log_dir = Path('logs')
        log_dir.mkdir(exist_ok=True)
        
        # File handler for debug logs
        file_handler = logging.handlers.RotatingFileHandler(
            log_dir / 'gatekeeper.log',
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        ))
        
        # Console handler for info and above
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(logging.Formatter(
            '%(levelname)s: %(message)s'
        ))
        
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)
        
        return logger

    def _handle_dns_error(self, error_type: str, target: str, error: Optional[Exception] = None) -> bool:
        """
        Handle DNS resolution errors consistently.
        
        Args:
            error_type: Type of DNS error (e.g., 'not exist', 'timeout')
            target: The target hostname or IP being resolved
            error: The exception that was raised (optional)
            
        Returns:
            bool: Always returns False to indicate failure
        """
        error_msg = f"DNS resolution failed: {error_type} for {target}"
        if error:
            error_msg += f": {str(error)}"
            
        self.logger.error(error_msg)
        self.config_manager.update_state(
            error_count=self.config_manager.state.error_count + 1
        )
        return False
        
    def verify_dns(self, target: str) -> bool:
        """Verify DNS resolution for a target."""
        config = self.config_manager.config
        
        try:
            # Try to resolve the target
            resolver = dns.resolver.Resolver()
            resolver.timeout = config.timeout
            resolver.lifetime = config.timeout
            
            # Check if it's an IP address
            try:
                ipaddress.ip_address(target)
                return True
            except ValueError:
                # Not an IP, try DNS resolution
                try:
                    resolver.resolve(target)
                    return True
                except dns.resolver.NXDOMAIN:
                    return self._handle_dns_error("does not exist", target)
                except dns.resolver.Timeout:
                    return self._handle_dns_error("timed out", target)
                except dns.resolver.NoAnswer:
                    return self._handle_dns_error("no answer", target)
                except Exception as e:
                    return self._handle_dns_error("error", target, e)
                    
        except Exception as e:
            return self._handle_dns_error("general verification error", target, e)

    def _scan_port(self, target: str, port: int, timeout: float, scan_type: str) -> Tuple[bool, Optional[str]]:
        """
        Scan a single port.
        
        Args:
            target: Target IP address or hostname
            port: Port number to scan
            timeout: Connection timeout in seconds
            scan_type: Type of scan ('tcp' or 'udp')
            
        Returns:
            Tuple[bool, Optional[str]]: A tuple where:
                - First element is True if port is open, False otherwise
                - Second element is None if port is closed/open normally,
                  or an error string if port is filtered or an error occurred
        """
        try:
            if scan_type == "tcp":
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(timeout)
                    result = sock.connect_ex((target, port))
                    return result == 0, None
            elif scan_type == "udp":
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.settimeout(timeout)
                    try:
                        sock.sendto(b'', (target, port))
                        data, addr = sock.recvfrom(1024)
                        return True, None
                    except socket.timeout:
                        return False, None
                    except Exception as e:
                        return False, str(e)
            else:
                raise ValueError(f"Unsupported scan type: {scan_type}")
        except Exception as e:
            return False, str(e)

    def _scan_with_progress(self, target: str, ports: List[int], scan_type: str = "tcp") -> Dict[str, Any]:
        """Scan ports with progress tracking."""
        config = self.config_manager.config
        state = self.config_manager.state
        
        open_ports = []
        closed_ports = []
        filtered_ports = []
        error_ports = []
        
        with tqdm(total=len(ports), desc="Scanning ports", unit="port") as progress:
            with concurrent.futures.ThreadPoolExecutor(max_workers=config.threads) as executor:
                future_to_port = {
                    executor.submit(
                        self._scan_port,
                        target,
                        port,
                        config.timeout,
                        scan_type
                    ): port for port in ports
                }
                
                for future in concurrent.futures.as_completed(future_to_port):
                    port = future_to_port[future]
                    try:
                        is_open, error = future.result()
                        if is_open:
                            open_ports.append(port)
                        elif error:
                            filtered_ports.append(port)
                            self.logger.debug(f"Port {port} filtered: {error}")
                        else:
                            closed_ports.append(port)
                    except Exception as e:
                        error_ports.append(port)
                        self.logger.error(f"Error scanning port {port}: {str(e)}")
                        self.config_manager.update_state(
                            error_count=state.error_count + 1
                        )
                    
                    progress.update(1)
                    self.config_manager.update_state(
                        progress=progress.n / len(ports)
                    )
        
        return {
            "target": target,
            "scan_id": state.scan_id,
            "start_time": state.start_time.isoformat(),
            "end_time": datetime.now().isoformat(),
            "open_ports": open_ports,
            "closed_ports": closed_ports,
            "filtered_ports": filtered_ports,
            "error_ports": error_ports,
            "scan_type": scan_type,
            "threads": config.threads,
            "timeout": config.timeout
        }

    async def scan_port(self, port: int) -> Optional[Dict]:
        """
        Scan a single port with rate limiting and timeout.
        
        Args:
            port: Port number to scan
            
        Returns:
            Optional[Dict]: Scan result if the port is open, None otherwise
        """
        config = self.config_manager.config
        
        if not 0 <= port <= 65535:
            raise ValueError(f"Port number must be between 0 and 65535, got {port}")
        
        # Use asyncio.sleep instead of time.sleep for rate limiting in async functions
        await asyncio.sleep(config.rate_limit)
        
        try:
            # Use context manager for socket handling
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(config.timeout)
                
                # Attempt connection
                result = sock.connect_ex((config.target, port))
                
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
        
        return None  # Return None for all error cases

    def _get_service_probe(self, port: int) -> Optional[bytes]:
        """
        Get an appropriate probe for the given port.
        
        Args:
            port: The port number to get a probe for
            
        Returns:
            Optional[bytes]: The probe data as bytes, or None if no probe is needed
        """
        config = self.config_manager.config
        if port in [80, 443, 8080]:
            # HTTP probe
            return f"GET / HTTP/1.1\r\nHost: {config.target}\r\n\r\n".encode()
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
        config = self.config_manager.config
        # Default service info if we can't identify it
        service_info = {"name": self.common_ports.get(port, f"Unknown-{port}"), "version": ""}
        
        try:
            reader, writer = await asyncio.open_connection(
                config.target, port, timeout=config.timeout
            )
            
            # Get appropriate probe based on port
            probe_data = self._get_service_probe(port)
            
            # Send probe if available
            if probe_data:
                writer.write(probe_data)
                await writer.drain()
            
            # Read response with timeout
            try:
                response = await asyncio.wait_for(reader.read(1024), timeout=config.timeout)
                
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
        config = self.config_manager.config
        if not config.encryption_key:
            raise ValueError("Encryption key not configured")
        f = Fernet(config.encryption_key)
        data = json.dumps(results).encode()
        return f.encrypt(data)

    def decrypt_results(self, encrypted_data: bytes) -> List[Dict]:
        """Decrypt scan results."""
        config = self.config_manager.config
        if not encrypted_data:
            raise ValueError("Cannot decrypt empty data")
            
        try:
            if not config.encryption_key:
                raise ValueError("Encryption key not configured")
            f = Fernet(config.encryption_key)
            decrypted_data = f.decrypt(encrypted_data)
            return json.loads(decrypted_data.decode())
        except Exception as e:
            raise ValueError(f"Failed to decrypt results: {e}")

    def _log_and_print(self, message: str, level: str = 'info', color: str = None) -> None:
        """Log a message and optionally print it with color."""
        # Log the message
        log_level = getattr(logging, level.upper())
        self.logger.log(log_level, message)
        
        # Print with color if specified
        if color:
            print(f"{color}{message}{Style.RESET_ALL}")
        else:
            print(message)

    def _save_results(self, results: Dict[str, Any]) -> None:
        """Save scan results in configured formats."""
        config = self.config_manager.config
        state = self.config_manager.state
        
        try:
            # Ensure output directory exists
            output_dir = Path(config.output_dir)
            output_dir.mkdir(parents=True, exist_ok=True)
            
            # Generate filename with timestamp
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            base_filename = f"gatekeeper_scan_{timestamp}"
            
            # Save in each configured format
            for format in config.export_formats:
                try:
                    if format == "json":
                        self._save_json_results(results, output_dir / f"{base_filename}.json")
                    elif format == "csv":
                        self._save_csv_results(results, output_dir / f"{base_filename}.csv")
                    elif format == "html":
                        self._save_html_results(results, output_dir / f"{base_filename}.html")
                    else:
                        self.logger.warning(f"Unsupported export format: {format}")
                except Exception as e:
                    self.logger.error(f"Error saving {format} results: {str(e)}")
                    self.config_manager.update_state(
                        error_count=state.error_count + 1
                    )
            
            self.logger.info(f"Results saved to {output_dir}")
            
        except Exception as e:
            self.logger.error(f"Error saving results: {str(e)}")
            self.config_manager.update_state(
                error_count=state.error_count + 1
            )
            raise

    def _save_json_results(self, results: Dict[str, Any], filepath: Path) -> None:
        """Save results in JSON format."""
        with self._open_file(filepath, 'w') as f:
            json.dump(results, f, indent=2)
        self.logger.debug(f"Saved JSON results to {filepath}")

    def _save_csv_results(self, results: Dict[str, Any], filepath: Path) -> None:
        """Save results in CSV format."""
        with self._open_file(filepath, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Port', 'Status'])
            for port in results['open_ports']:
                writer.writerow([port, 'Open'])
            for port in results['closed_ports']:
                writer.writerow([port, 'Closed'])
            for port in results['filtered_ports']:
                writer.writerow([port, 'Filtered'])
            for port in results['error_ports']:
                writer.writerow([port, 'Error'])
        self.logger.debug(f"Saved CSV results to {filepath}")

    def _save_html_results(self, results: Dict[str, Any], filepath: Path) -> None:
        """Save results in HTML format."""
        html_template = """<!DOCTYPE html>
<html>
<head>
    <title>GateKeeper Scan Results</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .open { color: green; }
        .closed { color: red; }
        .filtered { color: orange; }
        .error { color: gray; }
    </style>
</head>
<body>
    <h1>GateKeeper Scan Results</h1>
    <p>Target: {target}</p>
    <p>Scan ID: {scan_id}</p>
    <p>Start Time: {start_time}</p>
    <p>End Time: {end_time}</p>
    
    <h2>Port Status</h2>
    <table>
        <tr><th>Port</th><th>Status</th></tr>
        {port_rows}
    </table>
</body>
</html>
"""
        # Generate table rows for each port
        port_rows = []
        for port in results['open_ports']:
            port_rows.append(f'<tr><td>{port}</td><td class="open">Open</td></tr>')
        for port in results['closed_ports']:
            port_rows.append(f'<tr><td>{port}</td><td class="closed">Closed</td></tr>')
        for port in results['filtered_ports']:
            port_rows.append(f'<tr><td>{port}</td><td class="filtered">Filtered</td></tr>')
        for port in results['error_ports']:
            port_rows.append(f'<tr><td>{port}</td><td class="error">Error</td></tr>')
        
        # Format the template with data
        html_content = html_template.format(
            target=html.escape(results["target"]),
            scan_id=html.escape(results["scan_id"]),
            start_time=html.escape(results["start_time"]),
            end_time=html.escape(results["end_time"]),
            port_rows="\n        ".join(port_rows)
        )
        
        # Write to file
        with self._open_file(filepath, 'w') as f:
            f.write(html_content)
        
        self.logger.debug(f"Saved HTML results to {filepath}")

    def compare_reports(self, report1: str, report2: str) -> None:
        """Compare two scan reports."""
        config = self.config_manager.config
        state = self.config_manager.state
        
        try:
            # Load the reports
            report1_path = Path(report1)
            report2_path = Path(report2)
            
            if not report1_path.exists() or not report2_path.exists():
                self.logger.error("One or both report files do not exist")
                self.config_manager.update_state(
                    error_count=state.error_count + 1
                )
                return
            
            # Read and parse the reports
            report1_data = json.loads(self._read_file(report1_path))
            report2_data = json.loads(self._read_file(report2_path))
            
            if not report1_data or not report2_data:
                self.logger.error("Failed to parse one or both reports")
                self.config_manager.update_state(
                    error_count=state.error_count + 1
                )
                return
            
            # Compare the reports
            differences = self.report_comparer.compare_reports(report1_data, report2_data)
            
            # Display the differences
            if differences:
                self.logger.info("Report differences found:")
                for diff in differences:
                    self.logger.info(f"- {diff}")
            else:
                self.logger.info("No differences found between reports")
            
        except Exception as e:
            self.logger.error(f"Error comparing reports: {str(e)}")
            self.config_manager.update_state(
                error_count=state.error_count + 1
            )

    def list_available_reports(self) -> None:
        """List available scan reports."""
        config = self.config_manager.config
        state = self.config_manager.state
        
        try:
            # Get the reports directory
            reports_dir = Path(config.output_dir)
            if not reports_dir.exists():
                self.logger.error("Reports directory does not exist")
                self.config_manager.update_state(
                    error_count=state.error_count + 1
                )
                return
            
            # List all report files
            report_files = []
            for ext in ['.json', '.csv', '.html']:
                report_files.extend(reports_dir.glob(f'*{ext}'))
            
            if not report_files:
                self.logger.info("No reports found")
                return
            
            # Display the reports
            self.logger.info("Available reports:")
            for report in sorted(report_files):
                self.logger.info(f"- {report.name}")
            
        except Exception as e:
            self.logger.error(f"Error listing reports: {str(e)}")
            self.config_manager.update_state(
                error_count=state.error_count + 1
            )

    def analyze_port_behavior(self, report_file: str) -> None:
        """Analyze port behavior from a scan report."""
        config = self.config_manager.config
        state = self.config_manager.state
        
        try:
            # Load the report
            report_path = Path(report_file)
            if not report_path.exists():
                self.logger.error(f"Report file not found: {report_file}")
                self.config_manager.update_state(
                    error_count=state.error_count + 1
                )
                return
            
            # Read and parse the report
            report_data = json.loads(self._read_file(report_path))
            if not report_data:
                self.logger.error("Failed to parse report")
                self.config_manager.update_state(
                    error_count=state.error_count + 1
                )
                return
            
            # Analyze port behavior
            analysis = self.port_analyzer.analyze(report_data)
            
            # Display the analysis
            if analysis:
                self.logger.info("Port behavior analysis:")
                for item in analysis:
                    self.logger.info(f"- {item}")
            else:
                self.logger.info("No significant port behavior patterns found")
            
        except Exception as e:
            self.logger.error(f"Error analyzing port behavior: {str(e)}")
            self.config_manager.update_state(
                error_count=state.error_count + 1
            )

    def _validate_port(self, port: int, context: str = None) -> None:
        """Validate a port number."""
        config = self.config_manager.config
        state = self.config_manager.state
        
        try:
            if not isinstance(port, int):
                raise ValueError(f"Port must be an integer, got {type(port)}")
            
            if port < 1 or port > 65535:
                raise ValueError(f"Port must be between 1 and 65535, got {port}")
            
            # Check if port is in restricted range
            if port < 1024:
                self.logger.warning(f"Port {port} is in the restricted range (1-1023)")
                self.config_manager.update_state(
                    warning_count=state.warning_count + 1
                )
            
        except Exception as e:
            error_msg = f"Invalid port {port}"
            if context:
                error_msg += f" in {context}"
            self.logger.error(f"{error_msg}: {str(e)}")
            self.config_manager.update_state(
                error_count=state.error_count + 1
            )
            raise

    def _parse_port_range(self, range_str: str) -> List[int]:
        """
        Parse a port range string (e.g., '1-100') into a list of port numbers.
        
        Args:
            range_str: Port range string in the format 'start-end'
            
        Returns:
            List of port numbers in the range
        
        Raises:
            ValueError: If the range is invalid
        """
        ports = []
        start, end = map(int, range_str.split('-'))
        if start > end:
            raise ValueError(f"Invalid port range: {start}-{end}")
        for port in range(start, end + 1):
            self._validate_port(port, f"range {start}-{end}")
            ports.append(port)
        return ports

    def parse_ports(self, ports: str) -> List[int]:
        """
        Parse a string of ports into a list of integers.
        
        Supports individual ports (e.g., '80') and port ranges (e.g., '1-100').
        Multiple ports or ranges can be separated by commas.
        
        Args:
            ports: String representation of ports (e.g., '22,80,443,1000-1100')
            
        Returns:
            List of unique, sorted port numbers
            
        Raises:
            ValueError: If any port is invalid or out of range
        """
        config = self.config_manager.config
        state = self.config_manager.state
        
        try:
            result = []
            
            # Split by commas and process each part
            for part in ports.split(','):
                part = part.strip()
                if '-' in part:
                    # Handle port range
                    result.extend(self._parse_port_range(part))
                else:
                    # Handle single port
                    port = int(part)
                    self._validate_port(port)
                    result.append(port)
            
            # Remove duplicates and sort
            result = sorted(set(result))
            
            # Update configuration
            self.config_manager.update_config(ports=result)
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error parsing ports: {str(e)}")
            self.config_manager.update_state(
                error_count=state.error_count + 1
            )
            raise

    def _load_scan_policy(self, policy_name: str) -> None:
        """Load a scan policy."""
        config = self.config_manager.config
        state = self.config_manager.state
        
        try:
            if not policy_name:
                return
            
            # Load the policy
            policy_config = self.policy_manager.load_policy(policy_name)
            if not policy_config:
                self.logger.error(f"Policy not found: {policy_name}")
                self.config_manager.update_state(
                    error_count=state.error_count + 1
                )
                return
            
            # Update configuration with policy settings
            self.config_manager.update_config(**policy_config)
            self.logger.info(f"Loaded policy: {policy_name}")
            
        except Exception as e:
            self.logger.error(f"Error loading policy {policy_name}: {str(e)}")
            self.config_manager.update_state(
                error_count=state.error_count + 1
            )
            raise

    def _load_target_group(self, group_name: str) -> Tuple[str, List[int]]:
        """Load a target group."""
        config = self.config_manager.config
        state = self.config_manager.state
        
        try:
            if not group_name:
                return None, []
            
            # Load the group
            group_config = self.target_groups.load_group(group_name)
            if not group_config:
                self.logger.error(f"Group not found: {group_name}")
                self.config_manager.update_state(
                    error_count=state.error_count + 1
                )
                return None, []
            
            # Update configuration with group settings
            self.config_manager.update_config(**group_config)
            self.logger.info(f"Loaded group: {group_name}")
            
            return group_config.get('target'), group_config.get('ports', [])
            
        except Exception as e:
            self.logger.error(f"Error loading group {group_name}: {str(e)}")
            self.config_manager.update_state(
                error_count=state.error_count + 1
            )
            raise

    def scan_target(self, target: str, ports: List[int], threads: int = 100, timeout: float = 1.0,
                   scan_type: str = "tcp", policy_name: Optional[str] = None,
                   group_name: Optional[str] = None) -> Dict[str, Any]:
        """Scan a target for open ports."""
        try:
            # Update configuration
            self.config_manager.update_config(
                target=target,
                ports=ports,
                threads=threads,
                timeout=timeout,
                scan_type=scan_type
            )
            
            # Validate configuration
            if not self.config_manager.validate_target(target):
                raise ValueError(f"Invalid target: {target}")
            if not self.config_manager.validate_ports(ports):
                raise ValueError("Invalid port range")
            
            # Load policy if specified
            if policy_name:
                self._load_scan_policy(policy_name)
            
            # Load target group if specified
            if group_name:
                group_config = self.target_groups.load_group(group_name)
                if group_config:
                    self.config_manager.update_config(**group_config)
            
            # Initialize scan state
            self.config_manager.update_state(
                start_time=datetime.now(),
                scan_id=f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                status="running"
            )
            
            display_scan_start(target, ports)
            self.logger.info(f"Starting scan of {target} on ports {ports}")
            
            # Perform the scan
            results = self._perform_scan()
            
            # Update scan state
            self.config_manager.update_state(
                end_time=datetime.now(),
                results=results,
                status="completed"
            )
            
            # Save results
            self._save_results(results)
            
            # Process notifications
            self._process_notifications(results)
            
            display_scan_complete()
            self.logger.info("Scan completed successfully")
            
            return results
            
        except Exception as e:
            self.config_manager.update_state(
                status="failed",
                error_count=self.config_manager.state.error_count + 1
            )
            self.logger.error(f"Scan failed: {str(e)}")
            raise

    def _perform_scan(self) -> Dict[str, Any]:
        """Perform the actual port scan."""
        config = self.config_manager.config
        state = self.config_manager.state
        
        open_ports = []
        closed_ports = []
        filtered_ports = []
        error_ports = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=config.threads) as executor:
            future_to_port = {
                executor.submit(
                    self._scan_port,
                    config.target,
                    port,
                    config.timeout,
                    config.scan_type
                ): port for port in config.ports
            }
            
            for future in concurrent.futures.as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    is_open, error = future.result()
                    if is_open:
                        open_ports.append(port)
                    elif error:
                        filtered_ports.append(port)
                        self.logger.debug(f"Port {port} filtered: {error}")
                    else:
                        closed_ports.append(port)
                except Exception as e:
                    self.logger.error(f"Error scanning port {port}: {str(e)}")
                    error_ports.append(port)
                    self.config_manager.update_state(
                        error_count=state.error_count + 1
                    )
                
                # Update progress
                progress = (len(open_ports) + len(closed_ports) + len(filtered_ports) + len(error_ports)) / len(config.ports)
                self.config_manager.update_state(progress=progress)
        
        return {
            "target": config.target,
            "scan_id": state.scan_id,
            "start_time": state.start_time.isoformat(),
            "end_time": datetime.now().isoformat(),
            "open_ports": open_ports,
            "closed_ports": closed_ports,
            "filtered_ports": filtered_ports,
            "error_ports": error_ports,
            "scan_type": config.scan_type,
            "threads": config.threads,
            "timeout": config.timeout
        }

    def _process_notifications(self, scan_results: Dict[str, Any]) -> None:
        """Process notifications based on scan results."""
        config = self.config_manager.config
        state = self.config_manager.state
        
        try:
            if not self.notification_manager:
                self.logger.error("Notification manager not initialized")
                return
            
            # Process notifications - this will check rules and send notifications
            notification_results = self.notification_manager.process_scan_results(scan_results)
            
            # Log notification results
            for result in notification_results:
                if result.get('success'):
                    self.logger.info(f"Notification sent: {result.get('message')}")
                else:
                    self.logger.error(f"Notification failed: {result.get('error')}")
                    self.config_manager.update_state(
                        error_count=state.error_count + 1
                    )
            
        except Exception as e:
            self.logger.error(f"Error processing notifications: {str(e)}")
            self.config_manager.update_state(
                error_count=state.error_count + 1
            )

    @contextlib.contextmanager
    def _open_file(self, filepath: Union[str, Path], mode: str = 'r', **kwargs) -> Iterator[Union[TextIO, BinaryIO]]:
        """Context manager for file operations."""
        filepath = Path(filepath)
        try:
            # Create parent directories for write operations
            if 'w' in mode or 'a' in mode:
                filepath.parent.mkdir(parents=True, exist_ok=True)
            
            # Open the file
            with open(filepath, mode, **kwargs) as f:
                yield f
                
        except FileNotFoundError:
            self.logger.error(f"File not found: {filepath}")
            self.config_manager.update_state(
                error_count=self.config_manager.state.error_count + 1
            )
            raise
        except PermissionError:
            self.logger.error(f"Permission denied: {filepath}")
            self.config_manager.update_state(
                error_count=self.config_manager.state.error_count + 1
            )
            raise
        except IOError as e:
            self.logger.error(f"IO error: {str(e)}")
            self.config_manager.update_state(
                error_count=self.config_manager.state.error_count + 1
            )
            raise

    def _read_file(self, filepath: Union[str, Path], binary: bool = False) -> Union[str, bytes, None]:
        """Read a file's contents."""
        try:
            mode = 'rb' if binary else 'r'
            with self._open_file(filepath, mode) as f:
                return f.read()
        except Exception as e:
            self.logger.error(f"Error reading file {filepath}: {str(e)}")
            self.config_manager.update_state(
                error_count=self.config_manager.state.error_count + 1
            )
            return None

    def _write_file(self, filepath: Union[str, Path], content: Union[str, bytes], binary: bool = False) -> bool:
        """Write content to a file."""
        try:
            mode = 'wb' if binary else 'w'
            with self._open_file(filepath, mode) as f:
                f.write(content)
            return True
        except Exception as e:
            self.logger.error(f"Error writing file {filepath}: {str(e)}")
            self.config_manager.update_state(
                error_count=self.config_manager.state.error_count + 1
            )
            return False

    def _configure_notifications(self, config: Dict[str, Any]) -> None:
        """Configure notifications."""
        state = self.config_manager.state
        
        try:
            if not config:
                return
            
            # Update notification configuration
            self.config_manager.update_config(notification_config=config)
            
            # Initialize notification manager
            self.notification_manager = get_notification_manager()
            if not self.notification_manager:
                self.logger.error("Failed to initialize notification manager")
                self.config_manager.update_state(
                    error_count=state.error_count + 1
                )
                return
            
            self.logger.info("Configured notifications")
            
        except Exception as e:
            self.logger.error(f"Error configuring notifications: {str(e)}")
            self.config_manager.update_state(
                error_count=state.error_count + 1
            )
            raise

    def main(self) -> None:
        """Main entry point for the GateKeeper application."""
        parser = argparse.ArgumentParser(description='GateKeeper Network Security Scanner')
        subparsers = parser.add_subparsers(dest='command', help='Available commands')
        
        # Scan command
        scan_parser = subparsers.add_parser('scan', help='Run a network scan')
        scan_parser.add_argument('target', help='Target IP address or hostname')
        scan_parser.add_argument('ports', help='Port range or list (e.g., 80,443 or 1-1000)')
        scan_parser.add_argument('--threads', type=int, default=100, help='Number of concurrent threads')
        scan_parser.add_argument('--timeout', type=float, default=1.0, help='Connection timeout in seconds')
        scan_parser.add_argument('--scan-type', choices=['tcp', 'udp'], default='tcp', help='Scan type')
        scan_parser.add_argument('--policy', help='Scan policy name')
        scan_parser.add_argument('--group', help='Target group name')
        scan_parser.add_argument('--notify', action='store_true', help='Send notifications')
        
        # Policies command
        policies_parser = subparsers.add_parser('policies', help='Manage scan policies')
        policies_subparsers = policies_parser.add_subparsers(dest='policies_command')
        policies_subparsers.add_parser('list', help='List available policies')
        
        # Groups command
        groups_parser = subparsers.add_parser('groups', help='Manage target groups')
        groups_subparsers = groups_parser.add_subparsers(dest='groups_command')
        groups_subparsers.add_parser('list', help='List available groups')
        
        # Reports command
        reports_parser = subparsers.add_parser('reports', help='Manage scan reports')
        reports_subparsers = reports_parser.add_subparsers(dest='reports_command')
        reports_subparsers.add_parser('list', help='List available reports')
        
        # Compare command
        compare_parser = subparsers.add_parser('compare', help='Compare scan reports')
        compare_parser.add_argument('report1', help='First report file')
        compare_parser.add_argument('report2', help='Second report file')
        
        # Analyze command
        analyze_parser = subparsers.add_parser('analyze', help='Analyze port behavior')
        analyze_parser.add_argument('report', help='Report file to analyze')
        
        args = parser.parse_args()
        
        if not args.command:
            parser.print_help()
            return
        
        try:
            gatekeeper = GateKeeper()
            
            if args.command == "scan":
                # Parse ports
                ports = gatekeeper.parse_ports(args.ports)
                
                # Run scan
                gatekeeper.scan_target(
                    target=args.target,
                    ports=ports,
                    threads=args.threads,
                    timeout=args.timeout,
                    scan_type=args.scan_type,
                    policy_name=args.policy,
                    group_name=args.group
                )
                
            elif args.command == "policies":
                if args.policies_command == "list":
                    gatekeeper.policy_manager.list_policies()
                else:
                    policies_parser.print_help()
                    
            elif args.command == "groups":
                if args.groups_command == "list":
                    gatekeeper.target_groups.list_groups()
                else:
                    groups_parser.print_help()
                    
            elif args.command == "reports":
                if args.reports_command == "list":
                    gatekeeper.list_available_reports()
                else:
                    reports_parser.print_help()
                    
            elif args.command == "compare":
                gatekeeper.compare_reports(args.report1, args.report2)
                
            elif args.command == "analyze":
                gatekeeper.analyze_port_behavior(args.report)
                
        except Exception as e:
            print(f"Error: {str(e)}")
            sys.exit(1)

if __name__ == "__main__":
    gatekeeper = GateKeeper()
    gatekeeper.main()