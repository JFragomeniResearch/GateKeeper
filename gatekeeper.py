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
import functools

# Initialize colorama
init(autoreset=True)  # Automatically reset colors after each print

class GateKeeper:
    LOG_DIR = Path('logs')
    LOG_FILENAME = 'gatekeeper.log'

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

    def _handle_encryption_errors(self, func):
        """Decorator to handle common errors in encryption/decryption methods."""
        @functools.wraps(func)
        def wrapper(self, filepath: Union[str, Path], *args, **kwargs):
            config = self.config_manager.config
            state = self.config_manager.state
            
            # Determine default return value based on function name
            default_return = False if 'encrypt' in func.__name__ else None
            
            if not config.encryption_key:
                self.logger.error("No encryption key configured")
                self.config_manager.update_state(
                    error_count=state.error_count + 1
                )
                return default_return
            
            try:
                return func(self, filepath, *args, **kwargs)
            except Exception as e:
                action = "encrypting" if 'encrypt' in func.__name__ else "decrypting"
                self.logger.error(f"Error {action} file {filepath}: {str(e)}")
                self.config_manager.update_state(
                    error_count=state.error_count + 1
                )
                return default_return
            
        return wrapper

    @_handle_encryption_errors
    def _encrypt_file(self, filepath: Union[str, Path]) -> bool:
        """Encrypt a file using the configured encryption key."""
        config = self.config_manager.config
        
        # Read the file content
        content = self._read_file(filepath, binary=True)
        if content is None:
            return False # Handled by decorator, but explicit return helps clarity
        
        # Encrypt the content
        fernet = Fernet(config.encryption_key)
        encrypted_content = fernet.encrypt(content)
        
        # Write the encrypted content
        encrypted_file = Path(f"{filepath}.enc")
        return self._write_file(encrypted_file, encrypted_content, binary=True)

    @_handle_encryption_errors
    def _decrypt_file(self, filepath: Union[str, Path]) -> Optional[bytes]:
        """Decrypt a file using the configured encryption key."""
        config = self.config_manager.config
        
        # Read the encrypted content
        encrypted_content = self._read_file(filepath, binary=True)
        if encrypted_content is None:
            return None # Handled by decorator, but explicit return helps clarity
        
        # Decrypt the content
        fernet = Fernet(config.encryption_key)
        return fernet.decrypt(encrypted_content)

    def _setup_logging(self) -> logging.Logger:
        """Set up logging configuration."""
        logger = logging.getLogger('gatekeeper')
        logger.setLevel(logging.DEBUG)
        
        # Create logs directory if it doesn't exist using class attribute
        self.LOG_DIR.mkdir(exist_ok=True)
        
        # File handler for debug logs using class attributes
        log_filepath = self.LOG_DIR / self.LOG_FILENAME
        file_handler = logging.handlers.RotatingFileHandler(
            log_filepath,
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
            # Check if it's an IP address first
            ipaddress.ip_address(target)
            return True # It's a valid IP
        except ValueError:
            # Not an IP, so try DNS resolution
            try:
                resolver = dns.resolver.Resolver()
                resolver.timeout = config.timeout
                resolver.lifetime = config.timeout
                resolver.resolve(target)
                return True # DNS resolved successfully
            except dns.resolver.NXDOMAIN:
                return self._handle_dns_error("does not exist", target)
            except dns.resolver.Timeout:
                return self._handle_dns_error("timed out", target)
            except dns.resolver.NoAnswer:
                return self._handle_dns_error("no answer", target)
            except Exception as e:
                # Catch other DNS specific errors
                return self._handle_dns_error("DNS resolution error", target, e)
        except Exception as e:
            # Catch broader errors during the IP check or resolver setup
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
        total_ports = len(ports)
        
        with tqdm(total=total_ports, desc="Scanning ports", unit="port") as progress:
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
                        # Handle errors during the scan of a single port
                        error_ports.append(port)
                        self.logger.error(f"Error scanning port {port}: {str(e)}")
                        self.config_manager.update_state(
                            error_count=state.error_count + 1
                        )
                    finally:
                         # Ensure progress is updated even if an error occurs
                        progress.update(1)
                        if total_ports > 0: # Avoid division by zero
                            current_progress = progress.n / total_ports
                            self.config_manager.update_state(progress=current_progress)
        
        return {
            "target": target,
            "scan_id": state.scan_id,
            # Ensure start_time exists before accessing isoformat
            "start_time": state.start_time.isoformat() if state.start_time else None,
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
        """Identify the service running on a specific port."""
        config = self.config_manager.config
        service_info = {"name": self.common_ports.get(port, f"Unknown-{port}"), "version": ""}
        
        reader = None # Initialize reader/writer to ensure they exist in finally block
        writer = None
        try:
            reader, writer = await asyncio.open_connection(
                config.target, port, timeout=config.timeout
            )
            
            probe_data = self._get_service_probe(port)
            if probe_data:
                writer.write(probe_data)
                await writer.drain()
            
            response = await asyncio.wait_for(reader.read(1024), timeout=config.timeout)
            response_str = response.decode('utf-8', errors='ignore')
            
            # --- Define conditions for clarity ---
            is_http = b"HTTP/" in response
            is_ssh = b"SSH-" in response
            # Check for typical FTP responses (220 code often precedes server name)
            is_ftp = b"FTP" in response or (b"220" in response and (b"ftp" in response.lower() or port == 21))
            # Check for typical SMTP responses (220 code often precedes server name)
            is_smtp = b"SMTP" in response or (b"220" in response and b"mail" in response.lower())
            # Check for MySQL (often includes version number or keyword)
            is_mysql = b"mysql" in response.lower() or port == 3306
            # --- End conditions --- 

            # Map conditions to handler functions
            service_detectors = {
                is_http: lambda: self._extract_http_info(response_str),
                is_ssh: lambda: self._extract_ssh_info(response_str),
                is_ftp: lambda: self._extract_ftp_info(response_str),
                is_smtp: lambda: self._extract_smtp_info(response_str),
                is_mysql: lambda: self._extract_mysql_info(response_str)
            }
            
            # Apply the first matching detector
            for condition, handler in service_detectors.items():
                if condition: # Check if the condition variable is True
                    service_info = handler()
                    break
                    
        except asyncio.TimeoutError:
            # Timeout reading response or connecting
            self.logger.debug(f"Timeout during service identification for port {port}")
            # service_info remains default
        except ConnectionRefusedError:
             self.logger.debug(f"Connection refused during service identification for port {port}")
             # service_info remains default
        except Exception as e:
            self.logger.error(f"Service identification failed for port {port}: {e}")
            # service_info remains default
        finally:
            # Ensure connection is closed if writer was opened
            if writer:
                writer.close()
                await writer.wait_closed()
                
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
        
        # Map format names to save methods
        save_methods = {
            "json": self._save_json_results,
            "csv": self._save_csv_results,
            "html": self._save_html_results,
        }
        
        try:
            # Ensure output directory exists
            output_dir = Path(config.output_dir)
            output_dir.mkdir(parents=True, exist_ok=True)
            
            # Generate filename with timestamp
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            base_filename = f"gatekeeper_scan_{timestamp}"
            
            # Save in each configured format
            for format_name in config.export_formats:
                save_func = save_methods.get(format_name)
                if save_func:
                    try:
                        filepath = output_dir / f"{base_filename}.{format_name}"
                        save_func(results, filepath)
                    except Exception as e:
                        self.logger.error(f"Error saving {format_name} results: {str(e)}")
                        self.config_manager.update_state(
                            error_count=state.error_count + 1
                        )
                else:
                    self.logger.warning(f"Unsupported export format: {format_name}")
            
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
            
            # Use chained comparison for range check
            if not 1 <= port <= 65535:
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
        
        parsed_ports = []
        try:
            # Split by commas and process each part
            for part in ports.split(','):
                part = part.strip()
                if not part: # Skip empty parts resulting from trailing commas etc.
                    continue 
                if '-' in part:
                    # Handle port range
                    parsed_ports.extend(self._parse_port_range(part))
                else:
                    # Handle single port
                    port = int(part)
                    self._validate_port(port)
                    parsed_ports.append(port)
            
            # Remove duplicates and sort
            result = sorted(set(parsed_ports))
            
            # Update configuration (Consider if this update is desired here)
            # self.config_manager.update_config(ports=result)
            
            return result
            
        except ValueError as ve:
            # Catch specific errors from int() or _validate_port/_parse_port_range
            self.logger.error(f"Error parsing ports ('{ports}'): {str(ve)}")
            self.config_manager.update_state(
                error_count=state.error_count + 1
            )
            raise # Re-raise after logging
        except Exception as e:
            # Catch unexpected errors during parsing
            self.logger.error(f"Unexpected error parsing ports ('{ports}'): {str(e)}")
            self.config_manager.update_state(
                error_count=state.error_count + 1
            )
            raise # Re-raise after logging

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
            # Update configuration first
            self.config_manager.update_config(
                target=target,
                ports=ports,
                threads=threads,
                timeout=timeout,
                scan_type=scan_type
            )
            
            # Validate configuration from ConfigManager
            if not self.config_manager.validate_target(self.config_manager.config.target):
                 # Use the value from config for validation
                raise ValueError(f"Invalid target: {self.config_manager.config.target}")
            if not self.config_manager.validate_ports(self.config_manager.config.ports):
                raise ValueError("Invalid port configuration")
            
            # Load policy if specified (modifies config)
            if policy_name:
                self._load_scan_policy(policy_name)
            
            # Load target group if specified (modifies config)
            if group_name:
                group_config = self.target_groups.load_group(group_name)
                if group_config: # Check if group was loaded successfully
                    self.config_manager.update_config(**group_config)
            
            # Initialize scan state (uses current config)
            self.config_manager.update_state(
                start_time=datetime.now(),
                scan_id=f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                status="running"
            )
            
            # Display start banner (use config values)
            display_scan_start(self.config_manager.config.target, self.config_manager.config.ports)
            self.logger.info(f"Starting scan of {self.config_manager.config.target} on ports {self.config_manager.config.ports}")
            
            # Perform the scan (uses config values)
            results = self._perform_scan()
            
            # Update scan state with results
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
            # Centralized error handling for the entire scan process
            self.config_manager.update_state(
                status="failed",
                # Increment error count safely
                error_count=getattr(self.config_manager.state, 'error_count', 0) + 1 
            )
            # Log the exception causing the scan failure
            self.logger.exception(f"Scan failed for target '{target}': {str(e)}") 
            raise # Re-raise the exception so the caller knows the scan failed

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
            # Catches errors during file opening (from _open_file) or during read()
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
            # Catches errors during file opening (from _open_file) or during write()
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

    def _handle_scan_command(self, args: argparse.Namespace) -> None:
        """Handle the 'scan' command."""
        ports = self.parse_ports(args.ports)
        self.scan_target(
            target=args.target,
            ports=ports,
            threads=args.threads,
            timeout=args.timeout,
            scan_type=args.scan_type,
            policy_name=args.policy,
            group_name=args.group
            # TODO: Add notification handling based on args.notify?
        )

    def _handle_policies_command(self, args: argparse.Namespace) -> None:
        """Handle the 'policies' command and its subcommands."""
        if args.policies_command == "list":
            self.policy_manager.list_policies()
        # No else needed: argparse handles invalid/missing subcommands due to required=True

    def _handle_groups_command(self, args: argparse.Namespace) -> None:
        """Handle the 'groups' command and its subcommands."""
        if args.groups_command == "list":
            self.target_groups.list_groups()
        # No else needed: argparse handles invalid/missing subcommands due to required=True

    def _handle_reports_command(self, args: argparse.Namespace) -> None:
        """Handle the 'reports' command and its subcommands."""
        if args.reports_command == "list":
            self.list_available_reports()
        # No else needed: argparse handles invalid/missing subcommands due to required=True

    def _handle_compare_command(self, args: argparse.Namespace) -> None:
        """Handle the 'compare' command."""
        self.compare_reports(args.report1, args.report2)

    def _handle_analyze_command(self, args: argparse.Namespace) -> None:
        """Handle the 'analyze' command."""
        self.analyze_port_behavior(args.report)

    def main(self) -> None:
        """Main entry point for the GateKeeper application."""
        parser = argparse.ArgumentParser(description='GateKeeper Network Security Scanner')
        # Make command required by argparse itself
        subparsers = parser.add_subparsers(dest='command', help='Available commands', required=True)

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
        # Make subcommand required by argparse itself
        policies_parser = subparsers.add_parser('policies', help='Manage scan policies')
        policies_subparsers = policies_parser.add_subparsers(dest='policies_command', help='Policy subcommands', required=True)
        policies_subparsers.add_parser('list', help='List available policies')

        # Groups command
        # Make subcommand required by argparse itself
        groups_parser = subparsers.add_parser('groups', help='Manage target groups')
        groups_subparsers = groups_parser.add_subparsers(dest='groups_command', help='Group subcommands', required=True)
        groups_subparsers.add_parser('list', help='List available groups')

        # Reports command
        # Make subcommand required by argparse itself
        reports_parser = subparsers.add_parser('reports', help='Manage scan reports')
        reports_subparsers = reports_parser.add_subparsers(dest='reports_command', help='Report subcommands', required=True)
        reports_subparsers.add_parser('list', help='List available reports')

        # Compare command
        compare_parser = subparsers.add_parser('compare', help='Compare scan reports')
        compare_parser.add_argument('report1', help='First report file')
        compare_parser.add_argument('report2', help='Second report file')

        # Analyze command
        analyze_parser = subparsers.add_parser('analyze', help='Analyze port behavior')
        analyze_parser.add_argument('report', help='Report file to analyze')
        # --- End of argument definitions ---

        args = parser.parse_args()

        # Map command names to handler methods
        command_handlers = {
            "scan": self._handle_scan_command,
            "policies": self._handle_policies_command,
            "groups": self._handle_groups_command,
            "reports": self._handle_reports_command,
            "compare": self._handle_compare_command,
            "analyze": self._handle_analyze_command,
        }

        try:
            # Get the handler function from the dictionary
            # Argparse with required=True ensures command is valid and in the dict
            handler = command_handlers[args.command] # Use direct access as key is guaranteed

            # Execute the command handler
            handler(args)

        except Exception as e:
            # Use logger if possible, otherwise print
            log_message = f"Error executing command '{args.command}': {str(e)}"
            try:
                # Check if logger was initialized (might fail early in __init__)
                if hasattr(self, 'logger') and self.logger:
                    # Log exception with traceback for debugging
                    self.logger.exception(log_message)
                else:
                    print(log_message, file=sys.stderr)
            except Exception:
                 # Fallback print if logging fails
                 print(log_message, file=sys.stderr)
            sys.exit(1)

if __name__ == "__main__":
    gatekeeper_instance = GateKeeper()
    gatekeeper_instance.main()